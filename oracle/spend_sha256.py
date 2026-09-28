#!/usr/bin/env python3
"""Reference relation and test-case generator for the EVM spend challenge.

The statement is the minimal shielded pool's two-input, two-output spend
(depth-20 tree, occurrence-bound nullifiers) with SHA-256 as its only hash.
Every hashed message starts with a one-byte domain tag. `evaluate` returns
every violated rule and the 32-byte statement digest; a valid input violates
no rule, and an implementation must return exactly that digest for it and
must not return anything for an invalid input.

With --hash blake2s it produces the BLAKE2s edition instead: the same
statement with BLAKE2s-256 as every hash, and nothing else changed.

Usage:
  python3 oracle/spend_sha256.py write fixtures/public.json
  python3 oracle/spend_sha256.py check fixtures/public.json
  python3 oracle/spend_sha256.py hidden OUT.json --seed N --count K
  python3 oracle/spend_sha256.py --hash blake2s write fixtures/public-blake2s.json
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import random
import sys
from dataclasses import dataclass
from pathlib import Path

DEPTH = 20
MAX_INDEX = 1 << DEPTH
U128 = 1 << 128
INPUT_BYTES = 1680
NOTE_BYTES = 32 + 32 + 16 + 4 + 32 * DEPTH  # spend key, rho, value, index, path
OUTPUT_BYTES = 32 + 16                       # inner, value

TAG_PK, TAG_COMMIT, TAG_NULL, TAG_NODE, TAG_INNER, TAG_NK, TAG_OCC, TAG_STATEMENT = range(1, 9)
SINK = ((1).to_bytes(32, "big"), (2).to_bytes(32, "big"))
ZERO20 = bytes(20)

RULES = (
    "length",                    # the input is exactly INPUT_BYTES long
    "index_range",               # each leaf index is below 2^20
    "membership",                # a nonzero-value input opens to the root
    "nonzero_input",             # the inputs carry nonzero total value
    "conservation",              # inputs = outputs + public amount + fee, over integers
    "zero_output_sink",          # a zero-value output uses its position's sink inner
    "positive_output_not_sink",  # a positive output uses neither sink inner
    "authorizer_nonzero",        # the one-time authorizer is not the zero address
    "recipient_matches_amount",  # recipient is zero exactly when the public amount is
    "distinct_nullifiers",       # the two nullifiers differ
    "distinct_outputs",          # the two output commitments differ
)


# The statement's hash; main() switches it for the BLAKE2s edition.
HASH, EDITION = hashlib.sha256, "SHA-256"


def H(tag: int, *parts: bytes) -> bytes:
    return HASH(bytes([tag]) + b"".join(parts)).digest()


def u128(value: int) -> bytes:
    return value.to_bytes(16, "big")


@dataclass
class Note:
    spend_key: bytes
    rho: bytes
    value: int
    index: int
    siblings: list


@dataclass
class Output:
    inner: bytes
    value: int


@dataclass
class Spend:
    root: bytes
    domain: bytes
    public_amount: int
    fee: int
    recipient: bytes
    authorizer: bytes
    inputs: list
    outputs: list

    def encode(self) -> bytes:
        out = bytearray()
        out += self.root + self.domain + u128(self.public_amount) + u128(self.fee)
        out += self.recipient + self.authorizer
        for note in self.inputs:
            out += note.spend_key + note.rho + u128(note.value) + note.index.to_bytes(4, "big")
            out += b"".join(note.siblings)
        for output in self.outputs:
            out += output.inner + u128(output.value)
        assert len(out) == INPUT_BYTES
        return bytes(out)


def decode(payload: bytes) -> Spend:
    assert len(payload) == INPUT_BYTES
    take = memoryview(payload)
    pos = 0

    def read(n: int) -> bytes:
        nonlocal pos
        chunk = bytes(take[pos:pos + n])
        pos += n
        return chunk

    root, domain = read(32), read(32)
    public_amount, fee = int.from_bytes(read(16), "big"), int.from_bytes(read(16), "big")
    recipient, authorizer = read(20), read(20)
    inputs = []
    for _ in range(2):
        spend_key, rho = read(32), read(32)
        value, index = int.from_bytes(read(16), "big"), int.from_bytes(read(4), "big")
        inputs.append(Note(spend_key, rho, value, index, [read(32) for _ in range(DEPTH)]))
    outputs = [Output(read(32), int.from_bytes(read(16), "big")) for _ in range(2)]
    assert pos == INPUT_BYTES
    return Spend(root, domain, public_amount, fee, recipient, authorizer, inputs, outputs)


def commitment(note: Note) -> bytes:
    owner = H(TAG_PK, note.spend_key)
    inner = H(TAG_INNER, owner, note.rho)
    return H(TAG_COMMIT, inner, u128(note.value))


def evaluate(payload: bytes):
    """Return (violated rules in RULES order, digest or None)."""
    if len(payload) != INPUT_BYTES:
        return ["length"], None
    spend = decode(payload)
    violated = set()
    nullifiers = []
    for note in spend.inputs:
        if note.index >= MAX_INDEX:
            violated.add("index_range")
        cm = commitment(note)
        current = cm
        for level, sibling in enumerate(note.siblings):
            if (note.index >> level) & 1:
                current = H(TAG_NODE, sibling, current)
            else:
                current = H(TAG_NODE, current, sibling)
        if note.value != 0 and current != spend.root:
            violated.add("membership")
        occurrence = H(TAG_OCC, cm, note.index.to_bytes(4, "big"))
        nullifier_key = H(TAG_NK, spend.domain, note.spend_key)
        nullifiers.append(H(TAG_NULL, nullifier_key, occurrence))
    total_in = sum(note.value for note in spend.inputs)
    if total_in == 0:
        violated.add("nonzero_input")
    if total_in != sum(o.value for o in spend.outputs) + spend.public_amount + spend.fee:
        violated.add("conservation")
    commitments = []
    for position, output in enumerate(spend.outputs):
        if output.value == 0 and output.inner != SINK[position]:
            violated.add("zero_output_sink")
        if output.value != 0 and output.inner in SINK:
            violated.add("positive_output_not_sink")
        commitments.append(H(TAG_COMMIT, output.inner, u128(output.value)))
    if spend.authorizer == ZERO20:
        violated.add("authorizer_nonzero")
    if (spend.public_amount == 0) != (spend.recipient == ZERO20):
        violated.add("recipient_matches_amount")
    if nullifiers[0] == nullifiers[1]:
        violated.add("distinct_nullifiers")
    if commitments[0] == commitments[1]:
        violated.add("distinct_outputs")
    digest = H(TAG_STATEMENT, nullifiers[0], nullifiers[1], commitments[0], commitments[1],
               spend.root, spend.domain, u128(spend.public_amount), u128(spend.fee),
               spend.recipient, spend.authorizer)
    return [rule for rule in RULES if rule in violated], digest


# ---------------------------------------------------------------- case builder

class SparseTree:
    """A depth-20 tree holding a few known leaves; every other subtree is a
    pseudo-random stand-in, so paths for all known leaves share one root."""

    def __init__(self, seed: bytes, leaves: dict):
        self.seed, self.leaves, self.memo = seed, leaves, {}

    def node(self, level: int, pos: int) -> bytes:
        key = (level, pos)
        if key not in self.memo:
            lo, hi = pos << level, (pos + 1) << level
            if not any(lo <= index < hi for index in self.leaves):
                value = hashlib.sha256(self.seed + level.to_bytes(1, "big") + pos.to_bytes(4, "big")).digest()
            elif level == 0:
                value = self.leaves[pos]
            else:
                value = H(TAG_NODE, self.node(level - 1, 2 * pos), self.node(level - 1, 2 * pos + 1))
            self.memo[key] = value
        return self.memo[key]

    def root(self) -> bytes:
        return self.node(DEPTH, 0)

    def path(self, index: int) -> list:
        return [self.node(level, (index >> level) ^ 1) for level in range(DEPTH)]


def nonzero(rng: random.Random, n: int) -> bytes:
    while True:
        value = rng.randbytes(n)
        if any(value) and value not in SINK:
            return value


def build(rng: random.Random, in_values, out_values, public_amount=0, fee=0, dummy=(False, False),
          indices=None, same_key=False, same_note=False, same_body=False, recipient=None) -> Spend:
    """Build a spend whose real inputs are members of one tree.

    `same_note` spends one note twice; `same_body` puts two equal commitments
    at different leaf positions.
    """
    if indices is None:
        indices = [rng.randrange(MAX_INDEX), rng.randrange(MAX_INDEX)]
        while indices[1] == indices[0] and not same_note:
            indices[1] = rng.randrange(MAX_INDEX)
    keys = [rng.randbytes(32), rng.randbytes(32)]
    rhos = [rng.randbytes(32), rng.randbytes(32)]
    if same_key or same_note or same_body:
        keys[1] = keys[0]
    if same_note or same_body:
        rhos[1] = rhos[0]
    if same_note:
        indices[1] = indices[0]
    notes = [Note(keys[k], rhos[k], in_values[k], indices[k], []) for k in range(2)]
    leaves = {note.index: commitment(note) for k, note in enumerate(notes) if not dummy[k]}
    tree = SparseTree(rng.randbytes(16), leaves)
    for k, note in enumerate(notes):
        note.siblings = [rng.randbytes(32) for _ in range(DEPTH)] if dummy[k] else tree.path(note.index)
    root = tree.root() if leaves else rng.randbytes(32)
    outputs = [Output(SINK[k] if out_values[k] == 0 else nonzero(rng, 32), out_values[k]) for k in range(2)]
    if recipient is None:
        recipient = nonzero(rng, 20) if public_amount else ZERO20
    return Spend(root, rng.randbytes(32), public_amount, fee, recipient, nonzero(rng, 20), notes, outputs)


def valid_catalog(rng: random.Random) -> list:
    top = U128 - 1
    cases = [
        ("transfer", build(rng, (700, 300), (600, 350), fee=50)),
        ("withdrawal", build(rng, (1000, 234), (500, 0), public_amount=700, fee=34)),
        ("real-then-dummy", build(rng, (1000, 0), (400, 590), fee=10, dummy=(False, True))),
        ("dummy-then-real", build(rng, (0, 777), (770, 0), fee=7, dummy=(True, False))),
        ("full-exit", build(rng, (5000, 0), (0, 0), public_amount=4990, fee=10, dummy=(False, True))),
        ("maximum-values", build(rng, (top, top), (top, top - 5), fee=5)),
        ("index-extremes", build(rng, (11, 22), (30, 3), indices=[0, MAX_INDEX - 1])),
        ("shared-spend-key", build(rng, (40, 60), (99, 1), same_key=True)),
        ("equal-commitments", build(rng, (50, 50), (60, 40), same_body=True)),
        ("zero-fee-withdrawal", build(rng, (9, 1), (0, 4), public_amount=6)),
    ]
    for k in range(10):
        cases.append((f"random-{k}", random_valid(rng)))
    return cases


def random_valid(rng: random.Random) -> Spend:
    dummy = rng.choice([(False, False), (False, True), (True, False)])
    in_values = [0 if dummy[k] else rng.randrange(1, U128) for k in range(2)]
    total = sum(in_values)
    # Split the total across outputs, public amount and fee; each part fits u128.
    while True:
        cuts = sorted(rng.randrange(total + 1) for _ in range(3))
        parts = [cuts[0], cuts[1] - cuts[0], cuts[2] - cuts[1], total - cuts[2]]
        if rng.random() < 0.3:
            parts[2] = 0  # a transfer
        parts[3] = total - sum(parts[:3])
        if all(0 <= p < U128 for p in parts) and parts[0] + parts[1] > 0 and parts[0] != parts[1]:
            break
    out_values, public_amount, fee = parts[:2], parts[2], parts[3]
    return build(rng, in_values, out_values, public_amount=public_amount, fee=fee, dummy=dummy)


def flip(data: bytes, rng: random.Random) -> bytes:
    position = rng.randrange(len(data))
    return data[:position] + bytes([data[position] ^ (1 << rng.randrange(8))]) + data[position + 1:]


def invalid_catalog(rng: random.Random) -> list:
    """Each case violates exactly one rule; `check` enforces that."""
    top = U128 - 1
    cases = []

    def add(name, rule, spend=None, payload=None):
        cases.append((name, rule, payload if payload is not None else spend.encode()))

    base = build(rng, (700, 300), (600, 350), fee=50)
    add("length-short", "length", payload=base.encode()[:-1])
    add("length-long", "length", payload=base.encode() + b"\x00")
    add("length-empty", "length", payload=b"")

    for bad_index in (MAX_INDEX, 0xFFFFFFFF):
        spend = build(rng, (1000, 0), (400, 590), fee=10, dummy=(False, True))
        spend.inputs[1].index = bad_index
        add(f"index-range-{bad_index:#x}", "index_range", spend)

    spend = copy.deepcopy(base)
    spend.root = flip(spend.root, rng)
    add("membership-root", "membership", spend)
    for k in range(2):
        for level in (0, 9, DEPTH - 1):
            spend = copy.deepcopy(base)
            spend.inputs[k].siblings[level] = flip(spend.inputs[k].siblings[level], rng)
            add(f"membership-input{k}-level{level}", "membership", spend)
        spend = copy.deepcopy(base)
        spend.inputs[k].index ^= 1 << rng.randrange(DEPTH)
        add(f"membership-input{k}-index", "membership", spend)
        spend = copy.deepcopy(base)
        spend.inputs[k].rho = flip(spend.inputs[k].rho, rng)
        add(f"membership-input{k}-rho", "membership", spend)
        spend = copy.deepcopy(base)
        spend.inputs[k].spend_key = flip(spend.inputs[k].spend_key, rng)
        add(f"membership-input{k}-spend-key", "membership", spend)
        spend = copy.deepcopy(base)
        spend.inputs[k].value += 1
        spend.outputs[0].value += 1
        add(f"membership-input{k}-value", "membership", spend)
    spend = build(rng, (0, 777), (770, 0), fee=7, dummy=(True, False))
    spend.inputs[0].value = 1          # a fabricated path now carries value
    spend.outputs[0].value += 1
    add("membership-dummy-with-value", "membership", spend)

    spend = build(rng, (0, 0), (0, 0), dummy=(True, True))
    add("nonzero-input-all-dummies", "nonzero_input", spend)

    for name, field_delta in (("output-plus-one", ("outputs", 0, 1)), ("output-minus-one", ("outputs", 1, -1))):
        spend = copy.deepcopy(base)
        spend.outputs[field_delta[1]].value += field_delta[2]
        add(f"conservation-{name}", "conservation", spend)
    spend = copy.deepcopy(base)
    spend.fee += 1
    add("conservation-fee", "conservation", spend)
    spend = build(rng, (1000, 234), (500, 0), public_amount=700, fee=34)
    spend.public_amount += 1
    add("conservation-public-amount", "conservation", spend)
    # Equal modulo 2^128 but not over the integers: a wrapping sum would mint.
    add("conservation-wrapping-inputs", "conservation", build(rng, (top, 2), (1, 0)))
    add("conservation-wrapping-outputs", "conservation",
        build(rng, (5, 0), (top, 6), dummy=(False, True)))

    spend = build(rng, (700, 300), (0, 950), fee=50)
    spend.outputs[0].inner = nonzero(rng, 32)
    add("zero-output-without-sink", "zero_output_sink", spend)
    spend = build(rng, (700, 300), (950, 0), fee=50)
    spend.outputs[1].inner = SINK[0]
    add("zero-output-wrong-position-sink", "zero_output_sink", spend)
    for position in range(2):
        for sink in range(2):
            spend = build(rng, (700, 300), (600, 350), fee=50)
            spend.outputs[position].inner = SINK[sink]
            add(f"positive-output{position}-sink{sink}", "positive_output_not_sink", spend)

    spend = copy.deepcopy(base)
    spend.authorizer = ZERO20
    add("authorizer-zero", "authorizer_nonzero", spend)
    spend = build(rng, (1000, 234), (500, 0), public_amount=700, fee=34)
    spend.recipient = ZERO20
    add("recipient-missing", "recipient_matches_amount", spend)
    spend = copy.deepcopy(base)
    spend.recipient = nonzero(rng, 20)
    add("recipient-unexpected", "recipient_matches_amount", spend)

    add("nullifier-same-note-twice", "distinct_nullifiers", build(rng, (500, 500), (900, 50), fee=50, same_note=True))
    spend = build(rng, (700, 300), (500, 500))
    spend.outputs[1].inner = spend.outputs[0].inner
    add("outputs-equal", "distinct_outputs", spend)
    return cases


def case_record(name, payload, rule=None):
    violated, digest = evaluate(payload)
    if rule is None:
        assert violated == [], (name, violated)
        return {"name": name, "valid": True, "input": payload.hex(), "digest": digest.hex()}
    assert violated == [rule], (name, rule, violated)
    return {"name": name, "valid": False, "rule": rule, "input": payload.hex()}


def generate(seed: int) -> dict:
    rng = random.Random(seed)
    cases = [case_record(name, spend.encode()) for name, spend in valid_catalog(rng)]
    cases += [case_record(name, payload, rule) for name, rule, payload in invalid_catalog(rng)]
    covered = {case["rule"] for case in cases if not case["valid"]}
    assert covered == set(RULES), sorted(set(RULES) - covered)
    return {
        "statement": f"MSP Spend(20), {EDITION} edition, v1",
        "input_bytes": INPUT_BYTES,
        "seed": seed,
        "rules": list(RULES),
        "cases": cases,
    }


def hidden(seed: int, count: int) -> dict:
    """Fresh cases for scoring: random valid spends plus random single-rule
    mutations drawn from the same catalog with a new seed."""
    rng = random.Random(seed)
    cases = [case_record(f"hidden-valid-{k}", random_valid(rng).encode()) for k in range(count)]
    mutations = invalid_catalog(rng)
    cases += [case_record(f"hidden-{name}", payload, rule) for name, rule, payload in mutations]
    return {"statement": f"MSP Spend(20), {EDITION} edition, v1", "input_bytes": INPUT_BYTES,
            "seed": seed, "rules": list(RULES), "cases": cases}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--hash", choices=("sha256", "blake2s"), default="sha256")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("write", "check"):
        p = sub.add_parser(command)
        p.add_argument("path", type=Path)
        p.add_argument("--seed", type=int, default=0)
    p = sub.add_parser("hidden")
    p.add_argument("path", type=Path)
    p.add_argument("--seed", type=int, required=True)
    p.add_argument("--count", type=int, default=16)
    args = parser.parse_args()
    global HASH, EDITION
    if args.hash == "blake2s":
        HASH, EDITION = hashlib.blake2s, "BLAKE2s"
    if args.command == "hidden":
        args.path.write_text(json.dumps(hidden(args.seed, args.count), indent=1) + "\n")
        return 0
    fixtures = generate(args.seed)
    if args.command == "write":
        args.path.parent.mkdir(parents=True, exist_ok=True)
        args.path.write_text(json.dumps(fixtures, indent=1) + "\n")
        valid = sum(case["valid"] for case in fixtures["cases"])
        print(f"wrote {len(fixtures['cases'])} cases ({valid} valid) to {args.path}")
        return 0
    saved = json.loads(args.path.read_text())
    if saved != fixtures:
        print("saved fixtures differ from the deterministic generator", file=sys.stderr)
        return 1
    for case in saved["cases"]:
        violated, digest = evaluate(bytes.fromhex(case["input"]))
        expected = [] if case["valid"] else [case["rule"]]
        assert violated == expected and (not case["valid"] or digest.hex() == case["digest"]), case["name"]
    print(f"checked {len(saved['cases'])} cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
