#!/usr/bin/env python3
"""Compare hash functions for the statement's 55 hash calls on leanVM.

Runs the guests in guests/hash-choice: SHA-256, BLAKE2s and BLAKE3 in software,
and BLAKE2s through leanVM's `blake2s` instruction. Each guest chains the 55
messages as spend_sha256::hash_control does. The script checks every output
against Python (hashlib for SHA-256 and BLAKE2s, a small BLAKE3 reference
checked against the published test vectors), records cycles, and with
--rounds N proves each guest N times interleaved (one warmup and two timed
proofs per round). Run scripts/build.sh first.

Usage: python3 scripts/hash_choice.py results/RUN [--rounds 2]
"""
import argparse
import hashlib
import json
import statistics
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCORER = ROOT / "target/release/spend-challenge"
PROFILER = ROOT / "target/release/examples/cycle_profile"
ELF = ROOT / "guests/target/riscv64im-unknown-none-elf/release"
FIXTURES = ROOT / "fixtures/public.json"
GUESTS = {"sha256-software": ("hash-sha256", "sha256"), "blake2s-software": ("hash-blake2s-software", "blake2s"),
          "blake3-software": ("hash-blake3-software", "blake3"),
          "blake2s-instruction": ("hash-blake2s-instruction", "blake2s")}

IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
M32 = 0xFFFFFFFF


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & M32


def mix(v, a, b, c, d, x, y):
    v[a] = (v[a] + v[b] + x) & M32
    v[d] = rotr(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d]) & M32
    v[b] = rotr(v[b] ^ v[c], 12)
    v[a] = (v[a] + v[b] + y) & M32
    v[d] = rotr(v[d] ^ v[a], 8)
    v[c] = (v[c] + v[d]) & M32
    v[b] = rotr(v[b] ^ v[c], 7)


def blake3(data: bytes) -> bytes:
    """BLAKE3-256 of at most one 1,024-byte chunk."""
    assert len(data) <= 1024
    cv = IV[:]
    blocks = max(1, -(-len(data) // 64))
    for i in range(blocks):
        chunk = data[64 * i:64 * i + 64]
        m = [int.from_bytes(chunk.ljust(64, b"\0")[4 * k:4 * k + 4], "little") for k in range(16)]
        v = cv[:] + IV[:4] + [0, 0, len(chunk), (1 if i == 0 else 0) | (10 if i == blocks - 1 else 0)]
        for r in range(7):
            for a, b, c, d, j in ((0, 4, 8, 12, 0), (1, 5, 9, 13, 2), (2, 6, 10, 14, 4), (3, 7, 11, 15, 6),
                                  (0, 5, 10, 15, 8), (1, 6, 11, 12, 10), (2, 7, 8, 13, 12), (3, 4, 9, 14, 14)):
                mix(v, a, b, c, d, m[j], m[j + 1])
            if r < 6:
                m = [m[PERM[k]] for k in range(16)]
        cv = [v[k] ^ v[k + 8] for k in range(8)]
    return b"".join(w.to_bytes(4, "little") for w in cv)


assert blake3(b"").hex() == "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
assert blake3(b"abc").hex() == "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
HASHES = {"sha256": lambda m: hashlib.sha256(m).digest(), "blake2s": lambda m: hashlib.blake2s(m).digest(),
          "blake3": blake3}
SCHEDULE = ([33, 65, 49] + [65] * 20 + [37, 65, 65]) * 2 + [49, 49, 265]


def control(data: bytes, hash_fn) -> bytes:
    message = bytearray(data[:265])
    state = data[265:297]
    for call, length in enumerate(SCHEDULE):
        message[0] = call
        message[1:33] = state
        state = hash_fn(bytes(message[:length]))
    return state


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("out", type=Path)
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--case", default="transfer")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    case = next(c for c in json.loads(FIXTURES.read_text())["cases"] if c["name"] == args.case)
    data = bytes.fromhex(case["input"])
    expected = {name: control(data, fn).hex() for name, fn in HASHES.items()}
    cycles = {}
    for name, (elf, hash_name) in GUESTS.items():
        run = json.loads(subprocess.run([str(PROFILER), str(ELF / elf), str(FIXTURES), args.case],
                                        capture_output=True, text=True, check=True).stdout)
        assert run["output"] == expected[hash_name], name
        cycles[name] = run["total"]
    rows = []
    for round_ in range(args.rounds):
        for name, (elf, hash_name) in GUESTS.items():
            out = subprocess.run([str(SCORER), "prove", "--route", "native", "--elf", str(ELF / elf), "--fixtures",
                                  str(FIXTURES), "--case", args.case, "--public", expected[hash_name], "--warmups", "1",
                                  "--repetitions", "2"], capture_output=True, text=True, check=True).stdout
            rows += [{**json.loads(line), "program": name, "round": round_} for line in out.splitlines()]
    (args.out / "timing.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    summary = {"case": args.case, "messages": len(SCHEDULE), "blocks_of_64_bytes": 105, "outputs_checked": True}
    for name in GUESTS:
        selected = [r for r in rows if r["program"] == name]
        timed = [r["proving_s"] for r in selected if not r["warmup"]]
        summary[name] = {"cycles": cycles[name], "padded_cycles": selected[0]["padded_cycles"] if selected else None,
                         "committed_words": selected[0]["committed_words"] if selected else None,
                         "median_proof_s": round(statistics.median(timed), 3) if timed else None,
                         "timed_proofs": len(timed)}
    (args.out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
