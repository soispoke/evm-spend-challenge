#!/usr/bin/env python3
"""Generate a hand-written EVM bytecode entry with a small assembler.

The program is fully unrolled and keeps its working values on the stack. Each
rule failure jumps to one REVERT, so every valid input runs the same
instructions. Memory holds four fixed message buffers, each with its tag byte
immediately before its fields, so most tags and shared fields are written once:

  31..96    tag, left, right   owner key, inner, commitment, occurrence, tree nodes, output commitments
  127..192  0x06, domain, key  nullifier key
  223..288  0x03, key, occ.    nullifier; the nullifier key and occurrence are written straight here
  511..776  0x08, ..., input   statement digest; nullifiers and output commitments are written straight here

Along a Merkle path the current node sits at 32 or 64 (32 when the path bit is
0), each sibling is copied to the other slot, and each hash result is written
where the next level reads it. As in the Yul entry, precompile results are not
checked: under the challenge's fixed 30 million gas limit a SHA-256 call cannot
run out of gas, which is its only way to fail.

Usage:
  python3 evm/bytecode/generate.py              write bytecode.hex and listing.txt
  python3 evm/bytecode/generate.py --drop RULE  print bytecode with one rule check removed
  python3 evm/bytecode/generate.py --precompile 0xb2 --out FILE
                                               the same entry calling another hash precompile,
                                               for the BLAKE2s edition
"""
import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEPTH = 20
NOTES_AT, NOTE_BYTES, OUTPUTS_AT = 136, 724, 1584
RULES = ("length", "index_range", "membership", "nonzero_input", "conservation", "zero_output_sink",
         "positive_output_not_sink", "authorizer_nonzero", "recipient_matches_amount",
         "distinct_nullifiers", "distinct_outputs")
OPCODES = {
    "ADD": 0x01, "SUB": 0x03, "LT": 0x10, "GT": 0x11, "EQ": 0x14, "ISZERO": 0x15, "AND": 0x16, "OR": 0x17,
    "XOR": 0x18, "SHL": 0x1b, "SHR": 0x1c, "CALLDATALOAD": 0x35, "CALLDATASIZE": 0x36, "CALLDATACOPY": 0x37,
    "POP": 0x50, "MLOAD": 0x51, "MSTORE8": 0x53, "JUMPI": 0x57, "GAS": 0x5a, "JUMPDEST": 0x5b, "MCOPY": 0x5e,
    "RETURN": 0xf3, "STATICCALL": 0xfa, "REVERT": 0xfd,
}
# Memory layout: tag byte then fields, for each message buffer.
A, NK, NF, S = 31, 127, 223, 511
SLOT_L, SLOT_R = 32, 64
NK_KEY, NF_KEY, NF_OCC = 160, 224, 256
S_NF, S_CM, S_PUBLIC = 512, 576, 640


class Assembler:
    def __init__(self):
        self.items = []      # (text, bytes or label reference)

    def op(self, name):
        if name.startswith("DUP"):
            code = 0x80 + int(name[3:]) - 1
        elif name.startswith("SWAP"):
            code = 0x90 + int(name[4:]) - 1
        else:
            code = OPCODES[name]
        self.items.append((name, bytes([code])))

    def push(self, value):
        if value == 0:
            self.items.append(("PUSH0", b"\x5f"))
            return
        width = (value.bit_length() + 7) // 8
        self.items.append((f"PUSH{width} {value}", bytes([0x5f + width]) + value.to_bytes(width, "big")))

    def push_label(self, label):
        self.items.append((f"PUSH2 @{label}", label))

    def label(self, label):
        self.items.append((f"{label}:", ("define", label)))
        self.op("JUMPDEST")

    def assemble(self):
        positions, pc = {}, 0
        for _, body in self.items:
            if isinstance(body, tuple):
                positions[body[1]] = pc
            elif isinstance(body, str):
                pc += 3
            else:
                pc += len(body)
        code, listing, pc = bytearray(), [], 0
        for text, body in self.items:
            if isinstance(body, tuple):
                listing.append(text)
                continue
            if isinstance(body, str):
                body = bytes([0x61]) + positions[body].to_bytes(2, "big")
            listing.append(f"{pc:5}  {text}")
            code += body
            pc += len(body)
        return bytes(code), "\n".join(listing) + "\n"


def generate(drop=None, precompile=2):
    a = Assembler()

    def fail_if(rule):
        """Jump to the revert when the value on top is nonzero."""
        if rule == drop:
            a.op("POP")
        else:
            a.push_label("fail")
            a.op("JUMPI")

    def mstore8(offset, value):
        a.push(value); a.push(offset); a.op("MSTORE8")

    def copy(dest, source, size):
        a.push(size); a.push(source); a.push(dest); a.op("CALLDATACOPY")

    def sha256(start, length, out=None):
        """SHA-256 of memory[start:start+length] into out, or into the offset on top of the stack (kept)."""
        a.push(32)
        if out is None:
            a.op("DUP2")
        else:
            a.push(out)
        a.push(length); a.push(start); a.push(precompile); a.op("GAS"); a.op("STATICCALL"); a.op("POP")

    def u128(offset):
        a.push(offset); a.op("CALLDATALOAD"); a.push(128); a.op("SHR")

    # Input length.
    a.op("CALLDATASIZE"); a.push(1680); a.op("XOR"); fail_if("length")
    # Fields and tags written once.
    mstore8(NK, 0x06); copy(NK + 1, 32, 32)            # nullifier key: tag, domain
    mstore8(NF, 0x03)                                  # nullifier: tag
    mstore8(S, 0x08); copy(S_PUBLIC, 0, 136)           # statement: tag, public fields

    for k in range(2):
        base = NOTES_AT + k * NOTE_BYTES
        key, rho, value, index, path = base, base + 32, base + 64, base + 80, base + 84
        u128(value)                                                    # [v]
        a.push(index); a.op("CALLDATALOAD"); a.push(224); a.op("SHR")  # [v, idx]
        a.op("DUP1"); a.push(20); a.op("SHR"); fail_if("index_range")
        a.push(5); a.op("SHL")                                         # [v, t]  t = idx << 5
        mstore8(A, 0x01); copy(SLOT_L, key, 32); sha256(A, 33, SLOT_L)     # owner key
        mstore8(A, 0x05); copy(SLOT_R, rho, 32); sha256(A, 65, SLOT_L)     # inner
        mstore8(A, 0x02); copy(SLOT_R, value, 16); sha256(A, 49, SLOT_L)   # commitment
        mstore8(A, 0x07); copy(SLOT_R, index, 4); sha256(A, 37, NF_OCC)    # occurrence
        # Merkle path. Bit j of the index, times 32, is (t >> j) & 32.
        mstore8(A, 0x04)
        a.op("DUP1"); a.push(32); a.op("AND"); a.push(32); a.op("ADD")    # [v, t, o]
        a.push(32); a.push(SLOT_L); a.op("DUP3"); a.op("MCOPY")            # commitment to slot o
        for level in range(DEPTH):
            # Sibling into the other slot, 96 xor o; this consumes o.
            a.push(96); a.op("XOR"); a.push(path + 32 * level); a.push(32); a.op("SWAP2"); a.op("CALLDATACOPY")
            # Where the result goes: 32 or 64 by the next bit.
            a.op("DUP1"); a.push(level + 1); a.op("SHR"); a.push(32); a.op("AND"); a.push(32); a.op("ADD")
            sha256(A, 65)                                                  # [v, t, o]
        a.op("POP"); a.op("POP")                                           # [v]; with idx < 2^20 the root is at 32
        # A note with value must open to the root.
        a.op("DUP1"); a.op("ISZERO"); a.push(SLOT_L); a.op("MLOAD"); a.push(0); a.op("CALLDATALOAD")
        a.op("EQ"); a.op("OR"); a.op("ISZERO"); fail_if("membership")
        copy(NK_KEY, key, 32); sha256(NK, 65, NF_KEY)                      # nullifier key
        sha256(NF, 65, S_NF + 32 * k)                                      # nullifier
    # Stack: [v0, v1]
    for k in range(2):
        base = OUTPUTS_AT + 48 * k
        mstore8(A, 0x02); copy(SLOT_L, base, 48); sha256(A, 49, S_CM + 32 * k)   # output commitment
        u128(base + 32)                                                    # [.., w]
        a.push(base); a.op("CALLDATALOAD")                                 # [.., w, I]
        a.op("DUP2"); a.op("ISZERO")                                       # [.., w, I, z]  z: value is zero
        # A zero output must use inner k + 1: fail when z and not (I == k + 1).
        a.op("DUP2"); a.push(k + 1); a.op("EQ"); a.op("DUP2"); a.op("GT"); fail_if("zero_output_sink")
        # A positive output must not use inner 1 or 2: fail when (I - 1 < 2) and not z.
        a.push(2); a.push(1); a.op("DUP4"); a.op("SUB"); a.op("LT"); a.op("GT"); fail_if("positive_output_not_sink")
        a.op("POP")                                                        # [.., w]
    # Stack: [v0, v1, w0, w1]
    u128(64)                                                               # public amount
    a.op("DUP1"); a.op("ISZERO"); a.push(96); a.op("CALLDATALOAD"); a.push(96); a.op("SHR"); a.op("ISZERO")
    a.op("XOR"); fail_if("recipient_matches_amount")
    a.op("ADD"); a.op("ADD"); u128(80); a.op("ADD")                          # [v0, v1, outputs + amount + fee]
    a.op("SWAP2"); a.op("ADD")                                             # [rhs, v0 + v1]
    a.op("DUP1"); a.op("ISZERO"); fail_if("nonzero_input")
    a.op("XOR"); fail_if("conservation")
    a.push(116); a.op("CALLDATALOAD"); a.push(96); a.op("SHR"); a.op("ISZERO"); fail_if("authorizer_nonzero")
    a.push(S_NF); a.op("MLOAD"); a.push(S_NF + 32); a.op("MLOAD"); a.op("EQ"); fail_if("distinct_nullifiers")
    a.push(S_CM); a.op("MLOAD"); a.push(S_CM + 32); a.op("MLOAD"); a.op("EQ"); fail_if("distinct_outputs")
    sha256(S, 265, 0)                                                      # statement digest
    a.push(32); a.push(0); a.op("RETURN")
    a.label("fail")
    a.push(0); a.push(0); a.op("REVERT")
    return a.assemble()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--drop", choices=RULES)
    parser.add_argument("--precompile", type=lambda text: int(text, 0), default=2)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    code, listing = generate(args.drop, args.precompile)
    if args.out:
        args.out.write_text(code.hex() + "\n")
        print(f"{len(code)} bytes")
        return 0
    if args.drop:
        print(code.hex())
        return 0
    (HERE / "bytecode.hex").write_text(code.hex() + "\n")
    (HERE / "listing.txt").write_text(listing)
    print(f"{len(code)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
