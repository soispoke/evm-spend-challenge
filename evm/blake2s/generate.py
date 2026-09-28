#!/usr/bin/env python3
"""Generate the BLAKE2s edition's EVM entries.

precompile.hex is the hand-written bytecode entry calling a BLAKE2s precompile
at 0xb2 (`evm/bytecode/generate.py --precompile 0xb2`); nothing else differs.

bytecode.hex computes BLAKE2s in EVM code, for an EVM without a BLAKE2s
precompile. It is the optimized Yul entry with each precompile call replaced by
a Yul function that hashes memory the same way. The compression keeps its
sixteen state words and sixteen message words in memory, one per 32-byte slot,
and its ten rounds are unrolled into calls of one mixing function with
constant offsets; every 32-bit addition and rotation is masked to 32 bits, and message and digest words are
byte-swapped, because BLAKE2s is little-endian and EVM memory is big-endian.
This is a straightforward implementation: packing several words per slot could
make it a few times faster, but not remove the cost of emulating 32-bit
arithmetic with 256-bit instructions.

Usage: python3 evm/blake2s/generate.py
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "evm/yul"))
import generate as yul  # noqa: E402

IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
]
# Working memory, above everything the entry itself uses (0 .. 0x209).
V, M, H, B = 0x400, 0x600, 0x800, 0x900
MASK = "0xffffffff"


def rotr(var: str, n: int) -> str:
    return f"{var} := and(or(shr({n}, {var}), shl({32 - n}, {var})), {MASK})"


def mix(a: int, b: int, c: int, d: int, x: int, y: int) -> str:
    """One G step, as a call with constant memory offsets."""
    return f"g({V + 32 * a}, {V + 32 * b}, {V + 32 * c}, {V + 32 * d}, {M + 32 * x}, {M + 32 * y})"


G_FUNCTION = [
    "function g(oa, ob, oc, od, ox, oy) {",
    "    let a := mload(oa) let b := mload(ob) let c := mload(oc) let d := mload(od)",
    f"    a := and(add(add(a, b), mload(ox)), {MASK})",
    "    d := xor(d, a) " + rotr("d", 16),
    f"    c := and(add(c, d), {MASK})",
    "    b := xor(b, c) " + rotr("b", 12),
    f"    a := and(add(add(a, b), mload(oy)), {MASK})",
    "    d := xor(d, a) " + rotr("d", 8),
    f"    c := and(add(c, d), {MASK})",
    "    b := xor(b, c) " + rotr("b", 7),
    "    mstore(oa, a) mstore(ob, b) mstore(oc, c) mstore(od, d)",
    "}",
]


def functions() -> str:
    body = list(G_FUNCTION)
    body.append("function bswap32(x) -> y {")
    body.append("    y := or(or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))), or(and(shr(8, x), 0xff00), shr(24, x)))")
    body.append("}")
    # One compression of the zero-padded block at B into the chaining value at H.
    body.append("function blake2s_compress(t, last) {")
    for i in range(16):
        body.append(f"    mstore({M + 32 * i}, bswap32(shr(224, mload({B + 4 * i}))))")
    for i in range(8):
        body.append(f"    mstore({V + 32 * i}, mload({H + 32 * i}))")
    for i in range(8):
        value = {12: f"xor({IV[4]:#x}, and(t, {MASK}))", 13: f"xor({IV[5]:#x}, shr(32, t))",
                 14: f"xor({IV[6]:#x}, mul(last, {MASK}))"}.get(8 + i, f"{IV[i]:#x}")
        body.append(f"    mstore({V + 32 * (8 + i)}, {value})")
    for s in SIGMA:
        for (a, b, c, d), k in zip(((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                                    (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)), range(0, 16, 2)):
            body.append("    " + mix(a, b, c, d, s[k], s[k + 1]))
    for i in range(8):
        body.append(f"    mstore({H + 32 * i}, xor(mload({H + 32 * i}), xor(mload({V + 32 * i}), mload({V + 32 * (i + 8)}))))")
    body.append("}")
    # BLAKE2s-256 of memory[src, src + len) into memory[out, out + 32).
    body.append("function blake2s(src, len, out) {")
    for i in range(8):
        body.append(f"    mstore({H + 32 * i}, {(IV[i] ^ 0x01010020 if i == 0 else IV[i]):#x})")
    body.append("    let blocks := shr(6, add(len, 63))")
    body.append("    if iszero(blocks) { blocks := 1 }")
    body.append("    for { let i := 0 } lt(i, blocks) { i := add(i, 1) } {")
    body.append("        let start := shl(6, i)")
    body.append("        let n := sub(len, start)")
    body.append("        if gt(n, 64) { n := 64 }")
    body.append(f"        mstore({B}, 0) mstore({B + 32}, 0)")
    body.append(f"        mcopy({B}, add(src, start), n)")
    body.append("        blake2s_compress(add(start, n), eq(add(i, 1), blocks))")
    body.append("    }")
    words = " ".join(f"d := or(d, shl({224 - 32 * i}, bswap32(mload({H + 32 * i}))))" for i in range(8))
    body.append(f"    let d := 0 {words}")
    body.append("    mstore(out, d)")
    body.append("}")
    return "".join("        " + line + "\n" for line in body)


def main() -> int:
    subprocess.run([sys.executable, str(ROOT / "evm/bytecode/generate.py"), "--precompile", "0xb2",
                    "--out", str(HERE / "precompile.hex")], check=True, capture_output=True)
    source = yul.generate(hash_call=lambda length, target, source: f"blake2s({source}, {length}, {target})",
                          functions=functions(), name="SpendBlake2s")
    runtime = yul.compile_yul(source)
    (HERE / "SpendBlake2s.yul").write_text(source)
    (HERE / "bytecode.hex").write_text(runtime + "\n")
    print(f"precompile.hex, and bytecode.hex with BLAKE2s in EVM code: {len(runtime) // 2} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
