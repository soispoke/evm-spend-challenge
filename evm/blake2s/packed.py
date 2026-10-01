#!/usr/bin/env python3
"""BLAKE2s in EVM code, packed four lanes per word.

The straightforward version (generate.py) keeps one 32-bit word per 32-byte
memory slot and runs each G step as a function over memory. This version keeps
the 4x4 state as four row words, one round function per round, with the
chaining value in memory between blocks. Each 256-bit word holds the four
32-bit lanes of one row, spaced 64 bits apart so that additions cannot carry
from one lane into the next, and one sequence of opcodes computes the four G
steps of a column (or, after rotating the rows, of a diagonal) at once:

  lane k of a, b, c, d = v[k], v[4 + k], v[8 + k], v[12 + k]

A 32-bit addition is ADD then a mask; a rotation is two shifts, OR and a mask;
rows are rotated between the column and diagonal steps with two shifts and OR.
The sixteen message words of a block are byte-swapped eight at a time and kept
in memory, one per slot, and each step gathers its four words into lanes.

Writes, next to this file:
  hashtest.hex             runtime code returning BLAKE2s-256 of its calldata
  SpendBlake2sPacked.yul   the spend entry using this BLAKE2s
  bytecode-packed.hex      its runtime code

Usage: python3 evm/blake2s/packed.py
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "evm/yul"))
import generate as yul  # noqa: E402  (evm/yul/generate.py; found first on the path)

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
# Memory above everything the spend entry uses (0 .. 0x209): message words, then the block.
MW, H, B = 0x600, 0x800, 0x900
LANES = "0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff"


def packed(words) -> str:
    """Lanes 0..3 (lane 0 in the low bits), each 32 bits in a 64-bit slot."""
    return hex(sum(w << (64 * k) for k, w in enumerate(words)))


def gather(indices) -> str:
    m = [f"mload({MW + 32 * i})" for i in indices]
    return f"or(or({m[0]}, shl(64, {m[1]})), or(shl(128, {m[2]}), shl(192, {m[3]})))"


def rotr(var: str, n: int) -> str:
    return f"{var} := and(or(shr({n}, {var}), shl({32 - n}, {var})), {LANES})"


def g_step(mx: str, my: str) -> list:
    return [
        f"a := and(add(add(a, b), {mx}), {LANES})",
        "d := xor(d, a)", rotr("d", 16),
        f"c := and(add(c, d), {LANES})",
        "b := xor(b, c)", rotr("b", 12),
        f"a := and(add(add(a, b), {my}), {LANES})",
        "d := xor(d, a)", rotr("d", 8),
        f"c := and(add(c, d), {LANES})",
        "b := xor(b, c)", rotr("b", 7),
    ]


def functions() -> str:
    body = [
        # Reverse the bytes of each 32-bit word of x, eight words at once.
        "function b2s_bswap(x) -> y {",
        "    y := or(and(shr(8, x), 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff),",
        "            and(shl(8, x), 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00))",
        "    y := or(and(shr(16, y), 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff),",
        "            and(shl(16, y), 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000))",
        "}",
        # The block's sixteen message words, little-endian, one per slot at MW.
        "function b2s_message() {",
        f"    let x := b2s_bswap(mload({B}))",
    ]
    for i in range(8):
        body.append(f"    mstore({MW + 32 * i}, and(shr({224 - 32 * i}, x), 0xffffffff))")
    body.append(f"    x := b2s_bswap(mload({B + 32}))")
    for i in range(8):
        body.append(f"    mstore({MW + 32 * (8 + i)}, and(shr({224 - 32 * i}, x), 0xffffffff))")
    body.append("}")
    # One round: the column step, rotate rows, the diagonal step, rotate back.
    for r, s in enumerate(SIGMA):
        body.append(f"function b2s_round{r}(a0, b0, c0, d0) -> a, b, c, d {{")
        body.append("    a := a0 b := b0 c := c0 d := d0")
        body += ["    " + line for line in g_step(gather(s[0:8:2]), gather(s[1:8:2]))]
        body += ["    b := or(shr(64, b), shl(192, b))", "    c := or(shr(128, c), shl(128, c))",
                 "    d := or(shl(64, d), shr(192, d))"]
        body += ["    " + line for line in g_step(gather(s[8:16:2]), gather(s[9:16:2]))]
        body += ["    b := or(shl(64, b), shr(192, b))", "    c := or(shr(128, c), shl(128, c))",
                 "    d := or(shr(64, d), shl(192, d))"]
        body.append("}")
    # One compression of the zero-padded block at B into the chaining value at H (two row words).
    body += [
        "function b2s_compress(t, last) {",
        "    b2s_message()",
        f"    let a := mload({H})",
        f"    let b := mload({H + 32})",
        f"    let c := {packed(IV[:4])}",
        f"    let d := xor({packed(IV[4:])}, or(or(and(t, 0xffffffff), shl(64, shr(32, t))), shl(128, mul(last, 0xffffffff))))",
    ]
    for r in range(len(SIGMA)):
        body.append(f"    a, b, c, d := b2s_round{r}(a, b, c, d)")
    body += [
        f"    mstore({H}, xor(mload({H}), xor(a, c)))",
        f"    mstore({H + 32}, xor(mload({H + 32}), xor(b, d)))",
        "}",
        # BLAKE2s-256 of memory[src, src + len) into memory[out, out + 32).
        "function blake2s(src, len, out) {",
        f"    mstore({H}, {packed([IV[0] ^ 0x01010020] + IV[1:4])})",
        f"    mstore({H + 32}, {packed(IV[4:])})",
        "    let blocks := shr(6, add(len, 63))",
        "    if iszero(blocks) { blocks := 1 }",
        "    for { let i := 0 } lt(i, blocks) { i := add(i, 1) } {",
        "        let start := shl(6, i)",
        "        let n := sub(len, start)",
        "        if gt(n, 64) { n := 64 }",
        f"        mstore({B}, 0) mstore({B + 32}, 0)",
        f"        mcopy({B}, add(src, start), n)",
        "        b2s_compress(add(start, n), eq(add(i, 1), blocks))",
        "    }",
        "    b2s_output(out)",
        "}",
        "function b2s_output(out) {",
        f"    let lo := mload({H})",
        f"    let hi := mload({H + 32})",
        "    let w := or(or(shl(224, and(lo, 0xffffffff)), shl(192, and(shr(64, lo), 0xffffffff))),",
        "                or(shl(160, and(shr(128, lo), 0xffffffff)), shl(128, and(shr(192, lo), 0xffffffff))))",
        "    w := or(w, or(or(shl(96, and(hi, 0xffffffff)), shl(64, and(shr(64, hi), 0xffffffff))),",
        "                  or(shl(32, and(shr(128, hi), 0xffffffff)), and(shr(192, hi), 0xffffffff))))",
        "    mstore(out, b2s_bswap(w))",
        "}",
    ]
    return "".join("        " + line + "\n" for line in body)


def hash_test() -> str:
    """Runtime code: return BLAKE2s-256 of the calldata (placed above the working memory)."""
    return ('object "Blake2sTest" {\n    code {\n'
            "        calldatacopy(0x1000, 0, calldatasize())\n"
            "        blake2s(0x1000, calldatasize(), 0)\n"
            "        return(0, 32)\n" + functions() + "    }\n}\n")


def main() -> int:
    (HERE / "hashtest.hex").write_text(yul.compile_yul(hash_test()) + "\n")
    source = yul.generate(hash_call=lambda length, target, source: f"blake2s({source}, {length}, {target})",
                          functions=functions(), name="SpendBlake2sPacked")
    runtime = yul.compile_yul(source)
    (HERE / "SpendBlake2sPacked.yul").write_text(source)
    (HERE / "bytecode-packed.hex").write_text(runtime + "\n")
    print(f"hashtest.hex, and bytecode-packed.hex: {len(runtime) // 2} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
