#!/usr/bin/env python3
"""Generate an optimized EVM entry as fully unrolled Yul, and compile it.

The entry keeps one message buffer at memory 0..65, writes each tag byte and
copies each calldata field into place, and has every SHA-256 precompile call
write its result where the next hash reads it. Along a Merkle path, the
result goes to the left or right slot chosen by the next index bit, so no
value is swapped or copied. Every rule is folded into one flag with bitwise
AND, and the entry reverts once at the end if any rule failed. Nothing
branches on private data. The result of each precompile call is not checked:
under the challenge's fixed 30 million gas limit, a SHA-256 call cannot run
out of gas, which is its only way to fail.

Usage:
  python3 evm/yul/generate.py              write SpendSha256.yul and bytecode.hex
  python3 evm/yul/generate.py --drop RULE  print bytecode with one rule check removed
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# solc 0.8.30: $SOLC, else the copy Foundry installs on macOS, else solc on PATH.
SOLC = os.environ.get("SOLC") or next((str(p) for p in [Path.home() / "Library/Application Support/svm/0.8.30/solc-0.8.30",
                                        Path.home() / ".svm/0.8.30/solc-0.8.30"] if p.exists()), "solc")
DEPTH = 20
NOTES_AT, NOTE_BYTES, OUTPUTS_AT = 136, 724, 1584
OCC = 0x80        # saved occurrence hashes, 32 bytes per input note
S = 0x100         # statement message: tag, nf0, nf1, cm0, cm1, input[0:136]
RULES = ("length", "index_range", "membership", "nonzero_input", "conservation", "zero_output_sink",
         "positive_output_not_sink", "authorizer_nonzero", "recipient_matches_amount",
         "distinct_nullifiers", "distinct_outputs")


def generate(drop=None, hash_call=None, functions="", name="SpendSha256") -> str:
    out = []

    def rule(name, condition):
        if name != drop:
            out.append(f"ok := and(ok, {condition})")

    def call(length, target, source=0):
        if hash_call:
            out.append(hash_call(length, target, source))
        else:
            out.append(f"pop(staticcall(gas(), 2, {source}, {length}, {target}, 32))")

    out.append("let ok := 1")
    rule("length", "eq(calldatasize(), 1680)")
    for k in range(2):
        base = NOTES_AT + k * NOTE_BYTES
        key, rho, value, index, path = base, base + 32, base + 64, base + 80, base + 84
        out.append(f"let idx{k} := shr(224, calldataload({index}))")
        out.append(f"let v{k} := shr(128, calldataload({value}))")
        rule("index_range", f"lt(idx{k}, 0x100000)")
        out += ["mstore8(0, 0x01)", f"calldatacopy(1, {key}, 32)"]
        call(33, 1)                                  # owner key -> 1..33
        out += ["mstore8(0, 0x05)", f"calldatacopy(33, {rho}, 32)"]
        call(65, 1)                                  # inner -> 1..33
        out += ["mstore8(0, 0x02)", f"calldatacopy(33, {value}, 16)"]
        call(49, 1)                                  # commitment -> 1..33
        out += ["mstore8(0, 0x07)", f"calldatacopy(33, {index}, 4)"]
        call(37, OCC + 32 * k)                       # occurrence -> saved
        # Merkle path: the current node sits at o = 1 + 32 * bit, the sibling
        # goes to the other slot, 34 - o.
        out.append("mstore8(0, 0x04)")
        out.append(f"let o{k} := add(1, shl(5, and(idx{k}, 1)))")
        out.append(f"mcopy(o{k}, 1, 32)")
        for level in range(DEPTH):
            out.append(f"calldatacopy(sub(34, o{k}), {path + 32 * level}, 32)")
            out.append(f"o{k} := add(1, shl(5, and(shr({level + 1}, idx{k}), 1)))")
            call(65, f"o{k}")
        # With the index below 2^20, the root lands at 1..33.
        rule("membership", f"or(eq(mload(1), calldataload(0)), iszero(v{k}))")
        out += ["mstore8(0, 0x06)", "calldatacopy(1, 32, 32)", f"calldatacopy(33, {key}, 32)"]
        call(65, 1)                                  # nullifier key -> 1..33
        out += ["mstore8(0, 0x03)", f"mcopy(33, {OCC + 32 * k}, 32)"]
        call(65, S + 1 + 32 * k)                     # nullifier -> statement
    for k in range(2):
        base = OUTPUTS_AT + 48 * k
        out.append(f"let inner{k} := calldataload({base})")
        out.append(f"let w{k} := shr(128, calldataload({base + 32}))")
        rule("zero_output_sink", f"or(iszero(iszero(w{k})), eq(inner{k}, {k + 1}))")
        rule("positive_output_not_sink", f"or(iszero(w{k}), iszero(lt(sub(inner{k}, 1), 2)))")
        out += ["mstore8(0, 0x02)", f"calldatacopy(1, {base}, 48)"]
        call(49, S + 65 + 32 * k)                    # output commitment -> statement
    out.append("let pa := shr(128, calldataload(64))")
    out.append("let total := add(v0, v1)")
    rule("nonzero_input", "iszero(iszero(total))")
    rule("conservation", "eq(total, add(add(w0, w1), add(pa, shr(128, calldataload(80)))))")
    rule("authorizer_nonzero", "iszero(iszero(shr(96, calldataload(116))))")
    rule("recipient_matches_amount", "eq(iszero(shr(96, calldataload(96))), iszero(pa))")
    rule("distinct_nullifiers", f"iszero(eq(mload({S + 1}), mload({S + 33})))")
    rule("distinct_outputs", f"iszero(eq(mload({S + 65}), mload({S + 97})))")
    out += [f"mstore8({S}, 0x08)", f"calldatacopy({S + 129}, 0, 136)"]
    call(265, 0, source=S)                           # statement digest -> 0..32
    out += ["if iszero(ok) { revert(0, 0) }", "return(0, 32)"]
    body = "\n".join("        " + line for line in out)
    return ("/// Optimized entry for the EVM spend challenge, generated by generate.py.\n"
            f"object \"{name}\" {{\n    code {{\n" + body + "\n" + functions + "    }\n}\n")


def compile_yul(source: str) -> str:
    run = subprocess.run([SOLC, "--strict-assembly", "--evm-version", "cancun", "--optimize", "--bin", "-"],
                         input=source, capture_output=True, text=True, check=True)
    lines = run.stdout.splitlines()
    return lines[lines.index("Binary representation:") + 1].strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--drop", choices=RULES)
    args = parser.parse_args()
    source = generate(args.drop)
    runtime = compile_yul(source)
    if args.drop:
        print(runtime)
        return 0
    (HERE / "SpendSha256.yul").write_text(source)
    (HERE / "bytecode.hex").write_text(runtime + "\n")
    print(f"{len(runtime) // 2} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
