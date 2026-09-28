#!/usr/bin/env python3
"""Generate the ahead-of-time compiled programs.

Writes target/compiled/<name>.rs for every EVM program (used by
host/examples/compiled_parity.rs and blake2s_parity.rs),
guests/evm-variants/compiled_program.rs for the program embedded in
guests/evm/bytecode.bin, and guests/blake2s-edition/compiled_program.rs for
the one in guests/blake2s-edition/bytecode.bin, which defaults to the BLAKE2s
edition's precompile entry.

Usage: python3 scripts/compile_programs.py
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROGRAMS = {"solidity": "evm/baseline.hex", "yul": "evm/yul/bytecode.hex", "bytecode": "evm/bytecode/bytecode.hex",
            "calls_55": "evm/controls/calls-55.hex", "calls_0": "evm/controls/calls-0.hex",
            "blake2s_precompile": "evm/blake2s/precompile.hex", "blake2s_evm": "evm/blake2s/bytecode.hex"}
EMBEDDED = {"guests/evm/bytecode.bin": "guests/evm-variants/compiled_program.rs",
            "guests/blake2s-edition/bytecode.bin": "guests/blake2s-edition/compiled_program.rs"}


def compile_hex(hex_path: Path, out: Path):
    subprocess.run([sys.executable, str(ROOT / "interpreters/compile.py"), str(hex_path), str(out)], check=True)


def main() -> int:
    out = ROOT / "target/compiled"
    out.mkdir(parents=True, exist_ok=True)
    for name, path in PROGRAMS.items():
        compile_hex(ROOT / path, out / f"{name}.rs")
    default = ROOT / "guests/blake2s-edition/bytecode.bin"
    if not default.exists():
        default.write_bytes(bytes.fromhex((ROOT / "evm/blake2s/precompile.hex").read_text().strip()))
    for index, (embedded, target) in enumerate(EMBEDDED.items()):
        current = out / f"embedded-{index}.hex"
        current.write_text((ROOT / embedded).read_bytes().hex() + "\n")
        compile_hex(current, ROOT / target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
