#!/usr/bin/env python3
"""Run every deterministic measurement into one directory.

For the RISC-V reference, both EVM entries and the four control programs:
leanVM cycle counts on the public cases, the full scorer with fixed hidden
seeds, extra hidden checks, EVM instruction profiles, and the rule-removal
check. Proof timing is separate (scripts/time_proofs.py). Run
scripts/build.sh first.

Usage: python3 scripts/measure.py results/RUN
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCORER = ROOT / "target/release/spend-challenge"
PROFILE = ROOT / "target/release/examples/opcode_profile"
ELF = ROOT / "guests/target/riscv64im-unknown-none-elf/release"
FIXTURES = ROOT / "fixtures/public.json"
ENTRIES = {"solidity": "evm/baseline.hex", "yul": "evm/yul/bytecode.hex"}
CONTROLS = {"evm-calls-55": "evm/controls/calls-55.hex", "evm-calls-0": "evm/controls/calls-0.hex"}
HOST = subprocess.run(["rustc", "-vV"], capture_output=True, text=True).stdout.split("host: ")[1].split()[0]
TOOLCHAIN = Path(os.environ.get("RUSTUP_HOME", Path.home() / ".rustup")) / "toolchains" / f"nightly-2026-09-17-{HOST}"


def run(command, out=None):
    result = subprocess.run([str(c) for c in command], capture_output=True, text=True)
    if out is not None:
        out.write_text(result.stdout)
    return result


def build_evm_guest(bytecode_hex: str):
    (ROOT / "guests/evm/bytecode.bin").write_bytes(bytes.fromhex(Path(ROOT / bytecode_hex).read_text().strip()))
    env = dict(os.environ, PATH=f"{TOOLCHAIN / 'bin'}:{os.environ['PATH']}", DYLD_LIBRARY_PATH=str(TOOLCHAIN / "lib"))
    subprocess.run(["cargo", "build", "--release", "--offline", "-p", "spend-evm-guest"],
                   cwd=ROOT / "guests", env=env, check=True, capture_output=True)


def main() -> int:
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    # Cycles on the public cases. Entries and the reference also run the
    # invalid cases, which they must reject.
    run([SCORER, "execute", "--route", "native", "--elf", ELF / "spend-native", "--fixtures", FIXTURES],
        out / "execute-riscv.jsonl")
    run([SCORER, "execute", "--route", "control", "--elf", ELF / "spend-hash-control", "--fixtures", FIXTURES],
        out / "execute-rust-sha256-only.jsonl")
    run([SCORER, "execute", "--route", "null", "--elf", ELF / "spend-null-control", "--fixtures", FIXTURES],
        out / "execute-rust-start-only.jsonl")
    for name, path in ENTRIES.items():
        build_evm_guest(path)
        run([SCORER, "execute", "--route", "evm", "--elf", ELF / "spend-evm", "--fixtures", FIXTURES],
            out / f"execute-{name}.jsonl")
    for name, path in CONTROLS.items():
        build_evm_guest(path)
        route = "evm-start" if name == "evm-calls-0" else "control"
        run([SCORER, "execute", "--route", route, "--elf", ELF / "spend-evm", "--fixtures", FIXTURES],
            out / f"execute-{name}.jsonl")
    # Full scorer with fixed hidden seeds.
    for name, seeds in (("solidity", ["101", "202"]), ("yul", ["303", "404"])):
        run([sys.executable, ROOT / "scripts/score.py", ROOT / ENTRIES[name], "--hidden-seeds", *seeds,
             "--out", out / f"score-{name}.json"])
    build_evm_guest(ENTRIES["solidity"])
    # More hidden cases, checked natively for the Rust reference and both entries.
    checks = []
    with tempfile.TemporaryDirectory() as tmp:
        for seed in (1, 2, 3):
            cases = Path(tmp) / f"hidden-{seed}.json"
            run([sys.executable, ROOT / "oracle/spend_sha256.py", "hidden", cases, "--seed", seed, "--count", 40])
            for name, path in ENTRIES.items():
                result = json.loads(run([SCORER, "check", "--fixtures", cases, "--evm", ROOT / path]).stdout)
                checks.append({"seed": seed, "entry": name, **result})
    (out / "hidden-checks.json").write_text(json.dumps(checks, indent=1) + "\n")
    # EVM instruction profiles on the transfer case.
    for name, path in {**ENTRIES, **CONTROLS}.items():
        run([PROFILE, ROOT / path, FIXTURES, "transfer"], out / f"opcodes-{name}.json")
    # A missing rule check must fail a public case.
    for name in ENTRIES:
        run([sys.executable, ROOT / "scripts/mutation_check.py", name, out / f"rule-removal-{name}.json"])
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
