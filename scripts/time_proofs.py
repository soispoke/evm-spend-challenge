#!/usr/bin/env python3
"""Time leanVM proofs of the transfer case for every provable program.

Programs are interleaved: each round proves every program once as a warmup
and then twice timed, so slow drift in the machine affects all of them alike.
Proof times shift between sessions, so compare them only within one run.
Run scripts/build.sh first.

The default set is the challenge's programs. The `interpreters` set times the
entries and the calls-only control under each interpreter and compiled ahead
of time (see scripts/interpreters.py), with the RISC-V reference.

Usage: python3 scripts/time_proofs.py results/RUN/timing.jsonl [--rounds 3] [--set challenge|interpreters]
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCORER = ROOT / "target/release/spend-challenge"
ELF = ROOT / "guests/target/riscv64im-unknown-none-elf/release"
VARIANTS = ROOT / "target/elf-variants"
HOST = subprocess.run(["rustc", "-vV"], capture_output=True, text=True).stdout.split("host: ")[1].split()[0]
TOOLCHAIN = Path(os.environ.get("RUSTUP_HOME", Path.home() / ".rustup")) / "toolchains" / f"nightly-2026-09-17-{HOST}"
# name: (guest binary or EVM bytecode, scorer route, EVM guest binary)
PROGRAM_SETS = {
    "challenge": {
        "riscv": ("spend-native", "native", None),
        "evm-solidity": ("evm/baseline.hex", "evm", "spend-evm"),
        "evm-yul": ("evm/yul/bytecode.hex", "evm", "spend-evm"),
        "evm-calls-55": ("evm/controls/calls-55.hex", "control", "spend-evm"),
        "rust-sha256-only": ("spend-hash-control", "control", None),
        "rust-start-only": ("spend-null-control", "null", None),
    },
    "interpreters": {
        "riscv": ("spend-native", "native", None),
        **{f"{entry}-{interp}": (path, route, binary)
           for entry, path, route in (("bytecode", "evm/bytecode/bytecode.hex", "evm"),
                                      ("yul", "evm/yul/bytecode.hex", "evm"),
                                      ("solidity", "evm/baseline.hex", "evm"),
                                      ("calls-55", "evm/controls/calls-55.hex", "control"))
           for interp, binary in (("revm", "spend-evm"), ("revm-direct", "spend-evm-revm-direct"),
                                  ("fast", "spend-evm-fast"), ("compiled", "spend-evm-compiled"))
           if entry == "bytecode" or interp != "revm-direct"},
    },
}


def build_evm_guests(bytecode_hex: str, env: dict):
    (ROOT / "guests/evm/bytecode.bin").write_bytes(bytes.fromhex(bytecode_hex))
    subprocess.run(["python3", str(ROOT / "scripts/compile_programs.py")], check=True)
    subprocess.run(["cargo", "build", "--release", "--offline", "-p", "spend-evm-guest", "-p", "spend-evm-variants-guest"],
                   cwd=ROOT / "guests", env=env, check=True, capture_output=True)


def prepare(programs: dict) -> dict:
    VARIANTS.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PATH=f"{TOOLCHAIN / 'bin'}:{os.environ['PATH']}", DYLD_LIBRARY_PATH=str(TOOLCHAIN / "lib"))
    paths = {}
    built = None
    for name, (source, _, binary) in programs.items():
        if source.endswith(".hex"):
            if built != source:
                build_evm_guests((ROOT / source).read_text().strip(), env)
                built = source
            source = binary
        paths[name] = VARIANTS / name
        shutil.copyfile(ELF / source, paths[name])
    # Leave the default guests embedding the baseline, as scripts/build.sh does.
    build_evm_guests((ROOT / "evm/baseline.hex").read_text().strip(), env)
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("out", type=Path)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--set", choices=PROGRAM_SETS, default="challenge")
    args = parser.parse_args()
    programs = PROGRAM_SETS[args.set]
    paths = prepare(programs)
    power = subprocess.run(["pmset", "-g", "batt"], capture_output=True, text=True).stdout.splitlines()[:1]
    with args.out.open("w") as out:
        out.write(json.dumps({"record": "setup", "power": power, "load_average": os.getloadavg(),
                              "elf_sha256": {n: hashlib.sha256(p.read_bytes()).hexdigest() for n, p in paths.items()}}) + "\n")
        for round_ in range(args.rounds):
            for name, (_, route, _) in programs.items():
                run = subprocess.run([str(SCORER), "prove", "--route", route, "--elf", str(paths[name]),
                                      "--fixtures", str(ROOT / "fixtures/public.json"), "--case", "transfer",
                                      "--warmups", "1", "--repetitions", "2"], capture_output=True, text=True, check=True)
                for line in run.stdout.splitlines():
                    out.write(json.dumps({**json.loads(line), "program": name, "round": round_}) + "\n")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
