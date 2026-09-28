#!/usr/bin/env python3
"""Time leanVM proofs of the transfer case for every provable program.

Programs are interleaved: each round proves every program once as a warmup
and then twice timed, so slow drift in the machine affects all of them alike.
Proof times shift between sessions, so compare them only within one run.
Run scripts/build.sh first.

Usage: python3 scripts/time_proofs.py results/RUN/timing.jsonl [--rounds 3]
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
# name: (guest binary or EVM bytecode, scorer route)
PROGRAMS = {
    "riscv": ("spend-native", "native"),
    "evm-solidity": ("evm/baseline.hex", "evm"),
    "evm-yul": ("evm/yul/bytecode.hex", "evm"),
    "evm-calls-55": ("evm/controls/calls-55.hex", "control"),
    "rust-sha256-only": ("spend-hash-control", "control"),
    "rust-start-only": ("spend-null-control", "null"),
}


def prepare() -> dict:
    VARIANTS.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PATH=f"{TOOLCHAIN / 'bin'}:{os.environ['PATH']}", DYLD_LIBRARY_PATH=str(TOOLCHAIN / "lib"))
    paths = {}
    for name, (source, _) in PROGRAMS.items():
        if source.endswith(".hex"):
            (ROOT / "guests/evm/bytecode.bin").write_bytes(bytes.fromhex((ROOT / source).read_text().strip()))
            subprocess.run(["cargo", "build", "--release", "--offline", "-p", "spend-evm-guest"],
                           cwd=ROOT / "guests", env=env, check=True, capture_output=True)
            source = "spend-evm"
        paths[name] = VARIANTS / name
        shutil.copyfile(ELF / source, paths[name])
    # Leave the default guest embedding the baseline, as scripts/build.sh does.
    (ROOT / "guests/evm/bytecode.bin").write_bytes(bytes.fromhex((ROOT / "evm/baseline.hex").read_text().strip()))
    subprocess.run(["cargo", "build", "--release", "--offline", "-p", "spend-evm-guest"],
                   cwd=ROOT / "guests", env=env, check=True, capture_output=True)
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("out", type=Path)
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args()
    paths = prepare()
    power = subprocess.run(["pmset", "-g", "batt"], capture_output=True, text=True).stdout.splitlines()[:1]
    with args.out.open("w") as out:
        out.write(json.dumps({"record": "setup", "power": power, "load_average": os.getloadavg(),
                              "elf_sha256": {n: hashlib.sha256(p.read_bytes()).hexdigest() for n, p in paths.items()}}) + "\n")
        for round_ in range(args.rounds):
            for name, (_, route) in PROGRAMS.items():
                run = subprocess.run([str(SCORER), "prove", "--route", route, "--elf", str(paths[name]),
                                      "--fixtures", str(ROOT / "fixtures/public.json"), "--case", "transfer",
                                      "--warmups", "1", "--repetitions", "2"], capture_output=True, text=True, check=True)
                for line in run.stdout.splitlines():
                    out.write(json.dumps({**json.loads(line), "program": name, "round": round_}) + "\n")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
