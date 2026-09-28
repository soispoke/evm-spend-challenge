#!/usr/bin/env python3
"""Measure the EVM programs under each way of running them on leanVM.

For every program (the three entries and the two EVM controls) this embeds the
bytecode, builds the four EVM guests (the scoring harness's REVM, REVM with the
direct SHA-256 call, the interpreter written for proving, and the program
compiled ahead of time), and executes test cases on leanVM. It first checks
them against the REVM reference on the test cases and, for the two
interpreters, on random programs, and stops if any result or gas count
differs.

Without --run it is the quick check used while optimizing: the public cases,
200,000 random programs with a time-based seed, valid cases only on leanVM.
With --run DIR it writes a full run into DIR: parity on the public cases and
hidden seeds 1, 2 and 3, the compiled programs at five gas limits, the random
programs for each --fuzz-seed, and leanVM on the public cases and seeds 1 and 2
including the invalid cases. --record appends the run to a JSON-lines ledger.

Usage: python3 scripts/interpreters.py [--run DIR] [--fuzz N] [--fuzz-seeds S ...] [--record LEDGER --note TEXT]
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCORER = ROOT / "target/release/spend-challenge"
EXAMPLES = ROOT / "target/release/examples"
ELF = ROOT / "guests/target/riscv64im-unknown-none-elf/release"
FIXTURES = ROOT / "fixtures/public.json"
HOST = subprocess.run(["rustc", "-vV"], capture_output=True, text=True).stdout.split("host: ")[1].split()[0]
TOOLCHAIN = Path(os.environ.get("RUSTUP_HOME", Path.home() / ".rustup")) / "toolchains" / f"nightly-2026-09-17-{HOST}"
PROGRAMS = {
    "solidity": ("evm/baseline.hex", "evm"),
    "yul": ("evm/yul/bytecode.hex", "evm"),
    "bytecode": ("evm/bytecode/bytecode.hex", "evm"),
    "evm-calls-55": ("evm/controls/calls-55.hex", "control"),
    "evm-calls-0": ("evm/controls/calls-0.hex", "evm-start"),
}
INTERPRETERS = {"revm": "spend-evm", "revm-direct": "spend-evm-revm-direct", "fast": "spend-evm-fast",
                "compiled": "spend-evm-compiled"}


def build_guests(bytecode_hex: str):
    (ROOT / "guests/evm/bytecode.bin").write_bytes(bytes.fromhex(bytecode_hex))
    subprocess.run([sys.executable, str(ROOT / "scripts/compile_programs.py")], check=True)
    env = dict(os.environ, PATH=f"{TOOLCHAIN / 'bin'}:{os.environ['PATH']}", DYLD_LIBRARY_PATH=str(TOOLCHAIN / "lib"))
    subprocess.run(["cargo", "build", "--release", "--offline", "-p", "spend-evm-guest", "-p", "spend-evm-variants-guest"],
                   cwd=ROOT / "guests", env=env, check=True, capture_output=True)


def execute(elf: Path, route: str, fixtures: list, all_cases: bool) -> dict:
    cycles, padded, witness, rejected = [], set(), set(), 0
    for path in fixtures:
        flags = [] if all_cases else ["--valid-only"]
        run = subprocess.run([str(SCORER), "execute", "--route", route, "--elf", str(elf), "--fixtures", str(path),
                              *flags], capture_output=True, text=True)
        lines = [json.loads(line) for line in run.stdout.splitlines()]
        summary = lines[-1]
        assert run.returncode == 0 and not summary["failures"], (elf, path, summary)
        cycles += [r["cycles"] for r in lines[:-1] if r["valid"]]
        rejected += sum(1 for r in lines[:-1] if not r["valid"] and not r["accepted"])
        padded |= set(summary["distinct_padded_cycles"])
        witness |= set(summary["distinct_witness_log_size"])
    return {"max_cycles": max(cycles), "min_cycles": min(cycles), "valid_cases": len(cycles),
            "invalid_rejected": rejected, "padded_cycles": sorted(padded), "witness_log_size": sorted(witness)}


def json_run(command) -> dict:
    return json.loads(subprocess.run([str(c) for c in command], capture_output=True, text=True).stdout)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", type=Path)
    parser.add_argument("--fuzz", type=int, default=200_000)
    parser.add_argument("--fuzz-seeds", type=int, nargs="*")
    parser.add_argument("--record", type=Path)
    parser.add_argument("--note", default="")
    args = parser.parse_args()
    subprocess.run([sys.executable, str(ROOT / "scripts/compile_programs.py")], check=True)
    subprocess.run(["cargo", "build", "--release", "--offline", "-p", "spend-challenge", "--examples", "--bins"],
                   cwd=ROOT, check=True, capture_output=True)
    seeds = args.fuzz_seeds or [int(time.time())]
    with tempfile.TemporaryDirectory() as tmp:
        hidden = []
        if args.run:
            args.run.mkdir(parents=True, exist_ok=True)
            for seed in (1, 2, 3):
                path = Path(tmp) / f"hidden-{seed}.json"
                subprocess.run([sys.executable, str(ROOT / "oracle/spend_sha256.py"), "hidden", str(path), "--seed",
                                str(seed), "--count", "40"], check=True, capture_output=True)
                hidden.append(path)
        checked = [FIXTURES, *hidden]
        parity = json_run([EXAMPLES / "interpreter_parity", *sum((["--fixtures", p] for p in checked), []),
                           *sum((["--program", f"{n}={ROOT / p}"] for n, (p, _) in PROGRAMS.items()), [])])
        compiled = json_run([EXAMPLES / "compiled_parity", *checked])
        fuzz = [json_run([EXAMPLES / "interpreter_fuzz", "--iterations", args.fuzz, "--seed", seed, "--fixtures", FIXTURES,
                          *sum((["--program", ROOT / p] for p, _ in PROGRAMS.values()), [])]) for seed in seeds]
        if not (parity["all_match"] and compiled["all_match"] and all(f["all_match"] for f in fuzz)):
            print(json.dumps({"parity": parity, "compiled": compiled, "fuzz": [f["mismatches"][:3] for f in fuzz]}, indent=1))
            return 1
        gas = {p["program"]: p["gas_used_max"] for p in parity["programs"]}
        on_leanvm = [FIXTURES, *hidden[:2]]
        results = {}
        for name, (path, route) in PROGRAMS.items():
            build_guests((ROOT / path).read_text().strip())
            results[name] = {"gas": gas[name], **{interp: execute(ELF / elf, route, on_leanvm, bool(args.run))
                                                  for interp, elf in INTERPRETERS.items()}}
    # Leave the default guests embedding the baseline, as scripts/build.sh does.
    build_guests((ROOT / "evm/baseline.hex").read_text().strip())
    record = {"time": time.strftime("%Y-%m-%dT%H:%M:%S"), "note": args.note,
              "interpreter_sha256": hashlib.sha256((ROOT / "interpreters/src/fast.rs").read_bytes()).hexdigest()[:16],
              "parity_cases": sum(p["cases"] for p in parity["programs"]),
              "compiled_parity_runs": sum(p["runs"] for p in compiled["programs"]),
              "fuzz_programs": sum(f["iterations"] for f in fuzz), "fuzz_seeds": seeds,
              "leanvm_cases": "public and hidden seeds 1 and 2, invalid cases included" if args.run else "public, valid only",
              "results": results}
    for name, row in results.items():
        cells = "  ".join(f"{interp} {row[interp]['max_cycles']:>9,}" for interp in INTERPRETERS)
        print(f"{name:14} gas {row['gas']:>6,}  {cells}")
    if args.run:
        (args.run / "parity.json").write_text(json.dumps(parity, indent=1) + "\n")
        (args.run / "compiled-parity.json").write_text(json.dumps(compiled, indent=1) + "\n")
        for seed, result in zip(seeds, fuzz):
            (args.run / f"fuzz-{seed}.json").write_text(json.dumps(result, indent=1) + "\n")
        (args.run / "interpreters.json").write_text(json.dumps(record, indent=1) + "\n")
    if args.record:
        with args.record.open("a") as ledger:
            ledger.write(json.dumps(record) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
