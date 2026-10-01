#!/usr/bin/env python3
"""Score an EVM candidate: correctness gate, then RV64IM cycles on leanVM.

1. Check the candidate natively on the public cases and on fresh hidden cases
   (new seeds): every valid input must return the exact digest and every
   invalid input must be rejected.
2. Build the EVM guest with the candidate bytecode and execute every valid case
   on the pinned leanVM executor. Every padded table size, which a proof reveals,
   must be the same across the tested valid inputs.
3. The score is the largest cycle count over all valid cases. Lower is better.

Usage: python3 scripts/score.py [BYTECODE_HEX] [--hidden-seeds N ...] [--out FILE]
"""
import argparse
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCORER = ROOT / "target/release/spend-challenge"
GUEST = ROOT / "guests/target/riscv64im-unknown-none-elf/release/spend-evm"
HOST = subprocess.run(["rustc", "-vV"], capture_output=True, text=True).stdout.split("host: ")[1].split()[0]
TOOLCHAIN = Path(os.environ.get("RUSTUP_HOME", Path.home() / ".rustup")) / "toolchains" / f"nightly-2026-09-17-{HOST}"


def run_json_lines(command):
    run = subprocess.run(command, capture_output=True, text=True)
    lines = [json.loads(line) for line in run.stdout.splitlines() if line.startswith("{")]
    return run.returncode, lines


def build_guest(bytecode_hex: str):
    (ROOT / "guests/evm/bytecode.bin").write_bytes(bytes.fromhex(bytecode_hex))
    env = dict(os.environ, PATH=f"{TOOLCHAIN / 'bin'}:{os.environ['PATH']}", DYLD_LIBRARY_PATH=str(TOOLCHAIN / "lib"))
    build = subprocess.run(["cargo", "build", "--release", "--offline", "-p", "spend-evm-guest"],
                           cwd=ROOT / "guests", env=env, capture_output=True, text=True)
    if build.returncode != 0:
        sys.stderr.write(build.stdout + build.stderr)
        raise SystemExit("building the EVM guest failed; cargo's output is above")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("bytecode", nargs="?", default=str(ROOT / "evm/baseline.hex"))
    parser.add_argument("--hidden-seeds", type=int, nargs="*", help="default: two fresh random seeds")
    parser.add_argument("--hidden-count", type=int, default=24)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    bytecode_hex = Path(args.bytecode).read_text().strip()
    if bytecode_hex.lower().removeprefix("0x").startswith("ef"):
        # L1 rejects new code starting with 0xEF (EIP-3541), and REVM would parse
        # 0xEF01 as an EIP-7702 delegation instead of running it.
        print(json.dumps({"accepted": False, "reason": "bytecode starts with 0xEF"}))
        return 1
    seeds = args.hidden_seeds if args.hidden_seeds is not None else [secrets.randbits(32) for _ in range(2)]

    with tempfile.TemporaryDirectory() as tmp:
        case_files = [ROOT / "fixtures/public.json"]
        for seed in seeds:
            path = Path(tmp) / f"hidden-{seed}.json"
            subprocess.run([sys.executable, str(ROOT / "oracle/spend_sha256.py"), "hidden", str(path),
                            "--seed", str(seed), "--count", str(args.hidden_count)], check=True)
            case_files.append(path)
        hex_path = Path(tmp) / "candidate.hex"
        hex_path.write_text(bytecode_hex)

        gate = []
        for path in case_files:
            code, lines = run_json_lines([str(SCORER), "check", "--fixtures", str(path), "--evm", str(hex_path)])
            gate.append({"cases": path.name, **lines[-1]})
            if code != 0:
                print(json.dumps({"accepted": False, "gate": gate}, indent=1))
                return 1

        build_guest(bytecode_hex)
        cycles, padded, padded_shapes, witness = [], set(), set(), set()
        for path in case_files:
            code, lines = run_json_lines([str(SCORER), "execute", "--route", "evm", "--elf", str(GUEST),
                                          "--fixtures", str(path), "--valid-only"])
            summary = lines[-1]
            if code != 0:
                print(json.dumps({"accepted": False, "execution_failures": summary["failures"]}, indent=1))
                return 1
            cycles += [line["cycles"] for line in lines[:-1]]
            padded |= set(summary["distinct_padded_cycles"])
            padded_shapes |= {tuple(counts) for counts in summary["distinct_padded_counts"]}
            witness |= set(summary["distinct_witness_log_size"])

    result = {
        "accepted": len(padded_shapes) == 1,
        "score_cycles": max(cycles),
        "min_cycles": min(cycles),
        "valid_cases_executed": len(cycles),
        "padded_cycles": sorted(padded),
        "padded_counts": sorted(padded_shapes),
        "witness_log_size": sorted(witness),
        "provable_at_pinned_size_bound": all(mu <= 28 for mu in witness),
        "bytecode_bytes": len(bytecode_hex) // 2,
        "hidden_seeds": seeds,
        "gate": gate,
    }
    if len(padded_shapes) != 1:
        result["rejection"] = "padded table sizes vary across the tested valid inputs"
    print(json.dumps(result, indent=1))
    if args.out:
        args.out.write_text(json.dumps(result, indent=1) + "\n")
    return 0 if result["accepted"] else 1


if __name__ == "__main__":
    sys.exit(main())
