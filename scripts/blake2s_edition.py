#!/usr/bin/env python3
"""Measure the BLAKE2s edition of the statement on leanVM.

The BLAKE2s edition is the same spend with BLAKE2s-256 as every hash. It is
measured three ways:

  RISC-V   the Rust statement with software BLAKE2s (base RV64IM only), and
           with leanVM's `blake2s` instruction;
  EVM      the hand-written entry calling a BLAKE2s precompile at 0xb2, under
           REVM, the interpreter written for proving and compiled ahead of
           time, with the precompile served in software or with the
           instruction;
  EVM      the Yul entry computing BLAKE2s in EVM code, for an EVM without
           the precompile, under the same three.

The script checks both entries and the Rust statement against the oracle on
the public cases and hidden seeds 1 and 2, checks the interpreters and
compiled programs against REVM (parity, and random programs calling 0xb2),
runs every program on leanVM over the same cases, invalid ones included, and
with --rounds N times proofs of every program within leanVM's proof-size
limit. Run scripts/build.sh first.

Usage: python3 scripts/blake2s_edition.py results/RUN [--rounds 2] [--fuzz 300000]
"""
import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCORER = ROOT / "target/release/spend-challenge"
EXAMPLES = ROOT / "target/release/examples"
ELF = ROOT / "guests/target/riscv64im-unknown-none-elf/release"
PUBLIC = ROOT / "fixtures/public-blake2s.json"
HOST = subprocess.run(["rustc", "-vV"], capture_output=True, text=True).stdout.split("host: ")[1].split()[0]
TOOLCHAIN = Path(os.environ.get("RUSTUP_HOME", Path.home() / ".rustup")) / "toolchains" / f"nightly-2026-09-17-{HOST}"
ENTRIES = {"precompile": "evm/blake2s/precompile.hex", "blake2s-in-evm": "evm/blake2s/bytecode.hex"}
# name: (guest binary, route, entry or None)
PROGRAMS = {
    "riscv-base": ("b2-native-software", "native", None),
    "riscv-blake2s-instruction": ("b2-native-instruction", "native", None),
    **{f"evm-precompile-{impl}-{run}": (f"b2-evm-{run}-{impl}", "evm", "precompile")
       for run in ("revm", "fast", "compiled") for impl in ("software", "instruction")},
    **{f"evm-in-evm-{run}": (f"b2-evm-{run}-software", "evm", "blake2s-in-evm") for run in ("revm", "fast", "compiled")},
}


def run(command, **kwargs):
    return subprocess.run([str(c) for c in command], capture_output=True, text=True, **kwargs)


def build(entry: str, env: dict):
    (ROOT / "guests/blake2s-edition/bytecode.bin").write_bytes(bytes.fromhex((ROOT / ENTRIES[entry]).read_text().strip()))
    run([sys.executable, ROOT / "scripts/compile_programs.py"], check=True)
    run(["cargo", "build", "--release", "--offline", "-p", "spend-blake2s-edition-guests"], cwd=ROOT / "guests", env=env,
        check=True)


def execute(elf: Path, route: str, fixtures: list) -> dict:
    cycles, padded, witness, committed, rejected = [], set(), set(), set(), 0
    for path in fixtures:
        result = run([SCORER, "execute", "--route", route, "--elf", elf, "--fixtures", path])
        lines = [json.loads(line) for line in result.stdout.splitlines()]
        assert result.returncode == 0 and not lines[-1]["failures"], (elf, path, lines[-1])
        for record in lines[:-1]:
            if record["valid"]:
                cycles.append(record["cycles"])
                committed.add(record["committed_words"])
            elif not record["accepted"]:
                rejected += 1
        padded |= set(lines[-1]["distinct_padded_cycles"])
        witness |= set(lines[-1]["distinct_witness_log_size"])
    return {"max_cycles": max(cycles), "min_cycles": min(cycles), "valid_cases": len(cycles), "invalid_rejected": rejected,
            "padded_cycles": sorted(padded), "witness_log_size": sorted(witness), "committed_words": sorted(committed),
            "provable_at_pinned_size_bound": all(mu <= 28 for mu in witness)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("out", type=Path)
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--fuzz", type=int, default=300_000)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PATH=f"{TOOLCHAIN / 'bin'}:{os.environ['PATH']}", DYLD_LIBRARY_PATH=str(TOOLCHAIN / "lib"))
    run([sys.executable, ROOT / "oracle/spend_sha256.py", "--hash", "blake2s", "check", PUBLIC], check=True)
    with tempfile.TemporaryDirectory() as tmp:
        hidden = []
        for seed in (1, 2):
            path = Path(tmp) / f"hidden-blake2s-{seed}.json"
            run([sys.executable, ROOT / "oracle/spend_sha256.py", "--hash", "blake2s", "hidden", path, "--seed", seed,
                 "--count", 20], check=True)
            hidden.append(path)
        cases = [PUBLIC, *hidden]
        checks = {name: [json.loads(run([SCORER, "check", "--fixtures", path, "--hash", "blake2s", "--evm",
                                         ROOT / entry]).stdout) for path in cases] for name, entry in ENTRIES.items()}
        assert all(not c["failures"] for results in checks.values() for c in results), checks
        run([sys.executable, ROOT / "scripts/compile_programs.py"], check=True)
        run(["cargo", "build", "--release", "--offline", "-p", "spend-challenge", "--examples", "--bins"], cwd=ROOT,
            check=True)
        parity = json.loads(run([EXAMPLES / "blake2s_parity", *cases]).stdout)
        assert parity["all_match"], parity
        fuzz = [json.loads(run([EXAMPLES / "interpreter_fuzz", "--iterations", args.fuzz, "--seed", seed, "--precompile",
                                "blake2s", "--fixtures", PUBLIC, "--program", ROOT / ENTRIES["precompile"],
                                "--program", ROOT / ENTRIES["blake2s-in-evm"]]).stdout) for seed in (11, 12)]
        assert all(f["all_match"] for f in fuzz), [f["mismatches"][:2] for f in fuzz]
        results, elfs = {}, {}
        variants = ROOT / "target/elf-variants/blake2s"
        variants.mkdir(parents=True, exist_ok=True)
        for entry in ("precompile", "blake2s-in-evm"):
            build(entry, env)
            for name, (binary, route, program_entry) in PROGRAMS.items():
                # The RISC-V programs do not embed an entry; measure them once.
                if program_entry != entry and not (program_entry is None and entry == "precompile"):
                    continue
                elfs[name] = variants / name
                elfs[name].write_bytes((ELF / binary).read_bytes())
                results[name] = execute(elfs[name], route, cases)
                print(f"{name:34} {results[name]['max_cycles']:>12,} cycles  padded {results[name]['padded_cycles']}",
                      flush=True)
    build("precompile", env)  # leave the default guests, as scripts/build.sh does
    timing = []
    provable = [name for name, r in results.items() if r["provable_at_pinned_size_bound"]]
    for round_ in range(args.rounds):
        for name in provable:
            binary, route, _ = PROGRAMS[name]
            out = run([SCORER, "prove", "--route", route, "--elf", elfs[name], "--fixtures", PUBLIC, "--case", "transfer",
                       "--warmups", "1", "--repetitions", "2"], check=True).stdout
            timing += [{**json.loads(line), "program": name, "round": round_} for line in out.splitlines()]
    (args.out / "timing.jsonl").write_text("".join(json.dumps(r) + "\n" for r in timing))
    for name in provable:
        timed = [r["proving_s"] for r in timing if r["program"] == name and not r["warmup"]]
        if timed:
            results[name]["median_proof_s"] = round(statistics.median(timed), 3)
            results[name]["timed_proofs"] = len(timed)
    reference = {"base": results["riscv-base"]["max_cycles"], "instruction": results["riscv-blake2s-instruction"]["max_cycles"]}
    for r in results.values():
        r["over_riscv_base"] = round(r["max_cycles"] / reference["base"], 2)
        r["over_riscv_instruction"] = round(r["max_cycles"] / reference["instruction"], 2)
    summary = {
        "statement": "MSP Spend(20), BLAKE2s edition, v1",
        "precompile": "hypothetical BLAKE2s-256 at 0xb2, priced like SHA-256 (60 plus 12 per word)",
        "cases": "public BLAKE2s cases and hidden seeds 1 and 2, invalid cases included",
        "gas_used": {e["entry"]: e["gas_used_max"] for e in parity["entries"]},
        "checks": {"oracle_and_rust": "all cases", "parity_cases": parity["entries"][0]["cases"],
                   "fuzz_programs": sum(f["iterations"] - f["skipped_ef01"] for f in fuzz)},
        "programs": results,
    }
    (args.out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    (args.out / "parity.json").write_text(json.dumps(parity, indent=1) + "\n")
    print(json.dumps({n: (r["max_cycles"], r.get("median_proof_s")) for n, r in results.items()}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
