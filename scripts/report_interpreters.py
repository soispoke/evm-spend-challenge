#!/usr/bin/env python3
"""Build results/interpreters-summary.json from an interpreter run.

Reads the files written by scripts/interpreters.py (interpreters.json and the
ledger), the parity and fuzz checks, and scripts/time_proofs.py --set
interpreters (timing.jsonl), and adds the cost split and the estimates for
faster SHA-256. The SHA-256 cycles and the RISC-V reference come from
results/summary.json, the challenge's own measurements.

Usage: python3 scripts/report_interpreters.py results/RUN
"""
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPRESSIONS, CALLS = 105, 55
ENTRIES = ("solidity", "yul", "bytecode")
INTERPRETERS = ("revm", "revm-direct", "fast", "compiled")


def jsonl(path: Path) -> list:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def timing(path: Path) -> dict:
    rows = [r for r in jsonl(path) if r.get("record") != "setup"]
    result = {}
    for program in dict.fromkeys(r["program"] for r in rows):
        selected = [r for r in rows if r["program"] == program]
        timed = [r["proving_s"] for r in selected if not r["warmup"]]
        result[program] = {"median_s": round(statistics.median(timed), 3), "min_s": round(min(timed), 3),
                           "max_s": round(max(timed), 3), "timed_proofs": len(timed),
                           "padded_cycles": selected[0]["padded_cycles"],
                           "peak_memory_gib": round(max(r["peak_rss_bytes"] for r in selected) / 2**30, 2)}
    return result


def main() -> int:
    run = Path(sys.argv[1])
    challenge = json.loads((ROOT / "results/summary.json").read_text())
    reference = challenge["cycles"]["riscv"]["max_cycles"]
    hashing = challenge["breakdown"]["sha256"]
    riscv_other = challenge["breakdown"]["riscv_outside_sha256"]
    measured = json.loads((run / "interpreters.json").read_text())["results"]
    cycles = {program: {interp: measured[program][interp]["max_cycles"] for interp in INTERPRETERS}
              for program in measured}
    gas = {program: measured[program]["gas"] for program in measured}

    breakdown = {}
    for interp in INTERPRETERS:
        start = cycles["evm-calls-0"][interp]
        calls = cycles["evm-calls-55"][interp] - hashing - start
        breakdown[interp] = {
            "start_up": start,
            "precompile_calls": calls,
            "precompile_calls_per_call": round(calls / CALLS, 1),
            "bytecode_outside_calls": {e: cycles[e][interp] - cycles["evm-calls-55"][interp] for e in ENTRIES},
            "extra_over_reference": {e: cycles[e][interp] - reference for e in ENTRIES},
        }

    def estimate(per_compression: int) -> dict:
        saved = hashing - COMPRESSIONS * per_compression
        row = {"cycles_per_compression": per_compression, "riscv": reference - saved}
        for e in ENTRIES:
            for interp in INTERPRETERS:
                row[f"{e}_{interp}"] = cycles[e][interp] - saved
                row[f"{e}_{interp}_over_riscv"] = round((cycles[e][interp] - saved) / row["riscv"], 2)
        return row

    timings = timing(run / "timing.jsonl") if (run / "timing.jsonl").exists() else {}
    setup = jsonl(run / "timing.jsonl")[0] if timings else {}
    proof_ratio = {name: round(t["median_s"] / timings["riscv"]["median_s"], 2) for name, t in timings.items()} if timings else {}

    parity = json.loads((run / "parity.json").read_text())
    compiled = json.loads((run / "compiled-parity.json").read_text())
    fuzz = [json.loads(p.read_text()) for p in sorted(run.glob("fuzz-*.json"))]
    ledger = jsonl(run / "ledger.jsonl")
    summary = {
        "question": "How much of the EVM's extra proving cost is the interpreter?",
        "reference_cycles": reference,
        "sha256_cycles": hashing,
        "riscv_outside_sha256": riscv_other,
        "cycles": cycles,
        "cycles_over_reference": {p: {i: round(c / reference, 3) for i, c in row.items()} for p, row in cycles.items()},
        "padded_cycles": {p: {i: measured[p][i]["padded_cycles"][0] for i in INTERPRETERS} for p in measured},
        "gas_used": gas,
        "cycles_per_gas": {p: {i: round(cycles[p][i] / gas[p], 1) for i in INTERPRETERS} for p in ENTRIES},
        "breakdown": breakdown,
        "estimates_faster_sha256": [estimate(c) for c in (200, 0)],
        "proving": timings,
        "proving_time_over_riscv": proof_ratio,
        "proving_conditions": ("transfer case; per program and round one warmup and two timed proofs, interleaved; "
                               f"Apple M5 Max, {setup['power'][0] if setup.get('power') else 'power unknown'}, "
                               f"load average {setup['load_average'][0]:.1f} at start; no zero knowledge"
                               if setup else None),
        "validation": {
            "parity_cases_per_program": parity["programs"][0]["cases"],
            "parity_all_match": parity["all_match"],
            "gas_constant_on_valid_cases": all(p["gas_used_max"] == p["gas_used_min"] for p in parity["programs"]),
            "compiled_runs_per_program": compiled["programs"][0]["runs"],
            "compiled_all_match": compiled["all_match"],
            "fuzz_programs": sum(f["iterations"] - f["skipped_ef01"] for f in fuzz),
            "fuzz_all_match": all(f["all_match"] for f in fuzz),
            "leanvm": {p: {i: {"valid_accepted": measured[p][i]["valid_cases"],
                               "invalid_rejected": measured[p][i]["invalid_rejected"]} for i in INTERPRETERS}
                       for p in ENTRIES},
        },
        "rounds": [{"note": r["note"], "bytecode_fast": r["results"]["bytecode"]["fast"]["max_cycles"],
                    "calls_55_fast": r["results"]["evm-calls-55"]["fast"]["max_cycles"],
                    "solidity_fast": r["results"]["solidity"]["fast"]["max_cycles"]} for r in ledger],
    }
    (ROOT / "results/interpreters-summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps({k: summary[k] for k in ("cycles", "gas_used", "breakdown", "proving_time_over_riscv")}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
