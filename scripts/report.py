#!/usr/bin/env python3
"""Build results/summary.json from a measurement run.

Reads the files written by scripts/measure.py and scripts/time_proofs.py and
derives the cost breakdown, the instruction mix and the estimates for faster
SHA-256 from the measured controls.

Usage: python3 scripts/report.py results/RUN
"""
import hashlib
import json
import statistics
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPRESSIONS, CALLS = 105, 55
ENTRIES = ("solidity", "yul", "bytecode")
KINDS = [
    ("stack", lambda o: o.startswith(("PUSH", "DUP", "SWAP")) or o == "POP"),
    ("arithmetic_and_comparisons", lambda o: o in {"ADD", "SUB", "MUL", "DIV", "MOD", "AND", "OR", "XOR", "NOT", "SHL",
                                                  "SHR", "SAR", "LT", "GT", "SLT", "SGT", "EQ", "ISZERO", "BYTE",
                                                  "SIGNEXTEND", "EXP"}),
    ("jumps", lambda o: o in {"JUMP", "JUMPI", "JUMPDEST"}),
    ("memory", lambda o: o in {"MLOAD", "MSTORE", "MSTORE8", "MCOPY"}),
    ("calldata", lambda o: o.startswith("CALLDATA")),
    ("calls", lambda o: o in {"GAS", "STATICCALL"} or o.startswith("RETURNDATA")),
]


def jsonl(path: Path) -> list:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def execution(path: Path) -> dict:
    lines = jsonl(path)
    summary = lines[-1]
    record = {"cases": summary["valid_cases"], "max_cycles": summary["score_max_cycles"],
              "min_cycles": summary["min_cycles"], "failures": summary["failures"]}
    assert not summary["failures"] and len(summary["distinct_padded_cycles"]) == 1, path
    record["padded_cycles"] = summary["distinct_padded_cycles"][0]
    record["witness_log_size"] = summary["distinct_witness_log_size"][0]
    return record


def timing(path: Path) -> dict:
    rows = [r for r in jsonl(path) if r.get("record") != "setup"]
    result = {}
    for program in dict.fromkeys(r["program"] for r in rows):
        selected = [r for r in rows if r["program"] == program]
        timed = [r["proving_s"] for r in selected if not r["warmup"]]
        result[program] = {"median_s": round(statistics.median(timed), 3), "min_s": round(min(timed), 3),
                           "max_s": round(max(timed), 3), "timed_proofs": len(timed),
                           "peak_memory_gib": round(max(r["peak_rss_bytes"] for r in selected) / 2**30, 2),
                           "proof_kib": round(selected[0]["proof_bytes"] / 1024, 1),
                           "verification_ms": round(1000 * statistics.median(r["verification_s"] for r in selected), 1)}
    return result


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    run = Path(sys.argv[1])
    ex = {name: execution(run / f"execute-{name}.jsonl") for name in
          ("riscv", *ENTRIES, "evm-calls-55", "evm-calls-0", "rust-sha256-only", "rust-start-only")}
    scores = {name: json.loads((run / f"score-{name}.json").read_text()) for name in ENTRIES}
    for name, score in scores.items():
        ex[name].update(max_cycles=score["score_cycles"], min_cycles=score["min_cycles"],
                        cases=score["valid_cases_executed"], bytecode_bytes=score["bytecode_bytes"])
    reference = ex["riscv"]["max_cycles"]
    hashing = ex["rust-sha256-only"]["max_cycles"] - ex["rust-start-only"]["max_cycles"]
    start = ex["evm-calls-0"]["max_cycles"]
    calls = ex["evm-calls-55"]["max_cycles"] - hashing - start
    outside = {name: ex[name]["max_cycles"] - ex["evm-calls-55"]["max_cycles"] for name in ENTRIES}
    riscv_other = reference - hashing

    instructions = {}
    gas = {}
    for name in (*ENTRIES, "evm-calls-55", "evm-calls-0"):
        profile = json.loads((run / f"opcodes-{name}.json").read_text())
        gas[name] = profile["gas_used"]
        kinds = {kind: sum(n for op, n in profile["opcodes"] if test(op)) for kind, test in KINDS}
        kinds["other"] = profile["instructions"] - sum(kinds.values())
        instructions[name] = {"total": profile["instructions"], "by_kind": kinds,
                              "peak_evm_memory_bytes": profile["peak_memory_bytes"]}

    def estimate(per_compression: int) -> dict:
        hash_part = COMPRESSIONS * per_compression
        row = {"cycles_per_compression": per_compression, "riscv": riscv_other + hash_part}
        for name in ENTRIES:
            row[name] = start + calls + outside[name] + hash_part
            row[f"{name}_over_riscv"] = round(row[name] / row["riscv"], 2)
        return row

    batches = {"final": timing(run / "timing.jsonl")}
    for path in sorted((run / "earlier-timing").glob("*.jsonl")):
        rows = jsonl(path)
        renamed = {"evm-baseline": "evm-solidity", "evm-calls55": "evm-calls-55",
                   "hash-control": "rust-sha256-only", "null-control": "rust-start-only"}
        for row in rows:
            row["program"] = renamed.get(row.get("program"), row.get("program"))
        tmp = run / f".{path.stem}.tmp"
        tmp.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
        batches[path.stem] = timing(tmp)
        tmp.unlink()
    ratios = {name: sorted(round(b[name]["median_s"] / b["riscv"]["median_s"], 2) for b in batches.values() if name in b)
              for name in (f"evm-{e}" for e in ENTRIES) if any(name in b for b in batches.values())}

    hidden = json.loads((run / "hidden-checks.json").read_text())
    removal = {name: json.loads((run / f"rule-removal-{name}.json").read_text())["mutants"] for name in ENTRIES}
    setup = jsonl(run / "timing.jsonl")[0]
    leanvm = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT / "vendor/leanVM", capture_output=True, text=True).stdout.strip()
    summary = {
        "statement": "MSP Spend(20), SHA-256 edition, v1",
        "machine": f"leanVM riscv-exploration {leanvm}, RV64IM",
        "cycles": ex,
        "cycles_over_reference": {name: round(ex[name]["max_cycles"] / reference, 3) for name in (*ENTRIES, "evm-calls-55")},
        "cycles_over_sha256_only_control": {name: round(ex[name]["max_cycles"] / ex["rust-sha256-only"]["max_cycles"], 3)
                                            for name in ENTRIES},
        "gas_used": gas,
        "breakdown": {"sha256": hashing, "sha256_per_compression": round(hashing / COMPRESSIONS, 1),
                      "precompile_calls": calls, "precompile_calls_per_call": round(calls / CALLS, 1),
                      "evm_start_up": start, "bytecode_outside_calls": outside,
                      "bytecode_outside_calls_per_call": {k: round(v / CALLS, 1) for k, v in outside.items()},
                      "riscv_outside_sha256": riscv_other,
                      "extra_over_reference": {k: ex[k]["max_cycles"] - reference for k in outside}},
        "evm_instructions_transfer": instructions,
        "estimates_faster_sha256": [estimate(c) for c in (0, 200, 800)],
        "proving": batches,
        "proving_time_ratio_range_over_riscv": ratios,
        "proving_conditions": "transfer case; per program and round one warmup and two timed proofs, interleaved; "
                              f"Apple M5 Max, {setup['power'][0] if setup['power'] else 'power unknown'}; no zero knowledge",
        "validation": {
            "public_cases": {"cases": 59, "valid": 20, "invalid": 39,
                             "rejected_on_leanvm": {k: len(ex[k]["failures"]) == 0 for k in ("riscv", *ENTRIES)}},
            "hidden_seeds": {"scored": {k: v["hidden_seeds"] for k, v in scores.items()},
                             "checked": sorted({h["seed"] for h in hidden}),
                             "all_passed": all(not h["failures"] for h in hidden) and all(
                                 not g["failures"] for s in scores.values() for g in s["gate"])},
            "rule_removal_caught": {k: f"{sum(m['caught'] for m in v)} of {len(v)}" for k, v in removal.items()},
            "constant_padded_trace": all(s["accepted"] for s in scores.values()),
        },
        "artifacts_sha256": {
            **{path: sha256(ROOT / path) for path in ("fixtures/public.json", "oracle/spend_sha256.py",
                                                       "statement/src/lib.rs", "engine/src/lib.rs",
                                                       "evm/src/SpendSha256.sol", "evm/baseline.hex",
                                                       "evm/yul/generate.py", "evm/yul/bytecode.hex",
                                                       "evm/bytecode/generate.py", "evm/bytecode/bytecode.hex",
                                                       "evm/controls/calls-55.hex", "evm/controls/calls-0.hex")},
            "timed_elfs": setup["elf_sha256"],
        },
    }
    (ROOT / "results/summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps({k: summary[k] for k in ("cycles_over_reference", "cycles_over_sha256_only_control",
                                               "breakdown", "proving_time_ratio_range_over_riscv")}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
