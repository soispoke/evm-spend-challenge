#!/usr/bin/env python3
"""Check that the public cases catch a missing rule check in an entry.

For each of the eleven rules, build the entry with that one check removed and
run the scorer's correctness check. Every such mutant must fail at least one
public case.

  solidity: removes the baseline's `revert Rule(n)`, recompiled with Foundry
  yul:      regenerates the Yul entry with `evm/yul/generate.py --drop RULE`
  bytecode: regenerates the bytecode entry with `evm/bytecode/generate.py --drop RULE`

Usage: python3 scripts/mutation_check.py solidity|yul|bytecode OUT.json
"""
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCORER = ROOT / "target/release/spend-challenge"
FIXTURES = ROOT / "fixtures/public.json"


def solidity_mutant(code: int, rule: str, work: Path) -> str:
    source = (ROOT / "evm/src/SpendSha256.sol").read_text()
    pattern = re.compile(rf"revert Rule\({code}\);")
    assert len(pattern.findall(source)) == 1, rule
    project = work / "evm"
    shutil.copytree(ROOT / "evm", project, ignore=shutil.ignore_patterns("out", "cache", "yul", "controls"))
    (project / "src/SpendSha256.sol").write_text(pattern.sub("{}", source))
    subprocess.run(["forge", "build", "--threads", "1", "--quiet"], cwd=project, check=True)
    artifact = json.loads((project / "out/SpendSha256.sol/SpendSha256.json").read_text())
    return artifact["deployedBytecode"]["object"].removeprefix("0x")


def generated_mutant(generator: str):
    def build(code: int, rule: str, work: Path) -> str:
        run = subprocess.run([sys.executable, str(ROOT / generator), "--drop", rule],
                             capture_output=True, text=True, check=True)
        return run.stdout.strip()
    return build


def main() -> int:
    entry, out = sys.argv[1], Path(sys.argv[2])
    build = {"solidity": solidity_mutant, "yul": generated_mutant("evm/yul/generate.py"),
             "bytecode": generated_mutant("evm/bytecode/generate.py")}[entry]
    rules = json.loads(FIXTURES.read_text())["rules"]
    results = []
    for code, rule in enumerate(rules):
        with tempfile.TemporaryDirectory() as tmp:
            hex_path = Path(tmp) / "mutant.hex"
            hex_path.write_text(build(code, rule, Path(tmp)))
            run = subprocess.run([str(SCORER), "check", "--fixtures", str(FIXTURES), "--evm", str(hex_path)],
                                 capture_output=True, text=True)
        caught = [f["case"] for f in json.loads(run.stdout)["failures"] if f["route"] == "evm"]
        results.append({"rule": rule, "caught": bool(caught), "failing_cases": caught})
        print(f"{rule:26} {'caught' if caught else 'NOT CAUGHT'} by {len(caught)} case(s)")
    out.write_text(json.dumps({"entry": entry, "mutants": results}, indent=1) + "\n")
    return 0 if all(r["caught"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
