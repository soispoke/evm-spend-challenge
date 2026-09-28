#!/usr/bin/env python3
"""Show where a guest spends its leanVM cycles, by function.

Runs host/examples/cycle_profile on one case and attributes each executed
instruction to the function symbol that contains it (from `nm`). With
--hot N it also lists the N most executed instruction addresses.

Usage: python3 scripts/profile.py ELF [--case transfer] [--fixtures fixtures/public.json] [--top 25] [--hot 0]
"""
import argparse
import bisect
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILER = ROOT / "target/release/examples/cycle_profile"


def symbols(elf: Path):
    rows = []
    for line in subprocess.run(["nm", "-n", "--print-size", str(elf)], capture_output=True, text=True).stdout.splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[2] in "tTwW" and not parts[3].startswith(".L"):
            rows.append((int(parts[0], 16), int(parts[1], 16), parts[3]))
    return rows


def short(name: str) -> str:
    """Readable form of a v0-mangled Rust name: its last two path components."""
    parts = re.findall(r"\d+_?([A-Za-z_][A-Za-z0-9_]*)", name.split(".llvm.")[0])
    return "::".join(parts[-2:]) if parts else name


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("elf", type=Path)
    parser.add_argument("--case", default="transfer")
    parser.add_argument("--fixtures", default=str(ROOT / "fixtures/public.json"))
    parser.add_argument("--top", type=int, default=25)
    parser.add_argument("--hot", type=int, default=0)
    parser.add_argument("--function", default="", help="with --hot, only instructions of symbols containing this")
    args = parser.parse_args()
    run = subprocess.run([str(PROFILER), str(args.elf), args.fixtures, args.case], capture_output=True, text=True, check=True)
    data = json.loads(run.stdout)
    table = symbols(args.elf)
    starts = [start for start, _, _ in table]
    by_function = {}
    for pc_hex, count in data["counts"].items():
        pc = int(pc_hex, 16)
        i = bisect.bisect_right(starts, pc) - 1
        name = short(table[i][2]) if i >= 0 and pc < table[i][0] + max(table[i][1], 4) else f"?{pc_hex}"
        by_function[name] = by_function.get(name, 0) + count
    total = data["total"]
    print(f"total {total:,} cycles")
    for name, count in sorted(by_function.items(), key=lambda kv: -kv[1])[:args.top]:
        print(f"{count:>10,}  {100 * count / total:5.1f}%  {name}")
    if args.hot:
        # The hottest instructions of one function, in address order, disassembled.
        from rvdis import decode, text_words
        words = text_words(args.elf)
        focus = args.function
        rows = []
        for pc_hex, count in data["counts"].items():
            pc = int(pc_hex, 16)
            i = bisect.bisect_right(starts, pc) - 1
            if focus and (i < 0 or focus not in table[i][2]):
                continue
            rows.append((pc, count))
        keep = sorted(sorted(rows, key=lambda r: -r[1])[:args.hot])
        print(f"hottest {len(keep)} instructions{' in ' + focus if focus else ''}:")
        for pc, count in keep:
            print(f"  {pc:x}  {count:>8,}  {decode(words.get(pc, 0), pc)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
