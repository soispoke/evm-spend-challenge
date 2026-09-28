# EVM Spend Challenge: Results

## TL;DR

On the fixed leanVM machine, the RISC-V reference checks a spend in 460,471 cycles, the Solidity baseline in 1,225,610 (2.66 times) and an optimized Yul entry in 625,721 (1.36 times). Both EVM versions spend 447,399 cycles on SHA-256, the same as the reference, and about 108,000 on the 55 precompile calls themselves. What separates them is the bytecode outside the calls: 663,651 cycles for Solidity and 63,762 for Yul. Faster hashing would lower every total by the same amount, so it would not change the extra cycles over RISC-V but would raise the ratio. All numbers are in [results/summary.json](results/summary.json), produced by [scripts/report.py](scripts/report.py) from the raw runs in [results/2026-09-28](results/2026-09-28).

## Programs

| Program | Cycles | vs reference | Padded trace | EVM instructions | Bytecode |
|---|---:|---:|---:|---:|---:|
| RISC-V reference (Rust) | 460,354 to 460,471 | 1.00 | 622,872 | | |
| Solidity baseline | 1,225,610 | 2.66 | 1,836,808 | 8,684 | 2,593 B |
| Optimized Yul entry | 625,697 to 625,721 | 1.36 | 983,496 | 1,348 | 1,789 B |
| Control: EVM making only the 55 calls | 561,959 | 1.22 | 917,712 | 616 | 899 B |
| Control: EVM making no calls | 6,435 | | 8,352 | 11 | 19 B |
| Control: Rust making only the 55 SHA-256 calls | 454,412 | 0.99 | 622,744 | | |
| Control: Rust that only starts and returns | 7,013 | | 8,480 | | |

Cycles span the valid public cases for the reference (20), all 56 public inputs of the correct length for the controls, which check no rules, and 68 public and hidden valid cases for the two entries. EVM instructions are counted on the transfer case with [host/examples/opcode_profile.rs](host/examples/opcode_profile.rs). The controls are not valid spends; they separate parts of the cost. The two EVM controls come from [evm/controls/generate.py](evm/controls/generate.py), and the Rust controls from [statement/src/lib.rs](statement/src/lib.rs).

The RISC-V reference is within about 1% of the best any RISC-V version can do here. Both versions must use the same SHA-256 code, and the reference spends only 6,059 cycles more than the control that makes the 55 SHA-256 calls and nothing else. Against that control, a lower bound rather than a valid program, the Yul entry is 1.38 times and the Solidity baseline 2.70 times.

## Where the EVM cycles go

| Part | Solidity baseline | Optimized Yul |
|---|---:|---:|
| SHA-256, 105 compressions | 447,399 | 447,399 |
| The 55 precompile calls themselves | 108,125 | 108,125 |
| EVM bytecode outside the calls | 663,651 | 63,762 |
| Start-up | 6,435 | 6,435 |
| Total | 1,225,610 | 625,721 |
| Extra cycles over the reference | 765,139 | 165,250 |

SHA-256 is the Rust SHA-256 control minus the Rust start-up control, about 4,261 cycles per compression. The precompile calls are the EVM calls control minus SHA-256 and the EVM start-up control, about 1,966 cycles per call. The bytecode outside the calls is each entry minus the EVM calls control: about 12,066 cycles per call for Solidity and 1,159 for Yul. An entry controls only this last part, because the hashed messages are fixed by the rules and the cost of each call mostly by the interpreter.

## EVM instructions by kind

| Kind | Solidity baseline | Optimized Yul | Only the 55 calls |
|---|---:|---:|---:|
| Stack: PUSH, DUP, SWAP, POP | 5,002 | 827 | 448 |
| Arithmetic and comparisons | 1,911 | 313 | 0 |
| Jumps: JUMP, JUMPI, JUMPDEST | 929 | 1 | 0 |
| Memory: MLOAD, MSTORE, MSTORE8, MCOPY | 612 | 27 | 55 |
| Calldata reads and copies | 118 | 69 | 2 |
| Calls: GAS, STATICCALL | 110 | 110 | 110 |
| Other | 2 | 1 | 1 |
| Total | 8,684 | 1,348 | 616 |

Most of the Solidity baseline's extra instructions come from code the compiler generates around `abi.encodePacked` and `sha256`: moving values on the stack, computing and bounds-checking calldata offsets, and jumps for loops, function calls and a success check after every call. They average about 82 RISC-V cycles each. The [Yul entry](evm/yul/generate.py) is fully unrolled, reuses one 65-byte message buffer, copies each field from calldata into place, has each precompile call write its result where the next hash reads it, and checks all rules with one revert at the end. It does not check each call's result: under the fixed 30 million gas limit, a SHA-256 call cannot run out of gas, which is its only way to fail. Peak EVM memory is 7,424 bytes for the baseline and 544 for the Yul entry.

## Proof time

| Program | Median proof time | Peak memory | Proof size | Verification |
|---|---:|---:|---:|---:|
| RISC-V reference | 0.60 s | 3.5 GiB | 330 KiB | 7.7 ms |
| Solidity baseline | 1.67 s | 10.2 GiB | 331 KiB | 10.0 ms |
| Optimized Yul entry | 1.01 s | 5.5 GiB | 323 KiB | 9.5 ms |
| Control: EVM making only the 55 calls | 0.92 s | 5.1 GiB | 319 KiB | 9.1 ms |
| Control: Rust making only the 55 SHA-256 calls | 0.62 s | 3.5 GiB | 328 KiB | 8.7 ms |
| Control: Rust that only starts and returns | 0.04 s | 0.24 GiB | 257 KiB | 6.2 ms |

leanVM proved the transfer case six times per program in one [interleaved run](results/2026-09-28/timing.jsonl) ([scripts/time_proofs.py](scripts/time_proofs.py)), on an Apple M5 Max on AC power, without zero knowledge. Times vary between runs: two [other runs](results/2026-09-28/earlier-timing) of the same programs measured the reference at 0.52 and 0.61 seconds. Over the three runs, the Solidity baseline took 2.66 to 3.05 times the reference's proof time and the Yul entry 1.47 to 1.77 times. Within one run, the reference and the SHA-256-only control, whose traces are nearly the same size, differed by up to 15%, so small time differences are not meaningful. Time ratios are larger than cycle ratios because proving time follows the padded trace size, which grows in steps. Timings for a decision should use zero knowledge and more repetitions.

## With faster SHA-256

The rows below are computed from the measured parts, not run.

| SHA-256 cycles per compression | RISC-V reference | Solidity baseline | Optimized Yul |
|---|---:|---:|---:|
| 4,261 (software, measured) | 460,471 | 1,225,610 (2.66) | 625,721 (1.36) |
| 800 | 97,072 | 862,211 (8.88) | 262,322 (2.70) |
| 200 | 34,072 | 799,211 (23.46) | 199,322 (5.85) |
| 0 | 13,072 | 778,211 (59.53) | 178,322 (13.64) |

A zkVM accelerator for SHA-256 lowers every total by the same amount. The extra cycles over the reference therefore stay 765,139 for the baseline and 165,250 for the Yul entry at any hash cost, while the ratio grows.

## Validation

The Python oracle, the Rust reference, the Solidity baseline and the Yul entry agree on all 59 public test cases: the expected digest for the 20 valid inputs and no result for the 39 invalid ones. The Rust reference and the Solidity baseline also name the broken rule, and it matches the oracle. All of them also agree on hidden cases from seeds 1, 2 and 3, and the scored runs used seeds 101 and 202 for the baseline and 303 and 404 for the Yul entry. Removing any one rule check makes at least one public case fail, for the [baseline](results/2026-09-28/rule-removal-solidity.json) and the [Yul entry](results/2026-09-28/rule-removal-yul.json) alike, 11 of 11 each. On leanVM, the reference and both entries accept every valid public case and reject all 36 invalid cases of the correct length, and every program keeps one padded trace size across its valid inputs.

## Reproduce

```sh
./scripts/build.sh
python3 scripts/measure.py results/NEW
python3 scripts/time_proofs.py results/NEW/timing.jsonl
python3 scripts/report.py results/NEW
```
