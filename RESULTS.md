# EVM Spend Challenge: Results

## TL;DR

On the fixed leanVM machine, the RISC-V reference checks a spend in 460,471 cycles. The Solidity baseline takes 1,225,610 cycles (2.66 times), the optimized Yul entry 625,721 (1.36 times) and a hand-written bytecode entry 615,971 (1.34 times). Every EVM version spends 447,399 cycles on SHA-256, the same as the reference; the rest is the REVM interpreter running the entry, and entries cannot remove it. Run by an interpreter written for proving, the hand-written entry takes 504,922 cycles (1.10 times); compiled ahead of time into Rust, it takes 461,359, within 0.2% of the reference, although its trace then pads to a larger size. With a faster SHA-256 the interpreter decides the ratio: 5.56 times under REVM, 2.30 with the new interpreter and 1.03 compiled, at 200 cycles per compression. Gas ranks the entries in the same order as cycles but overstates their differences, because the SHA-256 precompile costs far more to prove per unit of gas than other instructions. All numbers are in [results/summary.json](results/summary.json) and [results/interpreters-summary.json](results/interpreters-summary.json), produced from the raw runs in [results/2026-09-28](results/2026-09-28) and [results/2026-09-28-interpreters](results/2026-09-28-interpreters).

## Programs

| Program | Cycles | vs reference | Padded trace | Gas | EVM instructions | Bytecode |
|---|---:|---:|---:|---:|---:|---:|
| RISC-V reference (Rust) | 460,354 to 460,471 | 1.00 | 622,872 | | | |
| Solidity baseline | 1,225,610 | 2.66 | 1,836,808 | 41,075 | 8,684 | 2,593 B |
| Optimized Yul entry | 625,697 to 625,721 | 1.36 | 983,496 | 14,658 | 1,348 | 1,789 B |
| Hand-written bytecode entry | 615,949 to 615,971 | 1.34 | 983,496 | 14,559 | 1,242 | 1,935 B |
| Control: EVM making only the 55 calls | 561,959 | 1.22 | 917,712 | 12,270 | 616 | 899 B |
| Control: EVM making no calls | 6,435 | | 8,352 | 85 | 11 | 19 B |
| Control: Rust making only the 55 SHA-256 calls | 454,412 | 0.99 | 622,744 | | | |
| Control: Rust that only starts and returns | 7,013 | | 8,480 | | | |

Cycles span the valid public cases for the reference (20), all 56 public inputs of the correct length for the controls, which check no rules, and 68 public and hidden valid cases for each entry. Gas is the same on every valid case. EVM instructions are counted on the transfer case with [host/examples/opcode_profile.rs](host/examples/opcode_profile.rs). The controls are not valid spends; they separate parts of the cost. The two EVM controls come from [evm/controls/generate.py](evm/controls/generate.py), and the Rust controls from [statement/src/lib.rs](statement/src/lib.rs).

The RISC-V reference is close to the best any RISC-V version can do here. Both versions must use the same SHA-256 code, and the reference spends only 6,059 cycles (1.3%) more than the control that makes the 55 SHA-256 calls and nothing else. Against that control, a practical lower bound rather than a valid program, the hand-written entry is 1.36 times, the Yul entry 1.38 times and the Solidity baseline 2.70 times.

## Where the EVM cycles go

| Part | Solidity baseline | Optimized Yul | Hand-written bytecode |
|---|---:|---:|---:|
| SHA-256, 105 compressions | 447,399 | 447,399 | 447,399 |
| The 55 precompile calls themselves | 108,125 | 108,125 | 108,125 |
| EVM bytecode outside the calls | 663,651 | 63,762 | 54,012 |
| Start-up | 6,435 | 6,435 | 6,435 |
| Total | 1,225,610 | 625,721 | 615,971 |
| Extra cycles over the reference | 765,139 | 165,250 | 155,500 |

SHA-256 is the Rust SHA-256 control minus the Rust start-up control, about 4,261 cycles per compression. The precompile calls are the EVM calls control minus SHA-256 and the EVM start-up control, about 1,966 cycles per call. The bytecode outside the calls is each entry minus the EVM calls control: about 12,066 cycles per call for Solidity, 1,159 for Yul and 982 for the hand-written entry. An entry controls only this last part, because the hashed messages are fixed by the rules and the cost of each call mostly by the interpreter.

## EVM instructions by kind

| Kind | Solidity baseline | Optimized Yul | Hand-written bytecode | Only the 55 calls |
|---|---:|---:|---:|---:|
| Stack: PUSH, DUP, SWAP, POP | 5,002 | 827 | 813 | 448 |
| Arithmetic and comparisons | 1,911 | 313 | 211 | 0 |
| Jumps: JUMP, JUMPI, JUMPDEST | 929 | 1 | 15 | 0 |
| Memory: MLOAD, MSTORE, MSTORE8, MCOPY | 612 | 27 | 23 | 55 |
| Calldata reads and copies | 118 | 69 | 69 | 2 |
| Calls: GAS, STATICCALL | 110 | 110 | 110 | 110 |
| Other | 2 | 1 | 1 | 1 |
| Total | 8,684 | 1,348 | 1,242 | 616 |

Most of the Solidity baseline's extra instructions come from code the compiler generates around `abi.encodePacked` and `sha256`: moving values on the stack, computing and bounds-checking calldata offsets, and jumps for loops, function calls and a success check after every call. They average about 82 RISC-V cycles each. The [Yul entry](evm/yul/generate.py) is fully unrolled, reuses one 65-byte message buffer, copies each field from calldata into place, has each precompile call write its result where the next hash reads it, and checks all rules with one revert at the end. The [hand-written entry](evm/bytecode/generate.py) keeps its working values on the stack, writes each tag byte and shared field once, and jumps to a single revert when a check fails; its 15 conditional jumps are not taken on a valid input. Neither checks each call's result: under the fixed 30 million gas limit, a SHA-256 call cannot run out of gas, which is its only way to fail. Peak EVM memory is 7,424 bytes for the baseline, 544 for the Yul entry and 800 for the hand-written entry.

## Gas

Gas ranks the three entries in the same order as cycles but overstates the differences between them. The Solidity baseline uses 2.82 times the gas of the hand-written entry and 1.99 times its cycles.

The difference comes from hashing. The 55 calls cost 10,756 gas: 5,500 for the `STATICCALL` instructions (100 each) and 5,256 for the precompile itself (60 plus 12 per 32-byte word). That is 74% of the hand-written entry's gas. The precompile's 5,256 gas pays for 447,399 cycles of SHA-256, about 85 cycles per unit of gas, while the rest of the hand-written entry costs about 18 cycles per unit of gas under REVM (168,572 cycles for 9,303 gas). In proving terms, gas prices the hashing about five times below the other work. The gap widens with a faster interpreter, to about 14 times with the new interpreter and 57 times compiled (below), and a zkVM accelerator for SHA-256 would narrow it. Gas is a reasonable guide to which of two entries doing the same hashing is cheaper to prove, not to how much cheaper, and it cannot compare an EVM program with a RISC-V one, which has no gas.

## Proof time

| Program | Median proof time | Peak memory | Proof size | Verification |
|---|---:|---:|---:|---:|
| RISC-V reference | 0.60 s | 3.5 GiB | 330 KiB | 7.7 ms |
| Solidity baseline | 1.67 s | 10.2 GiB | 331 KiB | 10.0 ms |
| Optimized Yul entry | 1.01 s | 5.5 GiB | 323 KiB | 9.5 ms |
| Control: EVM making only the 55 calls | 0.92 s | 5.1 GiB | 319 KiB | 9.1 ms |
| Control: Rust making only the 55 SHA-256 calls | 0.62 s | 3.5 GiB | 328 KiB | 8.7 ms |
| Control: Rust that only starts and returns | 0.04 s | 0.24 GiB | 257 KiB | 6.2 ms |

leanVM proved the transfer case six times per program in one [interleaved run](results/2026-09-28/timing.jsonl) ([scripts/time_proofs.py](scripts/time_proofs.py)), on an Apple M5 Max on AC power, without zero knowledge. Times vary between runs: two [other runs](results/2026-09-28/earlier-timing) of the same programs measured the reference at 0.52 and 0.61 seconds. Over the three runs, the Solidity baseline took 2.66 to 3.05 times the reference's proof time and the Yul entry 1.47 to 1.77 times. Within one run, the reference and the SHA-256-only control, whose traces are nearly the same size, differed by up to 15%, so small time differences are not meaningful. Time ratios are larger than cycle ratios because proving time follows the padded trace size, which grows in steps. The hand-written entry was timed in the interpreter run below, at 1.61 times the reference. Timings for a decision should use zero knowledge and more repetitions.

## With faster SHA-256

The rows below are computed from the measured parts, not run.

| SHA-256 cycles per compression | RISC-V reference | Solidity baseline | Optimized Yul | Hand-written bytecode |
|---|---:|---:|---:|---:|
| 4,261 (software, measured) | 460,471 | 1,225,610 (2.66) | 625,721 (1.36) | 615,971 (1.34) |
| 800 | 97,072 | 862,211 (8.88) | 262,322 (2.70) | 252,572 (2.60) |
| 200 | 34,072 | 799,211 (23.46) | 199,322 (5.85) | 189,572 (5.56) |
| 0 | 13,072 | 778,211 (59.53) | 178,322 (13.64) | 168,572 (12.90) |

A zkVM accelerator for SHA-256 lowers every total by the same amount. The extra cycles over the reference therefore stay the same at any hash cost, 155,500 for the hand-written entry, while the ratio grows.

## Faster interpreters

The score fixes the interpreter so that entries compete on their bytecode. Under REVM, the hand-written entry's 155,500 extra cycles are all spent by the interpreter: on the precompile calls, the other instructions and start-up. To measure how much of that a better interpreter removes, the same programs ran in three more ways, each following the scoring rules exactly: Cancun gas, the 1 MiB memory limit, and only `STATICCALL` to the SHA-256 precompile.

1. **REVM with a direct SHA-256 call** ([interpreters/src/revm_direct.rs](interpreters/src/revm_direct.rs)). One REVM instruction is replaced: a `STATICCALL` to `0x02` hashes EVM memory in place and writes the digest back, instead of leaving the interpreter loop through a new call frame and copying the input out.
2. **An interpreter written for proving** ([interpreters/src/fast.rs](interpreters/src/fast.rs)). It runs one dispatch loop over a zero-padded copy of the code, keeps the stack in a fixed buffer, analyzes jump destinations only when a jump is taken, and hashes straight from EVM memory into EVM memory. It subtracts each instruction's fixed gas cost without a check and checks the balance wherever gas can be observed: at jumps, `GAS`, calls, memory growth, return, revert and stop. A program that runs out of gas in between still halts before anything leaves the interpreter, so results and gas are unchanged.
3. **Compiled ahead of time** ([interpreters/compile.py](interpreters/compile.py)). Each program becomes one Rust function, with stack values in local variables and stack bounds checked once per basic block. This removes interpretation entirely, so it shows about the best any interpreter could reach. A verifier would have to trust the compiler, or a proof that the compiled program matches the bytecode, so it is a limit rather than a design.

### Cycles

| Program | REVM (scored) | REVM, direct SHA-256 call | Interpreter written for proving | Compiled ahead of time |
|---|---:|---:|---:|---:|
| Solidity baseline | 1,225,610 (2.66) | 1,202,567 (2.61) | 895,279 (1.94) | 605,936 (1.32) |
| Optimized Yul | 625,721 (1.36) | 610,912 (1.33) | 520,530 (1.13) | 483,044 (1.05) |
| Hand-written bytecode | 615,971 (1.34) | 597,324 (1.30) | 504,922 (1.10) | 461,359 (1.00) |
| Control: only the 55 calls | 561,959 (1.22) | 547,263 (1.19) | 475,219 (1.03) | 450,599 (0.98) |
| Control: no calls | 6,435 | 6,480 | 1,725 | 1,069 |

Ratios are over the reference's 460,471 cycles. The direct call lowers each precompile call from about 1,966 cycles to 1,698. The new interpreter lowers it to about 474, including the eleven instructions that write the tag and set up the call, and runs the hand-written entry's other instructions in 29,703 cycles instead of 54,012. What remains per EVM instruction is mostly the dispatch, eight RISC-V instructions, and moving 256-bit stack words as four 64-bit limbs. Compiled code removes the dispatch and lets the Rust compiler optimize across instructions, for example using the constant offsets and lengths the entry pushes, so the hand-written entry's extra cycles over the reference fall from 155,500 to 888. The compiled calls control runs below the Rust SHA-256 control (450,599 cycles against 454,412) because it hashes messages in place in EVM memory while the Rust control builds each message first, so for compiled code the split between the calls and the rest is not meaningful.

### Proof time and trace size

| Program | How the EVM code runs | Padded trace | Median proof time | vs reference |
|---|---|---:|---:|---:|
| RISC-V reference | | 622,872 | 0.59 s | 1.00 |
| Hand-written bytecode | REVM | 983,496 | 0.95 s | 1.61 |
| Hand-written bytecode | REVM, direct call | 983,496 | 0.93 s | 1.58 |
| Hand-written bytecode | Interpreter for proving | 884,888 | 0.88 s | 1.49 |
| Hand-written bytecode | Compiled | 884,888 | 0.81 s | 1.38 |
| Optimized Yul | REVM | 983,496 | 0.92 s | 1.56 |
| Optimized Yul | Interpreter for proving | 884,896 | 0.85 s | 1.45 |
| Optimized Yul | Compiled | 884,896 | 0.86 s | 1.46 |
| Solidity baseline | REVM | 1,836,808 | 1.69 s | 2.86 |
| Solidity baseline | Interpreter for proving | 1,049,160 | 1.00 s | 1.70 |
| Solidity baseline | Compiled | 918,344 | 0.91 s | 1.55 |
| Control: only the 55 calls | REVM | 917,712 | 0.89 s | 1.51 |
| Control: only the 55 calls | Interpreter for proving | 884,888 | 0.85 s | 1.44 |
| Control: only the 55 calls | Compiled | 622,744 | 0.62 s | 1.04 |

Proof time follows the padded trace. The compiled hand-written entry runs as many cycles as the reference, yet its trace is 42% larger. leanVM pads each instruction table to a power of two, and padding the other tables adds jump rows to the ALU table. The reference's ALU table ends 1,376 rows under 2^18; the compiled entry's has 170 more rows and crosses it, so that table pads to 2^19. At a slightly larger statement both would pad to the same size, so this gap is a threshold, not a cost of the EVM. These proofs come from one [interleaved run](results/2026-09-28-interpreters/timing.jsonl) on AC power, with a load average of 3.1 at the start. Programs of the same padded size took 0.81 to 0.88 seconds, so differences under about 10% are noise.

### With faster SHA-256

| SHA-256 cycles per compression | RISC-V reference | Hand-written bytecode, REVM | REVM, direct call | Interpreter for proving | Compiled |
|---|---:|---:|---:|---:|---:|
| 4,261 (software, measured) | 460,471 | 615,971 (1.34) | 597,324 (1.30) | 504,922 (1.10) | 461,359 (1.00) |
| 200 | 34,072 | 189,572 (5.56) | 170,925 (5.02) | 78,523 (2.30) | 34,960 (1.03) |
| 0 | 13,072 | 168,572 (12.90) | 149,925 (11.47) | 57,523 (4.40) | 13,960 (1.07) |

Faster hashing removes the part both versions share, so what is left is mostly the interpreter. At 200 cycles per compression, the new interpreter keeps the hand-written entry at 2.30 times the reference instead of 5.56, and compiled code keeps it at 1.03.

### How the interpreter was optimized

Each round profiled the guest on leanVM, counting cycles per function and per instruction with [scripts/profile.py](scripts/profile.py), changed one thing, checked the result against REVM on the test cases and on 200,000 random programs, and measured every program with [scripts/interpreters.py](scripts/interpreters.py). The [ledger](results/2026-09-28-interpreters/ledger.jsonl) records each round.

| Round | Change | Hand-written bytecode | Only the 55 calls | Solidity baseline |
|---:|---|---:|---:|---:|
| 0 | First version: one dispatch loop, a generic PUSH, gas passed by reference | 531,207 | 487,518 | 989,920 |
| 1 | Gas kept in a register; PUSH1 and PUSH2 read their bytes directly | 509,518 | 477,495 | 919,255 |
| 2 | Fixed gas costs subtracted without a check; the dispatch table covers all 256 opcodes | 505,239 | 475,548 | 895,618 |
| 3 | Shared helpers moved to one module, also used by the compiled programs | 504,922 | 475,219 | 895,279 |

Two further ideas were estimated and not built. Fusing common instruction pairs would save little, because the most common pair, two PUSH1 in a row, accounts for 156 of the entry's 1,246 instructions. Dispatching through tail calls would save about three RISC-V instructions per EVM instruction, roughly 1% here. The compiled version shows about how far more interpreter work could go: 43,563 cycles separate the new interpreter from it on the hand-written entry.

### Checks

The REVM copy used to report gas ([interpreters/src/reference.rs](interpreters/src/reference.rs)) returns the same result as the scoring harness on every test case. On the 59 public cases and 237 hidden ones from seeds 1, 2 and 3, REVM with the direct call and the new interpreter return the same result as that reference for all five programs, with the same gas left after every return or revert ([parity.json](results/2026-09-28-interpreters/parity.json)). Each program uses the same gas on all of its valid cases.

On 2,999,949 random programs with random calldata and gas limits ([fuzz-101.json](results/2026-09-28-interpreters/fuzz-101.json) and the other two seeds), REVM with the direct call matches the reference exactly, including the reason for each halt, and the new interpreter matches its result and gas left, counting every exceptional halt as the same result. Half the programs are generated from instruction templates that reach memory growth, copies, the SHA-256 call, return data, jumps, running out of gas and every opcode byte; the other half mutate the entries and controls and run them on test inputs. The 51 programs starting with `0xEF01` were skipped, because the harness treats them as EIP-7702 delegations, which it cannot run.

The compiled programs match the reference on the same 296 cases at five gas limits, 1,480 runs each, some of which run out of gas ([compiled-parity.json](results/2026-09-28-interpreters/compiled-parity.json)). On leanVM, every entry, run each of the four ways, accepts all 100 valid cases from the public set and seeds 1 and 2, rejects all 108 invalid ones, and keeps one padded trace size.

### Limits

Cycle counts are exact for a given build, but a code change elsewhere in a guest can move data and shift a count by a few hundred cycles, all in `memcpy`, whose cost depends on alignment. After the BLAKE2s edition was added, REVM with the direct call measures 597,668 cycles on the hand-written entry instead of 597,324, with no other change; no ratio above moves.

This is research code, checked against REVM by testing, not audited or formally verified. The new interpreter and the compiled programs implement only what the scoring rules allow: no storage, logs, environment reads or calls other than to `0x02`. In production an interpreter is part of what verifiers trust, because a proof shows that one specific interpreter build produced the output. Replacing it is a verifier upgrade, and any difference from the EVM rules could make a program accept an input it should reject. Compiled code moves that trust to the compiler, or requires a proof that the compiled program matches the bytecode. Everything was measured on one leanVM commit without zero knowledge.

## Other hashes

The estimates above model faster hashing as fewer cycles per SHA-256 compression. To see what another hash gives on this machine, [guests/hash-choice](guests/hash-choice/src/lib.rs) makes the statement's 55 chained calls, 105 blocks of 64 bytes, with four hashes ([scripts/hash_choice.py](scripts/hash_choice.py)). Every output matches Python's `hashlib`, or for BLAKE3 a reference checked against the published test vectors. The BLAKE implementations are straightforward Rust; tuned ones could be somewhat faster.

| Hash for the 55 calls | Cycles | Padded trace | Committed words | Median proof time |
|---|---:|---:|---:|---:|
| SHA-256, software | 448,239 | 622,744 | 26,861,208 | 0.38 s |
| BLAKE2s, software | 337,159 | 491,552 | 21,727,184 | 0.38 s |
| BLAKE3, software | 238,304 | 278,560 | 12,945,360 | 0.19 s |
| BLAKE2s, leanVM's `blake2s` instruction | 39,748 | 51,472 | 3,460,592 | 0.06 s |

The counts include about 7,000 cycles of start-up. RV64IM has no rotate instruction, so in software a block takes about 2,200 cycles with BLAKE3 and 3,100 with BLAKE2s, against 4,200 with SHA-256. leanVM's instruction computes a whole BLAKE2s compression in one step; with the copying around it, a block costs about 310 cycles, and the proof is about six times faster than with software SHA-256. Its rows are wider than those of ordinary instructions, 67 committed words per padded cycle against 43, so cycle counts understate its proving cost and committed words compare the four fairly. Proof times on this laptop varied by up to about 40% between back-to-back runs of the same program, so only the large differences in the last column are meaningful ([timing](results/2026-09-28-hash-choice/timing.jsonl)).

The BLAKE2s edition below measures the whole statement with BLAKE2s. For BLAKE3, which leanVM does not accelerate, replacing the SHA-256 cycles with BLAKE3's software cycles puts the hand-written entry at about 1.62 times the RISC-V cycles under REVM, 1.18 with the new interpreter and 1.00 compiled, if the EVM had a BLAKE3 precompile; those numbers are computed, not run.

## The BLAKE2s edition

The BLAKE2s edition is the same spend with BLAKE2s-256 as every hash and nothing else changed: the oracle's `--hash blake2s` mode, the Rust statement's `verify_with::<Blake2sHash>`, and [59 public cases](fixtures/public-blake2s.json) with the same names and rules. It separates what an application's RISC-V program may use from what the EVM's precompile may use:

- **RISC-V:** the program computes BLAKE2s in software with the base RV64IM instructions only, or uses leanVM's `blake2s` instruction.
- **EVM with a precompile:** the [hand-written entry](evm/blake2s/generate.py), unchanged except that it calls a BLAKE2s precompile at `0xb2`. Ethereum has no such precompile; here it is priced like SHA-256's, and the interpreter serves it in software or with leanVM's instruction.
- **EVM without a precompile:** a Yul entry that computes BLAKE2s in EVM code, one 32-bit word per 32-byte memory slot, with every addition and rotation masked to 32 bits and every word byte-swapped, because BLAKE2s is little-endian and EVM memory is big-endian.

| Program | Cycles | Padded trace | Committed words | Median proof time |
|---|---:|---:|---:|---:|
| RISC-V, base instructions only | 344,072 | 491,608 | 22.0 M | 0.379 s |
| RISC-V with the `blake2s` instruction | 52,676 | 92,560 | 5.2 M | 0.085 s |
| EVM, precompile in software, REVM | 494,144 | 852,296 | 37.7 M | 0.773 s |
| EVM, precompile in software, interpreter for proving | 394,661 | 491,552 | 22.0 M | 0.487 s |
| EVM, precompile in software, compiled | 349,442 | 491,552 | 22.0 M | 0.465 s |
| EVM, precompile with the instruction, REVM | 202,548 | 246,336 | 12.1 M | 0.245 s |
| EVM, precompile with the instruction, interpreter for proving | 103,065 | 172,304 | 8.7 M | 0.197 s |
| EVM, precompile with the instruction, compiled | 57,846 | 98,576 | 5.5 M | 0.108 s |
| EVM, BLAKE2s in EVM code, REVM | 76,776,443 | 117,443,608 | 5,100 M | too large to prove |
| EVM, BLAKE2s in EVM code, interpreter for proving | 56,136,848 | 75,500,560 | 3,221 M | too large to prove |
| EVM, BLAKE2s in EVM code, compiled | 5,844,806 | 8,456,208 | 369 M | too large to prove |

Cycles are the largest count over 60 valid cases, the public ones and hidden seeds 1 and 2; every program accepts all of them and rejects all 108 invalid ones ([summary](results/2026-09-29-blake2s/summary.json)). Committed words, the data the prover commits to, follow the padded trace and compare programs using the hash instruction more fairly than cycles do. Proof times are medians of four proofs of the transfer case from one interleaved run on AC power ([timing](results/2026-09-29-blake2s/timing.jsonl)). The base-instruction RISC-V program and the two EVM programs with nearly the same padded trace took 0.38 to 0.49 seconds, and the RISC-V program's own four proofs ranged from 0.27 to 0.51 seconds, so differences of that size are noise. The runs with BLAKE2s in EVM code need a witness of 2^29 to 2^33 words, beyond the pinned leanVM's limit of 2^28, so they have cycle counts but no proofs. REVM here is the copy in [reference.rs](interpreters/src/reference.rs) that can serve `0xb2`; on the SHA-256 entry it costs 0.14% more than the scoring harness.

Grouped by what each side may use, the cycles compare as follows:

| RISC-V program may use | EVM precompile uses | RISC-V | EVM, REVM | EVM, interpreter for proving | EVM, compiled |
|---|---|---:|---:|---:|---:|
| Base instructions | Software | 344,072 | 1.44× | 1.15× | 1.02× |
| Base instructions | leanVM's instruction | 344,072 | 0.59× | 0.30× | 0.17× |
| leanVM's instruction | leanVM's instruction | 52,676 | 3.85× | 1.96× | 1.10× |
| leanVM's instruction | No precompile | 52,676 | 1,458× | 1,066× | 111× |

With a precompile, BLAKE2s behaves like SHA-256: the new interpreter stays within 1.15 times of RISC-V and compiled code matches it. With leanVM's instruction on both sides, hashing becomes cheap and the interpreter's own cost shows: 3.85 times under REVM, 1.96 with the new interpreter and 1.10 compiled, close to the estimates made from the SHA-256 measurements (3.99, 1.86 and 1.02).

Which instructions RISC-V programs may use matters as much as the interpreter. If applications get only the base instruction set while the protocol's BLAKE2s precompile uses leanVM's instruction, the EVM entry takes 3.3 times fewer cycles than the RISC-V program with the new interpreter, and 1.7 times fewer even under REVM. Exposing RISC-V with the instruction gives RISC-V programs the same hashing, and then they take half the cycles of the best interpreter.

Without a precompile, BLAKE2s in EVM code costs 17 times the base-instruction RISC-V program compiled and 223 times under REVM, and 2,752,716 gas against 14,559 with the precompile. Emulating 32-bit additions and rotations with 256-bit instructions, and converting every word between byte orders through EVM memory, dominates, so the new interpreter saves only 27%. A tuned EVM implementation could be a few times faster, but not close to the precompile.

The EVM has no precompile for BLAKE2s. Its BLAKE2 precompile at `0x09` computes the BLAKE2b compression, which leanVM does not accelerate, and EIP-8200 proposes replacing it with EVM bytecode. The EVM route gets leanVM's hashing speed only through a new BLAKE2s precompile in the EVM used for proofs.

## Validation

The Python oracle, the Rust reference and the three EVM entries agree on all 59 public test cases: the expected digest for the 20 valid inputs and no result for the 39 invalid ones. The Rust reference and the Solidity baseline also name the broken rule, and it matches the oracle. All of them also agree on hidden cases from seeds 1, 2 and 3, and the scored runs used seeds 101 and 202 for the baseline, 303 and 404 for the Yul entry, and 505 and 606 for the hand-written entry. Removing any one rule check makes at least one public case fail, for the [baseline](results/2026-09-28/rule-removal-solidity.json), the [Yul entry](results/2026-09-28/rule-removal-yul.json) and the [hand-written entry](results/2026-09-28/rule-removal-bytecode.json) alike, 11 of 11 each. On leanVM, the reference and all three entries accept every valid public case and reject all 36 invalid cases of the correct length, and every program keeps one padded trace size across its valid inputs.

## Reproduce

```sh
./scripts/build.sh
python3 scripts/measure.py results/NEW
python3 scripts/time_proofs.py results/NEW/timing.jsonl
python3 scripts/report.py results/NEW
python3 scripts/interpreters.py --run results/NEW-interpreters --fuzz 1000000 --fuzz-seeds 101 202 303
python3 scripts/time_proofs.py results/NEW-interpreters/timing.jsonl --set interpreters
python3 scripts/report_interpreters.py results/NEW-interpreters
python3 scripts/hash_choice.py results/NEW-hash-choice
python3 scripts/blake2s_edition.py results/NEW-blake2s
```
