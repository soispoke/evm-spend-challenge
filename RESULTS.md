# EVM Spend Challenge: Results

## TL;DR

The same privacy-pool spend check was proved by leanVM as two programs: a RISC-V program compiled from Rust, and EVM bytecode executed by an EVM interpreter compiled to RISC-V. How much more the EVM program costs depends mostly on how its bytecode is executed and on whether the prover has an instruction for the hash precompile it calls. With leanVM's `blake2s` instruction serving both programs, the EVM program takes 1.96 times the RISC-V cycles under an interpreter written for proving, 3.85 times under REVM and 1.10 times compiled ahead of time. With SHA-256 on base instructions on both sides, hashing is 97% of the RISC-V cycles and runs the same code in both programs, so the EVM program takes 1.00 to 1.34 times the RISC-V cycles (1.10 with the interpreter for proving). An EVM program that can only call the SHA-256 precompile takes 8.8 to 11.7 times the cycles of a RISC-V program using the instruction, and BLAKE2s in EVM opcodes, without a precompile, exceeds the pinned leanVM's single-proof limit of 2^28 committed words. A RISC-V program limited to base instructions takes 1.7 to 5.9 times the cycles of an EVM program whose precompile uses the instruction (3.3 times with the interpreter for proving). Gas does not measure proving cost.

## Setup

The statement is the spend defined in [SPEC.md](SPEC.md): two input notes in a 20-level Merkle tree, two output notes, 55 hash calls and 105 compressions of 64 bytes. It exists in two editions with the same rules and test cases, SHA-256, which the challenge scores, and BLAKE2s. Every program runs on leanVM's `riscv-exploration` branch at [`1096dedf`](https://github.com/leanEthereum/leanVM/tree/1096dedfbe29c72cfff2a2d8d8b420e6ff0d9f2d): RV64IM plus a `blake2s` instruction that computes one BLAKE2s compression, without zero knowledge.

The RISC-V program is the [Rust reference](statement/src/lib.rs) compiled to RV64IM. It hashes on base instructions or, for BLAKE2s, with the `blake2s` instruction. Base instructions are standard RV64IM, the counterpart of EVM opcodes; leanVM's `blake2s` instruction computes one BLAKE2s compression in a single step, the counterpart of an EVM precompile. The EVM program is an entry's bytecode, executed by an EVM interpreter inside the RISC-V program that leanVM proves. Its hash calls are `STATICCALL`s to a precompile: SHA-256 at `0x02`, or a BLAKE2s precompile at `0xb2`, which Ethereum does not have and which is priced here like SHA-256. The interpreter executes the precompile on base instructions, with the same Rust code as the reference, or with the `blake2s` instruction. The bytecode is executed in one of three ways:

1. **REVM:** `revm-interpreter` 43.0.0, the Rust EVM used by Reth, fixed by the challenge's scoring. It is not written for proving.
2. **An interpreter written for proving** ([interpreters/src/fast.rs](interpreters/src/fast.rs)): one dispatch loop over a zero-padded copy of the code, the stack in a fixed buffer, jump destinations analyzed only when a jump is taken, and hashing straight from EVM memory. It subtracts each opcode's fixed gas cost without a check and checks the balance wherever gas can be observed, so results and gas match REVM on the tested cases.
3. **Compiled ahead of time** ([interpreters/compile.py](interpreters/compile.py)): each program translated into one Rust function, with stack values in local variables. This removes interpreter dispatch but is not a proven lower bound. Each compiled program is a different RISC-V program, and a verifier would have to trust the compiler or a proof that the compiled program matches the bytecode.

## Main results

The hand-written EVM entry against the RISC-V program, in leanVM cycles, the largest count over all valid test cases; the last row is a Yul entry that computes BLAKE2s in EVM opcodes:

| RISC-V uses | EVM uses | RISC-V | EVM, compiled | EVM, interpreter for proving | EVM, REVM |
|---|---|---:|---:|---:|---:|
| SHA-256, base instructions | SHA-256 precompile, base instructions | 460,471 | 461,359 (1.00×) | 504,922 (1.10×) | 615,971 (1.34×) |
| BLAKE2s, `blake2s` instruction | BLAKE2s precompile, `blake2s` instruction | 52,676 | 57,846 (1.10×) | 103,065 (1.96×) | 202,548 (3.85×) |
| BLAKE2s, `blake2s` instruction | SHA-256 precompile, base instructions | 52,676 | 461,359 (8.76×) | 504,922 (9.59×) | 615,971 (11.7×) |
| BLAKE2s, base instructions | BLAKE2s precompile, `blake2s` instruction | 344,072 | 57,846 (0.17×) | 103,065 (0.30×) | 202,548 (0.59×) |
| BLAKE2s, `blake2s` instruction | No precompile: BLAKE2s in EVM opcodes | 52,676 | 5,844,806 (111×) | 56,136,848 (1,066×) | 76,776,443 (1,458×) |

Median proof times of one spend:

| RISC-V uses | EVM uses | RISC-V | EVM, compiled | EVM, interpreter for proving | EVM, REVM |
|---|---|---:|---:|---:|---:|
| SHA-256, base instructions | SHA-256 precompile, base instructions | 0.59 s | 0.81 s (1.38×) | 0.88 s (1.49×) | 0.95 s (1.60×) |
| BLAKE2s, `blake2s` instruction | BLAKE2s precompile, `blake2s` instruction | 0.085 s | 0.108 s (1.27×) | 0.197 s (2.31×) | 0.245 s (2.88×) |
| BLAKE2s, base instructions | BLAKE2s precompile, `blake2s` instruction | 0.379 s | 0.108 s (0.28×) | 0.197 s (0.52×) | 0.245 s (0.65×) |

BLAKE2s in EVM opcodes needs a committed witness of 2^29 to 2^33 words, beyond the pinned leanVM's single-proof limit of 2^28. That version has no continuations, so these programs were not proved. The SHA-256 programs were timed in one [interleaved run](results/2026-09-28-interpreters/timing.jsonl) of six proofs each and the BLAKE2s programs in [another](results/2026-09-29-blake2s/timing.jsonl) of four each, on an Apple M5 Max; the SHA-256 run recorded AC power, and the BLAKE2s run kept no power record. In these two runs, retained samples of the same program differ by up to about 1.9 times: the SHA-256 reference spans 0.330 to 0.627 seconds, and the base-instruction BLAKE2s reference 0.275 to 0.515 seconds. Small timing differences are therefore inconclusive. Proof time follows the padded trace, which leanVM rounds up to powers of two table by table: the compiled SHA-256 entry runs as many cycles as the reference, but one of its tables crosses 2^18, so its trace is 42% larger. That gap is a threshold, not a cost of the EVM.

Three effects explain the tables.

**Hashing dilutes the interpreter's cost.** With SHA-256 on base instructions, the reference spends 447,493 of its 460,471 cycles hashing, and the EVM program runs the same code, so the interpreter adds 10% to 34%. With the `blake2s` instruction, the 55 hash calls take about 33,000 cycles, message handling included, and what remains is mostly the interpreter.

**The interpreter's own cost.** Each precompile call costs about 1,964 cycles under REVM and about 473 under the interpreter for proving. The hand-written entry's other opcodes cost about 86 cycles each under REVM and 47 under the interpreter for proving. What remains per opcode is mostly the dispatch, eight RISC-V instructions, and moving 256-bit stack words as four 64-bit limbs. Compiled code removes the dispatch and lets the Rust compiler optimize across opcodes.

**The measured fast hash call needs a matching precompile.** The SHA-256 EVM edition takes 8.8 to 11.7 times the cycles of the direct RISC-V BLAKE2s edition using the `blake2s` instruction. This comparison changes the hash and therefore the commitments and nullifiers. Keeping BLAKE2s and computing it in EVM opcodes instead takes 17 to 223 times the base-instruction RISC-V cycles for these implementations, whose 256-bit opcodes emulate 32-bit additions, rotations and byte-order conversions. Because EVM programs run under L1's EVM rules, a direct BLAKE2s call would need a new L1 precompile. Any pool that uses BLAKE2s, whether its proved program is EVM bytecode or RISC-V, also needs it on L1, or a separate proof, to update its tree and to recompute the statement digest it matches against the proof's public-input hash. The reverse comparison holds too: if RISC-V programs may use only base instructions while the EVM's precompile uses the `blake2s` instruction, the measured EVM program is faster. Ethereum's BLAKE2 precompile at `0x09` computes BLAKE2b compression, for which leanVM has no instruction, and [EIP-8200](https://eips.ethereum.org/EIPS/eip-8200) proposes replacing it with EVM bytecode.

## The challenge entries

The challenge scores entries under REVM with SHA-256 at `0x02`, the first row above.

| Program | Cycles | vs reference | Padded trace | Gas | EVM opcodes executed | Bytecode |
|---|---:|---:|---:|---:|---:|---:|
| RISC-V reference (Rust) | 460,354 to 460,471 | 1.00 | 622,872 | | | |
| Solidity baseline | 1,225,610 | 2.66 | 1,836,808 | 41,075 | 8,684 | 2,593 B |
| Optimized Yul entry | 625,697 to 625,721 | 1.36 | 983,496 | 14,658 | 1,348 | 1,789 B |
| Hand-written bytecode entry | 615,949 to 615,971 | 1.34 | 983,496 | 14,559 | 1,242 | 1,935 B |
| Control: EVM making only the 55 calls | 561,959 | 1.22 | 917,712 | 12,270 | 616 | 899 B |
| Control: Rust making only the 55 SHA-256 calls | 454,506 | 0.99 | 622,744 | | | |

Cycles span the 20 valid public cases for the reference, every public test case of the correct length for the controls, which check no rules and run the same count on each, and 68 public and hidden valid cases for each entry. The Rust controls were measured again with the current build on 2026-09-29 ([results/2026-09-29-control](results/2026-09-29-control/README.md)); the build of 2026-09-28, before the statement code gained its BLAKE2s edition, ran the SHA-256 control at 454,412 cycles, and the older summaries use that count. EVM opcodes are counted on the transfer case with [host/examples/opcode_profile.rs](host/examples/opcode_profile.rs). The controls are not valid spends; they separate parts of the cost ([evm/controls/generate.py](evm/controls/generate.py), [statement/src/lib.rs](statement/src/lib.rs)).

| Part | Solidity baseline | Optimized Yul | Hand-written bytecode |
|---|---:|---:|---:|
| SHA-256, 105 compressions | 447,493 | 447,493 | 447,493 |
| The 55 precompile calls themselves | 108,031 | 108,031 | 108,031 |
| EVM bytecode outside the calls | 663,651 | 63,762 | 54,012 |
| Start-up | 6,435 | 6,435 | 6,435 |
| Total | 1,225,610 | 625,721 | 615,971 |

SHA-256 is the Rust SHA-256 control minus a Rust program that only starts and returns (7,013 cycles). The precompile calls are the EVM calls control minus SHA-256 and an EVM program that makes no calls (6,435). The bytecode outside the calls is each entry minus the EVM calls control, the only part an entry controls. Most of the Solidity baseline's extra opcodes come from code the compiler generates around `abi.encodePacked` and `sha256`: moving values on the stack, computing and bounds-checking calldata offsets, and jumps. The [Yul entry](evm/yul/generate.py) and the [hand-written entry](evm/bytecode/generate.py) are unrolled, write each hash result where the next hash reads it, and check all rules with one revert. Neither checks each call's result, because under the fixed 30 million gas limit a SHA-256 call cannot fail. The reference spends 5,965 cycles more than the Rust control that makes the same 55 SHA-256 calls and nothing else, and is within about 2% of the cheapest measured program making those calls, the compiled calls control (450,599 cycles).

## Faster interpreters

The score fixes REVM so that entries compete on their bytecode. The same programs, run the two other ways under the same rules (Cancun gas, the 1 MiB memory limit, only `STATICCALL` to the SHA-256 precompile), in cycles and over the reference:

| Program | REVM (scored) | Interpreter for proving | Compiled |
|---|---:|---:|---:|
| Solidity baseline | 1,225,610 (2.66) | 895,279 (1.94) | 605,936 (1.32) |
| Optimized Yul | 625,721 (1.36) | 520,530 (1.13) | 483,044 (1.05) |
| Hand-written bytecode | 615,971 (1.34) | 504,922 (1.10) | 461,359 (1.00) |
| Control: only the 55 calls | 561,959 (1.22) | 475,219 (1.03) | 450,599 (0.98) |

A smaller change to REVM, running the precompile inside the `STATICCALL` opcode instead of through a new call frame ([interpreters/src/revm_direct.rs](interpreters/src/revm_direct.rs)), saves 1.9 to 3.0%. The interpreter for proving was built in four profile-guided rounds, each checked against REVM and recorded in the [ledger](results/2026-09-28-interpreters/ledger.jsonl). The compiled control runs below the Rust SHA-256 control because it hashes in place in EVM memory while the Rust control first builds each message.

### Checks

On the 59 public cases and 237 hidden ones from seeds 1, 2 and 3, the interpreter for proving and REVM with the direct call return the same result as REVM for all five programs, with the same gas left after every return or revert ([parity.json](results/2026-09-28-interpreters/parity.json)). On 2,999,949 random programs with random calldata and gas limits ([fuzz-101.json](results/2026-09-28-interpreters/fuzz-101.json) and the other two seeds), the interpreter for proving matches REVM's result and gas left, counting every exceptional halt as the same result. Half the programs come from opcode templates that reach memory growth, copies, the SHA-256 call, return data, jumps, running out of gas and every opcode byte; the other half mutate the entries and controls. The compiled programs match REVM on the same 296 cases at five gas limits ([compiled-parity.json](results/2026-09-28-interpreters/compiled-parity.json)). The BLAKE2s edition adds 177 cases and 600,000 random programs calling `0xb2`; that random-program coverage applies to the fast interpreter. The saved leanVM runs establish correct valid-case digests and the reported padded trace totals. Their negative-case flags are not evidence of rejection: the original execution harness masked acceptance whenever fixture metadata said an input was invalid. The native correctness gate is independent of that bug. The repaired harness checks guest completion independently and supplies canonical digests for length-correct invalid fixtures; wrong-length inputs remain a native host check. Historical measurement files are preserved unchanged.

## The BLAKE2s edition

The BLAKE2s edition is the same spend with BLAKE2s-256 as every hash: the oracle's `--hash blake2s` mode, the Rust statement's `verify_with::<Blake2sHash>`, and [62 public cases](fixtures/public-blake2s.json) with the same names and rules. The EVM entries are the [hand-written entry](evm/blake2s/generate.py) calling `0xb2`, unchanged otherwise, and a Yul entry that computes BLAKE2s in EVM opcodes, with one 32-bit word per 32-byte memory slot. The edition keeps the SHA-256 edition's messages, one-byte tags included. For BLAKE2s, a tag pushes every 64-byte payload (inner, tree node, nullifier key and nullifier) into a second block, so a spend takes 105 compressions; moving the tags into BLAKE2s's personalization parameter would take 59. That layout was not measured; with less hashing shared by both programs, the EVM-to-RISC-V ratios in the `blake2s` instruction rows would be higher.

| Program | Cycles | Padded trace | Committed words | Median proof time |
|---|---:|---:|---:|---:|
| RISC-V, base instructions only | 344,072 | 491,608 | 22.0 M | 0.379 s |
| RISC-V with the `blake2s` instruction | 52,676 | 92,560 | 5.2 M | 0.085 s |
| EVM, precompile on base instructions, REVM | 494,144 | 852,296 | 37.7 M | 0.773 s |
| EVM, precompile on base instructions, interpreter for proving | 394,661 | 491,552 | 22.0 M | 0.487 s |
| EVM, precompile on base instructions, compiled | 349,442 | 491,552 | 22.0 M | 0.465 s |
| EVM, precompile on the `blake2s` instruction, REVM | 202,548 | 246,336 | 12.1 M | 0.245 s |
| EVM, precompile on the `blake2s` instruction, interpreter for proving | 103,065 | 172,304 | 8.7 M | 0.197 s |
| EVM, precompile on the `blake2s` instruction, compiled | 57,846 | 98,576 | 5.5 M | 0.108 s |
| EVM, no precompile (EVM opcodes), REVM | 76,776,443 | 117,443,608 | 5,100 M | above the 2^28 limit |
| EVM, no precompile (EVM opcodes), interpreter for proving | 56,136,848 | 75,500,560 | 3,221 M | above the 2^28 limit |
| EVM, no precompile (EVM opcodes), compiled | 5,844,806 | 8,456,208 | 369 M | above the 2^28 limit |

Cycles are the largest count over 60 valid cases, the public ones and hidden seeds 1 and 2 ([summary](results/2026-09-29-blake2s/summary.json)). Committed words, the data the prover commits to, compare programs that use the `blake2s` instruction more fairly than cycles do, because its rows are wider than those of base instructions. REVM here is a copy that can execute a precompile at `0xb2` ([interpreters/src/reference.rs](interpreters/src/reference.rs)).

A second implementation of BLAKE2s in EVM opcodes ([evm/blake2s/packed.py](evm/blake2s/packed.py)) keeps the four 32-bit words of each state row in one 256-bit word, 64 bits apart so that additions cannot carry from one into the next, and computes the four column or diagonal steps of a round at once. The spend then uses 1,231,197 gas instead of 2,752,716, about 11,700 per compression averaged over the spend, and executes 410,140 opcodes instead of 905,870. It takes 26,858,924 cycles under the interpreter for proving, about 256,000 per compression, and 35,892,562 under REVM, about half the counts above, but 6,767,420 compiled ahead of time, 16% more. Its witness is still 2^29 to 2^32 words, so it was not proved either. Its BLAKE2s matches Python's on 400 random messages, and the entry passes the public BLAKE2s cases and two hidden seeds; its cycles are the largest over three valid public cases ([summary](results/2026-09-29-blake2s-packed/summary.json)).

With this message layout, most of the gain comes from the `blake2s` instruction rather than from the choice of hash. On base instructions, the statement's 55 calls take 448,239 cycles with SHA-256, 337,159 with BLAKE2s and 238,304 with BLAKE3, against 39,748 with the `blake2s` instruction ([guests/hash-choice](guests/hash-choice/src/lib.rs), [scripts/hash_choice.py](scripts/hash_choice.py)). On base instructions, BLAKE2s and BLAKE3 save 25% and 47% of SHA-256's cycles, while the `blake2s` instruction saves 91%. All three hashes rotate 32-bit words, which RV64IM emulates with shifts.

## Gas

Gas ranks the three entries in the same order as cycles but overstates their differences: the Solidity baseline uses 2.82 times the hand-written entry's gas and 1.99 times its cycles. The 55 calls cost 10,756 gas, 74% of the hand-written entry's gas: 5,500 for the 55 `STATICCALL` opcodes and 5,256 for the precompile. Those 5,256 gas pay for 447,493 cycles of SHA-256, about 85 cycles per unit of gas, while the rest of the entry costs about 18 cycles per unit under REVM. The BLAKE2s entry uses the same 14,559 gas whether its precompile runs on base instructions or on the `blake2s` instruction, although its cycles differ 2.4 to 6.0 times (3.8 times with the interpreter for proving). These figures exclude transaction overhead and price the hypothetical BLAKE2s precompile like SHA-256. Gas ranks these entries correctly but does not generally predict proving cost; a RISC-V program has no gas metric here.

## Validation

The Python oracle, the Rust reference and the three EVM entries agree on all 62 public test cases: the expected digest for the 20 valid inputs and no result for the 42 invalid ones. The Rust reference and the Solidity baseline also name the broken rule, and it matches the oracle. All of them agree on hidden cases from seeds 1, 2 and 3, and the scored runs used fresh seeds for each entry (101 and 202, 303 and 404, 505 and 606). Removing any one rule check makes at least one public case fail, for each entry, 11 of 11 ([baseline](results/2026-09-28/rule-removal-solidity.json), [Yul](results/2026-09-28/rule-removal-yul.json), [hand-written](results/2026-09-28/rule-removal-bytecode.json)).

The public fixtures gained three invalid cases on 2026-09-29: a funded note whose index is 2^20 or more, on each input, and a zero-value first output whose `inner` is 2. Only bits 0 to 19 of an index steer the Merkle path, so without the first two cases an entry could skip the index check on a funded note and give that note a second nullifier. Measurements and checks dated 2026-09-28 used the 59 earlier cases, which are unchanged.

## Limits

Cycle counts are exact for a given build, but a change elsewhere in a guest can shift a count by a few hundred cycles through `memcpy` alignment. Proof times come from one laptop without zero knowledge. The BLAKE2s precompile is hypothetical. The interpreter for proving and the compiled programs implement only what the scoring rules allow, with no storage, logs, environment reads or calls other than to the hash precompile. Finite tests and a focused review do not establish general equivalence or production security. In production an interpreter is part of what verifiers trust, because a proof shows that one specific interpreter build produced the output; any difference from the EVM rules could make a program accept an input it should reject. Each guest here embeds its program's bytecode. Hashing the hand-written entry alone, 31 BLAKE2s compressions, is estimated to add 10,000 cycles with the `blake2s` instruction. The complete dynamic-input interpreter path has not been measured.

The scorer now compares the full vector of padded table sizes, not just its sum. This is a finite shape check, not a privacy guarantee. The pinned leanVM also publishes the final clock, which grows with the cycle count, and has no zero knowledge, so equal padded table sizes do not establish that private inputs are hidden. On the public cases, the reference runs 460,354 to 460,358 cycles when one input is a dummy and 460,467 to 460,471 when both are funded, so its count reveals which kind of spend it proved; the three EVM entries' counts do not separate the two.

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
