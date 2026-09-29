# EVM Spend Challenge: Results

## TL;DR

The same privacy-pool spend check was proved by leanVM in two forms: a Rust program compiled to RISC-V, and EVM bytecode run by an EVM interpreter compiled to RISC-V. How much more the EVM form costs depends mostly on how its bytecode is executed and on whether it can call the hash that the prover accelerates. With leanVM's `blake2s` instruction serving both forms, the EVM form takes 1.96 times the RISC-V cycles under an interpreter written for proving, 3.85 times under REVM and 1.10 times compiled ahead of time. With SHA-256 in software on both sides, hashing is 97% of the RISC-V cycles and runs the same code in both forms, so the gap is 1.10 to 1.34 times. An EVM program that can only call SHA-256 takes about 10 times the cycles of a RISC-V program using the instruction, and BLAKE2s written in EVM code is too large to prove. A RISC-V program limited to base instructions takes 3.3 times the cycles of an EVM program whose precompile uses the instruction. Gas does not measure proving cost.

## Setup

The statement is the spend defined in [SPEC.md](SPEC.md): two input notes in a 20-level Merkle tree, two output notes, 55 hash calls and 105 compressions of 64 bytes. It exists in two editions with the same rules and test cases, SHA-256, which the challenge scores, and BLAKE2s. Every program runs on leanVM's `riscv-exploration` branch at [`1096dedf`](https://github.com/leanEthereum/leanVM/tree/1096dedfbe29c72cfff2a2d8d8b420e6ff0d9f2d): RV64IM plus a `blake2s` instruction that computes one BLAKE2s compression, without zero knowledge.

The RISC-V form is the [Rust reference](statement/src/lib.rs) compiled to RV64IM, hashing in software or, for BLAKE2s, with the instruction. The EVM form is an entry's bytecode inside a guest that runs an EVM interpreter. Its hash calls are `STATICCALL`s to a precompile: SHA-256 at `0x02`, or a BLAKE2s precompile at `0xb2`, which Ethereum does not have and which is priced here like SHA-256. The interpreter serves the precompile with the same Rust code as the reference, or with the instruction. The bytecode runs in one of three ways:

1. **REVM:** `revm-interpreter` 43.0.0, the Rust EVM used by Reth, fixed by the challenge's scoring. It is not written for proving.
2. **An interpreter written for proving** ([interpreters/src/fast.rs](interpreters/src/fast.rs)): one dispatch loop over a zero-padded copy of the code, the stack in a fixed buffer, jump destinations analyzed only when a jump is taken, and hashing straight from EVM memory. It subtracts each instruction's fixed gas cost without a check and checks the balance wherever gas can be observed, so results and gas match REVM.
3. **Compiled ahead of time** ([interpreters/compile.py](interpreters/compile.py)): each program translated into one Rust function, with stack values in local variables. This is about the best any interpreter could reach. Each compiled program is a different RISC-V program, and a verifier would have to trust the compiler or a proof that the compiled program matches the bytecode.

## Main results

The hand-written EVM entry against the RISC-V form, in leanVM cycles, the largest count over all valid test cases:

| RISC-V uses | EVM uses | RISC-V | EVM, compiled | EVM, interpreter for proving | EVM, REVM |
|---|---|---:|---:|---:|---:|
| SHA-256 in software | SHA-256 precompile, same code | 460,471 | 461,359 (1.00×) | 504,922 (1.10×) | 615,971 (1.34×) |
| `blake2s` instruction | BLAKE2s precompile, same instruction | 52,676 | 57,846 (1.10×) | 103,065 (1.96×) | 202,548 (3.85×) |
| `blake2s` instruction | SHA-256 precompile in software | 52,676 | 461,359 (8.76×) | 504,922 (9.59×) | 615,971 (11.7×) |
| BLAKE2s, base instructions | BLAKE2s precompile, `blake2s` instruction | 344,072 | 57,846 (0.17×) | 103,065 (0.30×) | 202,548 (0.59×) |
| `blake2s` instruction | BLAKE2s written in EVM code | 52,676 | 5,844,806 (111×) | 56,136,848 (1,066×) | 76,776,443 (1,458×) |

Median proof times of one spend:

| RISC-V uses | EVM uses | RISC-V | EVM, compiled | EVM, interpreter for proving | EVM, REVM |
|---|---|---:|---:|---:|---:|
| SHA-256 in software | SHA-256 precompile, same code | 0.59 s | 0.81 s (1.38×) | 0.88 s (1.49×) | 0.95 s (1.60×) |
| `blake2s` instruction | BLAKE2s precompile, same instruction | 0.085 s | 0.108 s (1.27×) | 0.197 s (2.31×) | 0.245 s (2.88×) |
| BLAKE2s, base instructions | BLAKE2s precompile, `blake2s` instruction | 0.379 s | 0.108 s (0.28×) | 0.197 s (0.52×) | 0.245 s (0.65×) |

BLAKE2s written in EVM code needs a witness of 2^29 to 2^33 words, beyond the pinned leanVM's limit of 2^28, so it has no proofs. The SHA-256 programs were timed in one [interleaved run](results/2026-09-28-interpreters/timing.jsonl) of six proofs each and the BLAKE2s programs in [another](results/2026-09-29-blake2s/timing.jsonl) of four each, on an Apple M5 Max on AC power. Back-to-back runs of the same program varied by up to 40%, so only large time differences are meaningful. Proof time follows the padded trace, which leanVM rounds up to powers of two table by table: the compiled SHA-256 entry runs as many cycles as the reference, but one of its tables crosses 2^18, so its trace is 42% larger. That gap is a threshold, not a cost of the EVM.

Three effects explain the tables.

**Hashing dilutes the interpreter's cost.** With software SHA-256, the reference spends 447,399 of its 460,471 cycles hashing, and the EVM form runs the same code, so the interpreter adds 10% to 34%. The instruction computes the 105 compressions in about 33,000 cycles, and what remains is mostly the interpreter.

**The interpreter's own cost.** Each precompile call costs about 1,966 cycles under REVM and about 474 under the interpreter for proving. The hand-written entry's other instructions cost about 86 cycles each under REVM and 47 under the interpreter for proving. What remains per instruction is mostly the dispatch, eight RISC-V instructions, and moving 256-bit stack words as four 64-bit limbs. Compiled code removes the dispatch and lets the Rust compiler optimize across instructions.

**The hash must be one both sides can accelerate.** An EVM program can only call what the EVM provides. Without a BLAKE2s precompile it hashes with SHA-256 in software, about ten times a RISC-V program using the instruction, or computes BLAKE2s in EVM code, 17 to 223 times a RISC-V program computing BLAKE2s in software, because 256-bit instructions emulate 32-bit additions and rotations and every word is byte-swapped between BLAKE2s's little-endian order and EVM memory's big-endian order. The reverse holds too: if RISC-V programs may use only the base instructions while the EVM's precompile uses the instruction, the EVM is faster. Ethereum's BLAKE2 precompile at `0x09` computes the BLAKE2b compression, which leanVM does not accelerate, and [EIP-8200](https://eips.ethereum.org/EIPS/eip-8200) proposes replacing it with EVM bytecode.

## The challenge entries

The challenge scores entries under REVM with SHA-256 at `0x02`, the first row above.

| Program | Cycles | vs reference | Padded trace | Gas | EVM instructions | Bytecode |
|---|---:|---:|---:|---:|---:|---:|
| RISC-V reference (Rust) | 460,354 to 460,471 | 1.00 | 622,872 | | | |
| Solidity baseline | 1,225,610 | 2.66 | 1,836,808 | 41,075 | 8,684 | 2,593 B |
| Optimized Yul entry | 625,697 to 625,721 | 1.36 | 983,496 | 14,658 | 1,348 | 1,789 B |
| Hand-written bytecode entry | 615,949 to 615,971 | 1.34 | 983,496 | 14,559 | 1,242 | 1,935 B |
| Control: EVM making only the 55 calls | 561,959 | 1.22 | 917,712 | 12,270 | 616 | 899 B |
| Control: Rust making only the 55 SHA-256 calls | 454,412 | 0.99 | 622,744 | | | |

Cycles span the 20 valid public cases for the reference, all 56 public inputs of the correct length for the controls, which check no rules, and 68 public and hidden valid cases for each entry. EVM instructions are counted on the transfer case with [host/examples/opcode_profile.rs](host/examples/opcode_profile.rs). The controls are not valid spends; they separate parts of the cost ([evm/controls/generate.py](evm/controls/generate.py), [statement/src/lib.rs](statement/src/lib.rs)).

| Part | Solidity baseline | Optimized Yul | Hand-written bytecode |
|---|---:|---:|---:|
| SHA-256, 105 compressions | 447,399 | 447,399 | 447,399 |
| The 55 precompile calls themselves | 108,125 | 108,125 | 108,125 |
| EVM bytecode outside the calls | 663,651 | 63,762 | 54,012 |
| Start-up | 6,435 | 6,435 | 6,435 |
| Total | 1,225,610 | 625,721 | 615,971 |

SHA-256 is the Rust SHA-256 control minus a Rust program that only starts and returns (7,013 cycles). The precompile calls are the EVM calls control minus SHA-256 and an EVM program that makes no calls (6,435). The bytecode outside the calls is each entry minus the EVM calls control, the only part an entry controls. Most of the Solidity baseline's extra instructions come from code the compiler generates around `abi.encodePacked` and `sha256`: moving values on the stack, computing and bounds-checking calldata offsets, and jumps. The [Yul entry](evm/yul/generate.py) and the [hand-written entry](evm/bytecode/generate.py) are unrolled, write each hash result where the next hash reads it, and check all rules with one revert. Neither checks each call's result, because under the fixed 30 million gas limit a SHA-256 call cannot fail. The reference is close to the best any RISC-V version can do here: it spends only 6,059 cycles more than the control that makes the 55 SHA-256 calls and nothing else.

## Faster interpreters

The score fixes REVM so that entries compete on their bytecode. The same programs, run the two other ways under the same rules (Cancun gas, the 1 MiB memory limit, only `STATICCALL` to the SHA-256 precompile), in cycles and over the reference:

| Program | REVM (scored) | Interpreter for proving | Compiled |
|---|---:|---:|---:|
| Solidity baseline | 1,225,610 (2.66) | 895,279 (1.94) | 605,936 (1.32) |
| Optimized Yul | 625,721 (1.36) | 520,530 (1.13) | 483,044 (1.05) |
| Hand-written bytecode | 615,971 (1.34) | 504,922 (1.10) | 461,359 (1.00) |
| Control: only the 55 calls | 561,959 (1.22) | 475,219 (1.03) | 450,599 (0.98) |

A smaller change to REVM, running the precompile inside the call instruction instead of through a new call frame ([interpreters/src/revm_direct.rs](interpreters/src/revm_direct.rs)), saves only 3%. The interpreter for proving was built in four profile-guided rounds, each checked against REVM and recorded in the [ledger](results/2026-09-28-interpreters/ledger.jsonl). The compiled control runs below the Rust SHA-256 control because it hashes in place in EVM memory while the Rust control first builds each message.

### Checks

On the 59 public cases and 237 hidden ones from seeds 1, 2 and 3, the interpreter for proving and REVM with the direct call return the same result as REVM for all five programs, with the same gas left after every return or revert ([parity.json](results/2026-09-28-interpreters/parity.json)). On 2,999,949 random programs with random calldata and gas limits ([fuzz-101.json](results/2026-09-28-interpreters/fuzz-101.json) and the other two seeds), the interpreter for proving matches REVM's result and gas left, counting every exceptional halt as the same result. Half the programs come from instruction templates that reach memory growth, copies, the SHA-256 call, return data, jumps, running out of gas and every opcode byte; the other half mutate the entries and controls. The compiled programs match REVM on the same 296 cases at five gas limits ([compiled-parity.json](results/2026-09-28-interpreters/compiled-parity.json)). The BLAKE2s edition adds 177 cases and 600,000 random programs calling `0xb2`. On leanVM, every program accepts every valid case, rejects every invalid one and keeps one padded trace size across its valid inputs.

## The BLAKE2s edition

The BLAKE2s edition is the same spend with BLAKE2s-256 as every hash: the oracle's `--hash blake2s` mode, the Rust statement's `verify_with::<Blake2sHash>`, and [59 public cases](fixtures/public-blake2s.json) with the same names and rules. The EVM entries are the [hand-written entry](evm/blake2s/generate.py) calling `0xb2`, unchanged otherwise, and a Yul entry that computes BLAKE2s in EVM code with one 32-bit word per 32-byte memory slot.

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

Cycles are the largest count over 60 valid cases, the public ones and hidden seeds 1 and 2 ([summary](results/2026-09-29-blake2s/summary.json)). Committed words, the data the prover commits to, compare programs that use the instruction more fairly than cycles do, because the instruction's rows are wider than those of ordinary instructions. REVM here is a copy that can serve `0xb2` ([interpreters/src/reference.rs](interpreters/src/reference.rs)); on the SHA-256 entry it costs 0.14% more than the scoring harness.

The gain comes from the instruction, not from the choice of hash. Made in software, the statement's 55 calls take 448,239 cycles with SHA-256, 337,159 with BLAKE2s and 238,304 with BLAKE3, against 39,748 with the instruction ([guests/hash-choice](guests/hash-choice/src/lib.rs), [scripts/hash_choice.py](scripts/hash_choice.py)). RV64IM has no rotate instruction, which BLAKE2s and BLAKE3 use heavily, so in software they save 25% and 47% of SHA-256's cycles, while the instruction saves 91%.

## Gas

Gas ranks the three entries in the same order as cycles but overstates their differences: the Solidity baseline uses 2.82 times the hand-written entry's gas and 1.99 times its cycles. The 55 calls cost 10,756 gas, 74% of the hand-written entry's gas: 5,500 for the `STATICCALL` instructions and 5,256 for the precompile. Those 5,256 gas pay for 447,399 cycles of SHA-256, about 85 cycles per unit of gas, while the rest of the entry costs about 18 cycles per unit under REVM. The BLAKE2s entry uses the same 14,559 gas whether its precompile is served in software or by the instruction, although its cycles differ almost fourfold. Gas can say which of two entries doing the same hashing is cheaper to prove, not by how much, and a RISC-V program has no gas.

## Validation

The Python oracle, the Rust reference and the three EVM entries agree on all 59 public test cases: the expected digest for the 20 valid inputs and no result for the 39 invalid ones. The Rust reference and the Solidity baseline also name the broken rule, and it matches the oracle. All of them agree on hidden cases from seeds 1, 2 and 3, and the scored runs used fresh seeds for each entry (101 and 202, 303 and 404, 505 and 606). Removing any one rule check makes at least one public case fail, for each entry, 11 of 11 ([baseline](results/2026-09-28/rule-removal-solidity.json), [Yul](results/2026-09-28/rule-removal-yul.json), [hand-written](results/2026-09-28/rule-removal-bytecode.json)).

## Limits

Cycle counts are exact for a given build, but a change elsewhere in a guest can shift a count by a few hundred cycles through `memcpy` alignment. Proof times come from one laptop without zero knowledge. The BLAKE2s precompile is hypothetical. The interpreter for proving and the compiled programs implement only what the scoring rules allow, with no storage, logs, environment reads or calls other than to the hash precompile. They are research code, tested against REVM, not audited or formally verified. In production an interpreter is part of what verifiers trust, because a proof shows that one specific interpreter build produced the output; any difference from the EVM rules could make a program accept an input it should reject. Each guest here embeds its program's bytecode. An interpreter used under EIP-8288 would take the bytecode as input and hash it, which for the hand-written entry, 31 BLAKE2s compressions, would add an estimated 10,000 cycles with the instruction.

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
