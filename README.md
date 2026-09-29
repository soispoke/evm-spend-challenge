# EVM Spend Challenge

## TL;DR

Under EIP-8288, a privacy pool could prove its spend rules with a program run in a zkVM. This repository measures what that proof costs when the program is EVM bytecode executed by an EVM interpreter, against the same check as a RISC-V program compiled from Rust, both proved by leanVM. How much more the EVM program costs depends mostly on how its bytecode is executed and on whether leanVM has an instruction for the hash precompile that the EVM program calls. When both compute BLAKE2s with leanVM's `blake2s` instruction, the EVM program through a BLAKE2s precompile, the EVM program takes 1.96 times the RISC-V cycles when executed by an interpreter written for proving and 3.85 times when executed by REVM. When both compute SHA-256 with base instructions, it takes 1.10 to 1.34 times, and when it can only call the SHA-256 precompile while the RISC-V program uses the `blake2s` instruction, about 10 times. It also holds the challenge itself: the [specification](SPEC.md), test cases, scorer and three entries. The [explainer](https://soispoke.github.io/evm-spend-challenge/explainer.html) shows the results on one page, and [RESULTS.md](RESULTS.md) has every measurement. This is research code tested against a Python oracle and REVM; it has not been audited, and the challenge has not launched.

## Results

The hand-written bytecode entry against the RISC-V program, in leanVM cycles and as a multiple of the RISC-V cycles:

| RISC-V uses | EVM uses | RISC-V | EVM, compiled ahead of time | EVM, interpreter for proving | EVM, REVM |
|---|---|---:|---:|---:|---:|
| SHA-256, base instructions | SHA-256 precompile, base instructions | 460,471 | 1.00× | 1.10× | 1.34× |
| BLAKE2s, `blake2s` instruction | BLAKE2s precompile, `blake2s` instruction | 52,676 | 1.10× | 1.96× | 3.85× |
| BLAKE2s, `blake2s` instruction | SHA-256 precompile, base instructions | 52,676 | 8.76× | 9.59× | 11.7× |
| BLAKE2s, base instructions | BLAKE2s precompile, `blake2s` instruction | 344,072 | 0.17× | 0.30× | 0.59× |
| BLAKE2s, `blake2s` instruction | No precompile: BLAKE2s in EVM opcodes | 52,676 | 111× | 1,066× | 1,458× |

Base instructions are standard RV64IM, the counterpart of EVM opcodes; leanVM's `blake2s` instruction computes one BLAKE2s compression in a single step, the counterpart of an EVM precompile. REVM is the Rust EVM used by Reth. The interpreter for proving was written for this study, and compiling ahead of time shows about the best any interpreter could reach. The BLAKE2s precompile is hypothetical: Ethereum has none. With SHA-256 on base instructions, hashing takes 97% of the RISC-V cycles and runs the same code in both programs, so the interpreter's cost barely shows. With the `blake2s` instruction, hashing is cheap and the interpreter sets the gap. Proof times follow the same pattern: 0.085 seconds for RISC-V with the `blake2s` instruction, against 0.197 with the interpreter for proving and 0.245 with REVM.

## What this means for EIP-8288

EVM programs are practical for EIP-8288 proofs when their heavy operations are precompiles that the prover executes with a dedicated instruction, at about twice the cycles of RISC-V with an interpreter written for proving. One interpreter can execute every EVM program under one verification key, because it takes the bytecode as input and hashes it. With a dedicated EIP-8288 scheme whose fork configuration pins the interpreter and the verifier, contracts name their program by fork and bytecode hash, and a faster interpreter or a new proof system reaches them without changes. The interpreter then needs the review and testing of a verifier.

The hash must match. L1 has SHA-256 (`0x02`) and Keccak-256 (`KECCAK256`); this leanVM version has an instruction only for BLAKE2s, which its README calls a placeholder, with SHA-2, SHA-3 and BLAKE3 under consideration. A BLAKE2s or BLAKE3 prover hash needs a new L1 precompile, added by a hard fork before programs deploy; SHA-256 or SHA-3 needs none. Every other heavy primitive, such as a signature scheme for private accounts, likewise needs an L1 precompile that the prover executes with a dedicated instruction. RISC-V remains the long-term target: faster, and able to run new primitives on base instructions without a fork, once one verification key can prove any RISC-V program.

## The challenge

Entrants submit EVM bytecode for the SHA-256 edition. REVM, the leanVM version and the SHA-256 code are fixed, and the score is the largest cycle count over the valid test cases, including new ones generated at scoring time ([SPEC.md](SPEC.md)).

| Entry | Cycles | vs RISC-V | Gas |
|---|---:|---:|---:|
| RISC-V reference (Rust) | 460,471 | 1.00× | |
| [Solidity baseline](evm/src/SpendSha256.sol) | 1,225,610 | 2.66× | 41,075 |
| [Optimized Yul](evm/yul/generate.py) | 625,721 | 1.36× | 14,658 |
| [Hand-written bytecode](evm/bytecode/generate.py) | 615,971 | 1.34× | 14,559 |

## Quick start

Requirements: git, Python 3, [Foundry](https://getfoundry.sh) with solc 0.8.30, and rustup with the `nightly-2026-09-17` toolchain and its `rust-src` component.

```sh
./scripts/build.sh                                  # fetch leanVM, build everything, check the entries
python3 scripts/score.py path/to/bytecode.hex       # score an entry
./target/release/examples/opcode_profile path/to/bytecode.hex fixtures/public.json transfer
```

`score.py` runs the correctness tests on the public cases and on two fresh hidden seeds, runs every valid case on leanVM, and prints the score: the largest cycle count, with the padded trace size and whether its witness fits leanVM's current limit. The opcode profile counts the EVM opcodes an entry executes on one case, and its gas. [RESULTS.md](RESULTS.md#reproduce) lists the commands that reproduce every measurement.

## Layout

| Path | Contents |
|---|---|
| [SPEC.md](SPEC.md) | The challenge: statement, input format, rules, scoring, fixed setup |
| [RESULTS.md](RESULTS.md) | Every measurement: cycles, proof times, interpreters, the BLAKE2s edition, gas, checks |
| [oracle/spend_sha256.py](oracle/spend_sha256.py) | Python reference for the statement; writes the public cases and generates hidden ones, for SHA-256 or BLAKE2s |
| [fixtures/](fixtures/public.json) | 20 valid spends and 39 invalid inputs, each breaking exactly one rule, in both editions |
| [statement/](statement/src/lib.rs) | Rust reference, compiled to RISC-V, and control programs |
| [engine/](engine/src/lib.rs) | The scoring harness: REVM 43.0.0 allowing only `STATICCALL` to the SHA-256 precompile, with [build patches](engine/vendor/README.md) |
| [evm/](evm/src/SpendSha256.sol) | The entries: Solidity baseline, optimized Yul, hand-written bytecode, controls, and the BLAKE2s edition's entries |
| [interpreters/](interpreters/src/lib.rs) | The interpreter written for proving, REVM variants that report gas, and [compile.py](interpreters/compile.py), which compiles a program ahead of time into Rust |
| [guests/](guests/runtime/src/lib.rs) | leanVM RV64IM programs: the reference, every entry under each interpreter, controls, and the BLAKE2s edition |
| [host/](host/src/main.rs) | Scorer with `check`, `execute` and `prove` modes; examples for opcode counts, cycle profiles, parity and random-program tests |
| [scripts/](scripts/score.py) | Build, scoring, measurement, timing and report scripts |
| [results/](results/summary.json) | Summaries and the raw runs they are built from |

## Limitations

The harness runs an EVM function, not a full transaction, and allows only the hash precompile. The pinned leanVM commit is exploratory and has no zero knowledge. Proof times were measured on one laptop and vary between runs. The interpreter for proving and the compiled programs are tested against REVM on the test cases and on random programs, but not audited.
