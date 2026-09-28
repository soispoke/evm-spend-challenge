# EVM Spend Challenge

## TL;DR

This directory is the complete challenge: its [specification](SPEC.md), the reference statement, the test cases, the scorer, two EVM entries and the [measured results](RESULTS.md). Entrants submit EVM bytecode that checks a privacy-pool spend. The score is the number of RV64IM cycles it takes on a fixed version of leanVM, compared with the same check written in Rust and compiled to RISC-V. The Solidity baseline scores 1,225,610 cycles (2.66 times the reference) and the optimized Yul entry 625,721 (1.36 times). The code is research code tested against a Python oracle; it has not been audited, and the challenge has not launched.

## Quick start

Requirements: git, Python 3, [Foundry](https://getfoundry.sh) with solc 0.8.30, and rustup with the `nightly-2026-09-17` toolchain and its `rust-src` component.

```sh
./scripts/build.sh                                  # fetch leanVM, build everything, check both entries
python3 scripts/score.py path/to/bytecode.hex       # score an entry
./target/release/examples/opcode_profile path/to/bytecode.hex fixtures/public.json transfer
```

`score.py` runs the correctness tests on the public cases and on two fresh hidden seeds, runs every valid case on leanVM, and prints the score: the largest cycle count, with the padded trace size and whether it fits leanVM's current proof-size limit. The opcode profile counts the EVM instructions an entry executes on one case. [RESULTS.md](RESULTS.md) shows how to reproduce the measurements.

## Layout

| Path | Contents |
|---|---|
| [SPEC.md](SPEC.md) | The challenge: statement, input format, rules, scoring, fixed setup |
| [RESULTS.md](RESULTS.md) | Measured cycles, cost breakdown, instruction counts, proof times, estimates |
| [explainer.html](explainer.html) | One-page explainer with an interactive view of the results |
| [oracle/spend_sha256.py](oracle/spend_sha256.py) | Python reference for the statement; writes the public cases and generates hidden ones |
| [fixtures/public.json](fixtures/public.json) | 20 valid spends and 39 invalid inputs, each breaking exactly one rule |
| [statement/](statement/src/lib.rs) | Rust reference, compiled to RISC-V for the reference score, and two control programs |
| [engine/](engine/src/lib.rs) | The EVM harness: REVM 43.0.0 allowing only `STATICCALL` to the SHA-256 precompile, with [build patches](engine/vendor/README.md) |
| [evm/src/SpendSha256.sol](evm/src/SpendSha256.sol) | Solidity baseline entry; bytecode in `evm/baseline.hex` |
| [evm/yul/generate.py](evm/yul/generate.py) | Optimized Yul entry, generated and compiled; bytecode in `evm/yul/bytecode.hex` |
| [evm/controls/generate.py](evm/controls/generate.py) | EVM control programs used to split the cost |
| [guests/](guests/runtime/src/lib.rs) | leanVM RV64IM programs: the reference, the EVM harness running an entry, and two controls |
| [host/](host/src/main.rs) | Scorer with `check`, `execute` and `prove` modes, and the opcode profiler |
| [scripts/](scripts/score.py) | `fetch.sh`, `build.sh`, `score.py`, `measure.py`, `time_proofs.py`, `report.py`, `mutation_check.py` |
| [results/](results/summary.json) | `summary.json` and the raw runs it is built from |

## Limitations

The harness runs an EVM function, not a full transaction, and allows one precompile. The leanVM branch is exploratory: the challenge pins one commit, and that commit has no zero knowledge. Proof times were measured on one laptop and vary between runs. No adapter for another zkVM exists yet.
