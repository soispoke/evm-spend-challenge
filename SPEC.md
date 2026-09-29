# EVM Spend Challenge: Specification

## TL;DR

Submit the EVM bytecode that checks a privacy-pool spend in the fewest RISC-V cycles. Each private transfer in a privacy pool comes with a zero-knowledge proof that the spend follows the pool's rules; under EIP-8288 those rules could be a program proved by a zkVM. This challenge measures that program's cost when it is EVM bytecode executed by an EVM interpreter, against the same check as a RISC-V program compiled from Rust, on a fixed version of leanVM. The Solidity baseline takes 1,225,610 cycles, 2.66 times the RISC-V reference, an optimized Yul entry takes 625,721 (1.36 times) and a hand-written bytecode entry 615,971 (1.34 times). Most of what remains is the fixed interpreter's cost: executed by an interpreter written for proving, the hand-written entry takes 1.10 times, and compiled ahead of time 1.00 times. The result informs whether applications under EIP-8288 can keep their proved programs in EVM bytecode or should be able to use RISC-V directly.

## The question

EIP-8288 lets transactions carry proofs that Ethereum verifies. A privacy application's proof shows that a program accepted a spend: the program reads the private data (keys, notes, Merkle paths) and the public values, checks the pool's rules, and outputs a hash of the public values. If that program costs about as much to prove as EVM bytecode as it does compiled to RISC-V, applications could keep writing it in EVM bytecode, which weakens the performance case for letting them use RISC-V directly. Letting entrants optimize the EVM program measures the best achievable cost rather than the cost of one implementation.

SHA-256 is the only hash, because the EVM already provides it as precompile `0x02`. No new precompile is assumed, and a precompile for another hash would be called the same way.

## Submission

An entry is EVM runtime bytecode (`bytecode.hex`) with its source and build instructions, in any language. The bytecode receives the 1,680-byte input as calldata. For a valid input it must return exactly the 32-byte statement digest. For an input that breaks any rule it must not return successfully. Reverting with `Rule(uint8)` to name the broken rule is optional.

## The statement

The statement is the minimal shielded pool's current [spend circuit](https://github.com/soispoke/minimal-shielded-pool/blob/08bb03412e90c3ef79145bc6627d739aaea34dc3/circuits/spend.circom): two input notes in a 20-level Merkle tree, two output notes, a public amount and a fee, with nullifiers bound to the note's leaf position. This version uses SHA-256 instead of Poseidon, fixed-width byte fields instead of field elements, and a one-byte tag at the start of every hashed message. Root freshness, nullifier reuse, the authorizer's signature and settlement remain on-chain checks, as in the pool.

### Input

The input is exactly 1,680 bytes. Integers are big-endian. Input note `k` starts at byte `136 + 724k` and output `k` at byte `1584 + 48k`.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 32 | `root` |
| 32 | 32 | `domain` |
| 64 | 16 | `public_amount` (u128) |
| 80 | 16 | `fee` (u128) |
| 96 | 20 | `recipient` |
| 116 | 20 | `authorizer` |
| note + 0 | 32 | `spend_key` |
| note + 32 | 32 | `rho` |
| note + 64 | 16 | `value` (u128) |
| note + 80 | 4 | `index` (u32) |
| note + 84 | 640 | 20 Merkle siblings, leaf level first |
| output + 0 | 32 | `inner`, provided by the output's recipient |
| output + 32 | 16 | `value` (u128) |

### Hashes

Each value is the SHA-256 digest of a tag byte followed by fixed-width fields.

| Value | Message | Bytes | Compressions |
|---|---|---:|---:|
| owner key | `0x01 ‖ spend_key` | 33 | 1 |
| inner | `0x05 ‖ owner key ‖ rho` | 65 | 2 |
| commitment | `0x02 ‖ inner ‖ value` | 49 | 1 |
| tree node | `0x04 ‖ left ‖ right` | 65 | 2 |
| occurrence | `0x07 ‖ commitment ‖ index` | 37 | 1 |
| nullifier key | `0x06 ‖ domain ‖ spend_key` | 65 | 2 |
| nullifier | `0x03 ‖ nullifier key ‖ occurrence` | 65 | 2 |
| output commitment | `0x02 ‖ inner ‖ value` | 49 | 1 |
| statement digest | `0x08 ‖ nullifier 0 ‖ nullifier 1 ‖ output commitment 0 ‖ output commitment 1 ‖ input[0:136]` | 265 | 5 |

At tree level `i`, the current node is the right child when bit `i` of `index` is 1 and the left child otherwise. A spend makes 55 SHA-256 calls, 105 compressions in total, 40 of the calls for the two Merkle paths. The last 136 bytes of the statement message are the input's first 136 bytes: root, domain, public amount, fee, recipient and authorizer.

### Rules

| Code | Rule |
|---:|---|
| 0 | The input is exactly 1,680 bytes. |
| 1 | Each input note's `index` is below 2^20. |
| 2 | For each input note with nonzero value, the Merkle path from its commitment leads to `root`. |
| 3 | The two input values do not sum to zero. |
| 4 | The input values sum to the output values plus `public_amount` plus `fee`, computed without wraparound. |
| 5 | An output with value zero has `inner` equal to 1 if it is the first output and 2 if it is the second, as 32-byte words. |
| 6 | An output with nonzero value has `inner` other than 1 and 2. |
| 7 | `authorizer` is not zero. |
| 8 | `recipient` is zero exactly when `public_amount` is zero. |
| 9 | The two nullifiers differ. |
| 10 | The two output commitments differ. |

The [Python oracle](oracle/spend_sha256.py) and the [Rust reference](statement/src/lib.rs) define the statement executably and agree on every test case.

## Scoring

### Correctness

An entry is scored only if it passes both sets of tests:

1. The 59 [public test cases](fixtures/public.json): it returns the expected digest for each of the 20 valid inputs and does not return for any of the 39 invalid inputs, each of which breaks exactly one rule.
2. New test cases generated from fresh random seeds at scoring time: random valid spends and a regenerated set of invalid inputs.

The invalid cases cover every rule: removing any one rule check from any of the three entries makes at least one public case fail.

### Score

The score is the largest RV64IM cycle count over all valid test cases, as counted by the fixed leanVM executor. Lower is better. The padded trace size must be the same for every valid input, because the proof reveals it; otherwise the entry is rejected. Taking the largest count means that shortcuts on private data, such as skipping a dummy note's path, never lower the score. Contract size limits do not apply, because the bytecode is a proved program and is never deployed.

### Fixed setup

An entry changes only its bytecode. The rest is fixed:

- **Interpreter:** `revm-interpreter` 43.0.0 with Cancun rules, a 30 million gas limit and a 1 MiB memory limit, patched only to build for RV64IM ([patches](engine/vendor/README.md)). It is fixed so that entries compete on their bytecode; faster interpreters are measured separately in [RESULTS.md](RESULTS.md#faster-interpreters) and do not change the score.
- **External calls:** only `STATICCALL` to the SHA-256 precompile at `0x02`, charged mainnet gas (60 plus 12 per 32-byte word) and computed with the same `sha2` 0.10.9 code as the RISC-V reference. Storage, logs, environment reads, value transfers and contract creation are rejected.
- **Machine:** leanVM, `riscv-exploration` branch at [`1096dedf`](https://github.com/leanEthereum/leanVM/tree/1096dedfbe29c72cfff2a2d8d8b420e6ff0d9f2d), RV64IM, with the [guest runtime](guests/runtime/src/lib.rs) and Rust `nightly-2026-09-17`.
- **Hashing:** base RV64IM instructions only on both sides, with no custom hash instruction.

## Reference results

| Program | Cycles | vs RISC-V | Gas |
|---|---:|---:|---:|
| RISC-V reference (Rust) | 460,471 | 1.00 | |
| [Solidity baseline](evm/src/SpendSha256.sol) | 1,225,610 | 2.66 | 41,075 |
| [Optimized Yul entry](evm/yul/generate.py) | 625,721 | 1.36 | 14,658 |
| [Hand-written bytecode entry](evm/bytecode/generate.py) | 615,971 | 1.34 | 14,559 |

Gas is reported for comparison with gas-scored challenges such as precompile.fast; it does not enter the score. [RESULTS.md](RESULTS.md) has the full measurements: control programs, where the cycles go, gas, proof times, the same programs under faster interpreters, and a BLAKE2s edition with and without leanVM's hash instruction.

## Provers and zero knowledge

Entries are EVM bytecode, so they do not depend on a particular prover. Other RISC-V zkVMs can prove both versions on the same machine to compare proof times, through an adapter that runs the same two programs, but the score comes only from the fixed leanVM executor. Compare the two versions only on the same prover and hardware. Many zkVMs use 32-bit RISC-V while this machine is 64-bit, so their cycle counts differ.

No separate zero-knowledge EVM prover is needed: an EVM interpreter proved by a RISC-V zkVM with zero knowledge is one. Final proof timings should use zero knowledge, since wallets will prove that way. Jolt supports it; the fixed leanVM version does not yet.

## Before launch

- **Threshold:** what counts as close enough, stated as proof time and peak memory with zero knowledge on a named laptop.
- **Hidden seeds:** how they are chosen after submission, for example from a later block hash.
- **Other zkVMs:** whether they contribute to the score or only to timing.
- **Interpreter round:** whether a second round lets entrants change the interpreter instead of the bytecode, with the parity and random-program tests against REVM in [RESULTS.md](RESULTS.md#checks) as the correctness gate, plus Ethereum's execution tests for any opcode those do not reach.
- **Hosting:** where the challenge runs, for example [Yukon](https://www.yukon.org/create) like [precompile.fast](https://www.yukon.org/precompile), and any recognition for entrants.
