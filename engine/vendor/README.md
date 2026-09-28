# REVM portability patches

## TL;DR

Three REVM 43 crates are vendored so the pinned `revm-interpreter` builds for leanVM's RV64IM target, which has no atomic instructions. The changes swap pointer atomics for portable ones; opcode behavior, gas rules and hashing are upstream code.

## Changes

| Crate | Version | Change |
|---|---|---|
| `revm-bytecode` | 43.0.0 | Use `portable-atomic-util::Arc` when pointer atomics are unavailable. |
| `revm-database-interface` | 43.0.0 | The same `Arc` substitution; omit unused `alloc::sync::Arc` trait wrappers on those targets. |
| `revm-context-interface` | 43.0.1 | The same substitutions; box the dynamically typed error before building its `Arc`. |

Both Cargo workspaces patch these crates through `[patch.crates-io]`. The guest runtime supplies a no-op critical section, which is correct only because leanVM runs one hart without interrupts. Each crate keeps its upstream license.
