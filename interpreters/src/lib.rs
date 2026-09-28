//! Faster EVM interpreters for the challenge harness, used to measure how much
//! of the EVM's proving cost comes from the interpreter rather than from the
//! entry's bytecode.
//!
//! Each follows the rules of the scoring harness in `spend-evm-engine`:
//! Cancun, a 30 million gas limit, a 1 MiB memory limit and only `STATICCALL`
//! to the SHA-256 precompile. The parity checks in `host/examples` compare
//! them with a REVM reference on the test cases and on random programs,
//! including gas. The challenge itself still scores with the harness. This is
//! research code.
#![no_std]
extern crate alloc;

use alloc::vec::Vec;
pub use spend_evm_engine::{Error, GAS_LIMIT, MEMORY_LIMIT};

pub mod fast;
pub mod reference;
pub mod revm_direct;
pub mod support;

// Items the ahead-of-time compiled programs use (`interpreters/compile.py`).
pub use revm_interpreter::{
    instructions::i256::{i256_cmp, i256_div, i256_mod},
    primitives::{keccak256, KECCAK_EMPTY, U256},
    InstructionResult,
};
pub use sha2::{Digest, Sha256};

/// The result of running a program, with the gas left. After an exceptional
/// halt all gas is consumed, so `gas_left` is zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub result: Result<Vec<u8>, Error>,
    pub gas_left: u64,
}

/// SHA-256 precompile gas: 60 plus 12 per 32-byte word.
pub fn sha256_cost(len: usize) -> u64 {
    60 + 12 * (len as u64).div_ceil(32)
}

/// The hash precompile an interpreter serves: the last byte of its address
/// (the other 19 are zero), its gas and its hash. The scoring harness serves
/// SHA-256 at `0x02`. The BLAKE2s edition measures a hypothetical BLAKE2s
/// precompile at `0xb2`, priced like SHA-256.
pub trait HashPrecompile {
    const ADDRESS: u8;
    fn hash(input: &[u8]) -> [u8; 32];
    #[inline(always)]
    fn cost(len: usize) -> u64 {
        sha256_cost(len)
    }
}

/// SHA-256 at `0x02`, as in the harness.
pub struct Sha256Precompile;

impl HashPrecompile for Sha256Precompile {
    const ADDRESS: u8 = 2;
    #[inline(always)]
    fn hash(input: &[u8]) -> [u8; 32] {
        Sha256::digest(input).into()
    }
}

pub const BLAKE2S_ADDRESS: u8 = 0xb2;

/// BLAKE2s-256 at `0xb2`, computed in software with the BLAKE2s edition's own
/// code. A leanVM guest can serve the same address with the machine's
/// `blake2s` instruction instead.
pub struct Blake2sPrecompile;

impl HashPrecompile for Blake2sPrecompile {
    const ADDRESS: u8 = BLAKE2S_ADDRESS;
    fn hash(input: &[u8]) -> [u8; 32] {
        spend_sha256::blake2s::hash(input)
    }
}
