//! The BLAKE2s edition of the statement on leanVM, in every combination the
//! comparison needs. The direct RISC-V program computes BLAKE2s either with the
//! base instruction set only or with leanVM's `blake2s` instruction. The EVM
//! entry (embedded from bytecode.bin) runs under REVM, the interpreter written
//! for proving, or compiled ahead of time (compiled_program.rs), and its
//! BLAKE2s precompile at 0xb2 is served either in software or with the same
//! instruction.
#![no_std]
extern crate alloc;

use spend_evm_interpreters::{HashPrecompile, BLAKE2S_ADDRESS};
use spend_sha256::StatementHash;

pub use spend_evm_interpreters::Blake2sPrecompile as SoftwarePrecompile;
pub use spend_sha256::Blake2sHash as SoftwareHash;

/// BLAKE2s through leanVM's `blake2s` instruction, as the statement's hash.
pub struct InstructionHash;

impl StatementHash for InstructionHash {
    fn digest(message: &[u8]) -> [u8; 32] {
        leanvm_guest::Blake2s::hash(message)
    }
}

/// The BLAKE2s precompile at 0xb2, served with leanVM's `blake2s` instruction.
pub struct InstructionPrecompile;

impl HashPrecompile for InstructionPrecompile {
    const ADDRESS: u8 = BLAKE2S_ADDRESS;
    fn hash(input: &[u8]) -> [u8; 32] {
        leanvm_guest::Blake2s::hash(input)
    }
}

pub fn finish(result: Result<alloc::vec::Vec<u8>, spend_evm_interpreters::Error>) {
    spend_runtime::finish(result.unwrap().as_slice().try_into().unwrap());
}
