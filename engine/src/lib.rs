//! A pure EVM function, executed by the pinned upstream REVM interpreter, with
//! one external call: STATICCALL to the SHA-256 precompile at address 0x02.
//!
//! The caller supplies runtime bytecode and calldata. This is not a
//! transaction processor: storage, logs, external environment reads, value
//! calls, creation and calls to any other address are rejected. Execution uses
//! Cancun rules, a fixed gas cap and a fixed EVM memory cap. The precompile
//! charges mainnet gas (60 + 12 per word) and uses the same portable `sha2`
//! code as the direct RISC-V statement.
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use revm_interpreter::{
    bytecode::Bytecode,
    host::DummyHost,
    instructions::{gas_table_spec, instruction_table},
    interpreter::{EthInterpreter, ExtBytecode},
    interpreter_types::ReturnData,
    primitives::{hardfork::SpecId, Address, Bytes, U256},
    CallInput, CallScheme, FrameInput, InputsImpl, Instruction, InstructionResult, Interpreter,
    InterpreterAction, SharedMemory,
};
use sha2::{Digest, Sha256};

pub const EVM_FORK: SpecId = SpecId::CANCUN;
pub const GAS_LIMIT: u64 = 30_000_000;
pub const MEMORY_LIMIT: u64 = 1 << 20;
pub const SHA256_PRECOMPILE: Address = Address::with_last_byte(2);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// STOP or an empty RETURN is not an affirmative result.
    MissingReturn,
    /// REVERT, with its revert data.
    Revert(Vec<u8>),
    /// Invalid opcode, rejected context access, gas or memory limits.
    Halt(InstructionResult),
    /// A call to anything other than the SHA-256 precompile, or a create.
    UnsupportedFrame,
}

/// SHA-256 precompile semantics: returns None when the call's gas is short.
fn sha256_precompile(input: &[u8], gas_limit: u64) -> Option<(u64, [u8; 32])> {
    let cost = 60 + 12 * (input.len() as u64).div_ceil(32);
    (cost <= gas_limit).then(|| (cost, Sha256::digest(input).into()))
}

pub fn execute(bytecode: &[u8], calldata: &[u8]) -> Result<Vec<u8>, Error> {
    let mut interpreter = Interpreter::<EthInterpreter>::new(
        SharedMemory::new_with_memory_limit(MEMORY_LIMIT),
        ExtBytecode::new(Bytecode::new_raw(Bytes::copy_from_slice(bytecode))),
        InputsImpl {
            input: CallInput::Bytes(Bytes::copy_from_slice(calldata)),
            ..Default::default()
        },
        true,
        EVM_FORK,
        GAS_LIMIT,
    );
    let mut table = instruction_table::<EthInterpreter, DummyHost>();
    // Reject external context and side effects at execution, not by scanning
    // bytecode data as if it were instructions. STATICCALL stays enabled; its
    // target is checked below.
    for opcode in [
        0x30, 0x31, 0x32, 0x33, 0x3a, 0x3b, 0x3c, 0x3f, // account/transaction context
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, // block context
        0x54, 0x55, 0x5c, 0x5d, // persistent/transient storage
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, // logs
        0xf0, 0xf1, 0xf2, 0xf4, 0xf5, 0xff, // value calls, create, selfdestruct
    ] {
        table[opcode] = Instruction::unknown();
    }
    let gas_table = gas_table_spec(EVM_FORK);
    let mut host = DummyHost::new(EVM_FORK);
    loop {
        match interpreter.run_plain(&table, &gas_table, &mut host) {
            InterpreterAction::Return(result) => {
                return match result.result {
                    InstructionResult::Return if !result.output.is_empty() => Ok(result.output.to_vec()),
                    InstructionResult::Return | InstructionResult::Stop => Err(Error::MissingReturn),
                    InstructionResult::Revert => Err(Error::Revert(result.output.to_vec())),
                    reason => Err(Error::Halt(reason)),
                };
            }
            InterpreterAction::NewFrame(FrameInput::Call(call))
                if call.scheme == CallScheme::StaticCall && call.bytecode_address == SHA256_PRECOMPILE =>
            {
                let input = match &call.input {
                    CallInput::Bytes(bytes) => bytes.to_vec(),
                    CallInput::SharedBuffer(range) if range.is_empty() => Vec::new(),
                    CallInput::SharedBuffer(range) => interpreter.memory.global_slice_range(range.clone()).to_vec(),
                };
                // Resume the caller exactly as REVM's frame handler does after a
                // precompile: return unused gas, copy output, push success.
                let success = match sha256_precompile(&input, call.gas_limit) {
                    Some((cost, output)) => {
                        interpreter.gas.erase_cost(call.gas_limit - cost);
                        let out = call.return_memory_offset.clone();
                        let copied = out.len().min(output.len());
                        if copied > 0 {
                            interpreter.memory.set(out.start, &output[..copied]);
                        }
                        interpreter.return_data.set_buffer(Bytes::copy_from_slice(&output));
                        1u8
                    }
                    None => {
                        interpreter.return_data.set_buffer(Bytes::new());
                        0u8
                    }
                };
                if !interpreter.stack.push(U256::from(success)) {
                    return Err(Error::Halt(InstructionResult::StackOverflow));
                }
            }
            InterpreterAction::NewFrame(_) => return Err(Error::UnsupportedFrame),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    #[test]
    fn returns_a_word() {
        // PUSH1 42; PUSH0; MSTORE; PUSH1 32; PUSH0; RETURN.
        let result = execute(&[0x60, 42, 0x5f, 0x52, 0x60, 32, 0x5f, 0xf3], &[]).unwrap();
        assert_eq!(result.len(), 32);
        assert_eq!(result[31], 42);
    }

    /// CALLDATACOPY the input to memory 0, STATICCALL 0x02 over it writing 32
    /// bytes at memory 0, then RETURN those 32 bytes and the success flag.
    fn sha256_program(gas: u8) -> Vec<u8> {
        let mut code = vec![
            0x36, 0x5f, 0x5f, 0x37, // CALLDATACOPY(0, 0, CALLDATASIZE)
            0x60, 0x20, 0x5f, // out_len 32, out_offset 0
            0x36, 0x5f, // in_len CALLDATASIZE, in_offset 0
            0x60, 0x02, // address 2
        ];
        code.extend(if gas == 0 { vec![0x5a] } else { vec![0x60, gas] }); // GAS or PUSH1 gas
        code.extend([
            0xfa, // STATICCALL -> success
            0x60, 0x20, 0x52, // MSTORE(32, success)
            0x60, 0x40, 0x5f, 0xf3, // RETURN(0, 64)
        ]);
        code
    }

    #[test]
    fn calls_the_sha256_precompile() {
        let result = execute(&sha256_program(0), b"abc").unwrap();
        let expected: [u8; 32] = Sha256::digest(b"abc").into();
        assert_eq!(&result[..32], &expected);
        assert_eq!(result[63], 1);
        // 65 bytes cost 60 + 12 * 3 = 96 gas: 95 fails without output, 96 succeeds.
        let message = [7u8; 65];
        let failed = execute(&sha256_program(95), &message).unwrap();
        assert_eq!(failed[63], 0);
        assert_eq!(&failed[..32], &message[..32], "a failed call must not write output");
        assert_eq!(execute(&sha256_program(96), &message).unwrap()[63], 1);
    }

    #[test]
    fn rejects_other_calls_reverts_and_state_access() {
        let mut other = sha256_program(0);
        other[10] = 0x03; // RIPEMD-160 precompile address
        assert_eq!(execute(&other, b"abc"), Err(Error::UnsupportedFrame));
        assert_eq!(execute(&[0x00], &[]), Err(Error::MissingReturn));
        assert_eq!(execute(&[0x5f, 0x5f, 0xfd], &[]), Err(Error::Revert(Vec::new())));
        assert!(matches!(execute(&[0x5f, 0x54, 0x00], &[]), Err(Error::Halt(_))));
        assert!(matches!(execute(&[0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0xf1], &[]), Err(Error::Halt(_))));
    }
}
