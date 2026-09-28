//! The scoring harness's REVM execution with a chosen gas limit, reporting the
//! gas left. The code matches `spend_evm_engine::execute`, which fixes the gas
//! limit and does not report gas; the parity checks confirm that the two agree
//! at the harness gas limit.

use alloc::vec::Vec;
use revm_interpreter::{
    bytecode::Bytecode,
    host::DummyHost,
    instructions::{gas_table_spec, instruction_table},
    interpreter::{EthInterpreter, ExtBytecode},
    interpreter_types::ReturnData,
    primitives::{Bytes, U256},
    CallInput, CallScheme, FrameInput, InputsImpl, Instruction, InstructionResult, Interpreter,
    InterpreterAction, SharedMemory,
};
use revm_interpreter::primitives::Address;
use spend_evm_engine::{EVM_FORK, MEMORY_LIMIT};

use crate::{Error, HashPrecompile, Outcome, Sha256Precompile};

/// Opcodes the harness rejects: external context and side effects.
pub const DISABLED: [u8; 34] = [
    0x30, 0x31, 0x32, 0x33, 0x3a, 0x3b, 0x3c, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4a, 0x54, 0x55, 0x5c, 0x5d, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xf0, 0xf1, 0xf2, 0xf4, 0xf5, 0xff,
];

pub fn run(bytecode: &[u8], calldata: &[u8], gas_limit: u64) -> Outcome {
    run_with::<Sha256Precompile>(bytecode, calldata, gas_limit)
}

/// `run` with `P` as the hash precompile, handled where the harness handles 0x02.
pub fn run_with<P: HashPrecompile>(bytecode: &[u8], calldata: &[u8], gas_limit: u64) -> Outcome {
    let mut interpreter = Interpreter::<EthInterpreter>::new(
        SharedMemory::new_with_memory_limit(MEMORY_LIMIT),
        ExtBytecode::new(Bytecode::new_raw(Bytes::copy_from_slice(bytecode))),
        InputsImpl { input: CallInput::Bytes(Bytes::copy_from_slice(calldata)), ..Default::default() },
        true,
        EVM_FORK,
        gas_limit,
    );
    let mut table = instruction_table::<EthInterpreter, DummyHost>();
    for opcode in DISABLED {
        table[opcode as usize] = Instruction::unknown();
    }
    let gas_table = gas_table_spec(EVM_FORK);
    let mut host = DummyHost::new(EVM_FORK);
    loop {
        match interpreter.run_plain(&table, &gas_table, &mut host) {
            InterpreterAction::Return(result) => {
                let gas_left = result.gas.remaining();
                let (result, gas_left) = match result.result {
                    InstructionResult::Return if !result.output.is_empty() => (Ok(result.output.to_vec()), gas_left),
                    InstructionResult::Return | InstructionResult::Stop => (Err(Error::MissingReturn), gas_left),
                    InstructionResult::Revert => (Err(Error::Revert(result.output.to_vec())), gas_left),
                    reason => (Err(Error::Halt(reason)), 0),
                };
                return Outcome { result, gas_left };
            }
            InterpreterAction::NewFrame(FrameInput::Call(call))
                if call.scheme == CallScheme::StaticCall && call.bytecode_address == Address::with_last_byte(P::ADDRESS) =>
            {
                let input = match &call.input {
                    CallInput::Bytes(bytes) => bytes.to_vec(),
                    CallInput::SharedBuffer(range) if range.is_empty() => Vec::new(),
                    CallInput::SharedBuffer(range) => interpreter.memory.global_slice_range(range.clone()).to_vec(),
                };
                let cost = P::cost(input.len());
                let success = if cost <= call.gas_limit {
                    interpreter.gas.erase_cost(call.gas_limit - cost);
                    let output: [u8; 32] = P::hash(&input);
                    let out = call.return_memory_offset.clone();
                    let copied = out.len().min(output.len());
                    if copied > 0 {
                        interpreter.memory.set(out.start, &output[..copied]);
                    }
                    interpreter.return_data.set_buffer(Bytes::copy_from_slice(&output));
                    1u8
                } else {
                    interpreter.return_data.set_buffer(Bytes::new());
                    0u8
                };
                if !interpreter.stack.push(U256::from(success)) {
                    return Outcome { result: Err(Error::Halt(InstructionResult::StackOverflow)), gas_left: 0 };
                }
            }
            InterpreterAction::NewFrame(_) => return Outcome { result: Err(Error::UnsupportedFrame), gas_left: 0 },
        }
    }
}
