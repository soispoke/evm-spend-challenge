//! The harness's REVM interpreter with one change: a `STATICCALL` to the
//! SHA-256 precompile is computed inside the call instruction, hashing EVM
//! memory in place and writing the digest back, instead of leaving the
//! interpreter loop through a new call frame and copying the input out. Every
//! other instruction, and every gas rule, is REVM's.

use alloc::boxed::Box;
use revm_interpreter::{
    bytecode::{opcode::STATICCALL, Bytecode},
    host::DummyHost,
    instructions::{
        contract::{get_memory_input_and_out_ranges, load_acc_and_calc_gas},
        gas_table_spec, instruction_table,
        utility::IntoAddress,
    },
    interpreter::{EthInterpreter, ExtBytecode},
    interpreter_types::{InputsTr, LoopControl, ReturnData},
    primitives::{Bytes, U256},
    CallInput, CallInputs, CallScheme, CallValue, FrameInput, InputsImpl, Instruction, InstructionContext,
    Host, InstructionExecResult, InstructionResult, Interpreter, InterpreterAction, SharedMemory,
};
use sha2::{Digest, Sha256};
use spend_evm_engine::{EVM_FORK, GAS_LIMIT, MEMORY_LIMIT, SHA256_PRECOMPILE};

use crate::{reference::DISABLED, sha256_cost, Error, Outcome};

pub fn execute(bytecode: &[u8], calldata: &[u8]) -> Result<alloc::vec::Vec<u8>, Error> {
    run(bytecode, calldata, GAS_LIMIT).result
}

pub fn run(bytecode: &[u8], calldata: &[u8], gas_limit: u64) -> Outcome {
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
    table[STATICCALL as usize] = Instruction::new(static_call);
    let gas_table = gas_table_spec(EVM_FORK);
    let mut host = DummyHost::new(EVM_FORK);
    match interpreter.run_plain(&table, &gas_table, &mut host) {
        InterpreterAction::Return(result) => {
            let gas_left = result.gas.remaining();
            let (result, gas_left) = match result.result {
                InstructionResult::Return if !result.output.is_empty() => (Ok(result.output.to_vec()), gas_left),
                InstructionResult::Return | InstructionResult::Stop => (Err(Error::MissingReturn), gas_left),
                InstructionResult::Revert => (Err(Error::Revert(result.output.to_vec())), gas_left),
                reason => (Err(Error::Halt(reason)), 0),
            };
            Outcome { result, gas_left }
        }
        // Only calls to other addresses leave the loop.
        InterpreterAction::NewFrame(_) => Outcome { result: Err(Error::UnsupportedFrame), gas_left: 0 },
    }
}

/// REVM's `STATICCALL` up to the gas it forwards, then the SHA-256 precompile
/// in place. Calls to any other address are handed out as a new frame, as
/// REVM does, and rejected by `run`.
fn static_call(mut context: InstructionContext<'_, DummyHost, EthInterpreter>) -> InstructionExecResult {
    revm_interpreter::popn!([local_gas_limit, to], context.interpreter);
    let to = to.into_address();
    let local_gas_limit = u64::try_from(local_gas_limit).unwrap_or(u64::MAX);
    let (input, return_memory_offset) =
        get_memory_input_and_out_ranges(context.interpreter, context.host.gas_params())?;
    let (gas_limit, bytecode, bytecode_hash, charged_new_account_state_gas) =
        load_acc_and_calc_gas(&mut context, to, false, false, local_gas_limit)?;
    let interpreter = context.interpreter;
    if to != SHA256_PRECOMPILE {
        interpreter.bytecode.set_action(InterpreterAction::NewFrame(FrameInput::Call(Box::new(CallInputs {
            input: CallInput::SharedBuffer(input),
            gas_limit,
            target_address: to,
            caller: interpreter.input.target_address(),
            bytecode_address: to,
            known_bytecode: (bytecode_hash, bytecode),
            value: CallValue::Transfer(U256::ZERO),
            scheme: CallScheme::StaticCall,
            is_static: true,
            return_memory_offset,
            reservoir: interpreter.gas.reservoir(),
            charged_new_account_state_gas,
        }))));
        return Err(InstructionResult::Suspend);
    }
    let cost = sha256_cost(input.len());
    let success = if cost <= gas_limit {
        interpreter.gas.erase_cost(gas_limit - cost);
        let digest: [u8; 32] = if input.is_empty() {
            Sha256::digest([]).into()
        } else {
            Sha256::digest(&*interpreter.memory.global_slice_range(input)).into()
        };
        let copied = return_memory_offset.len().min(32);
        if copied > 0 {
            interpreter.memory.set(return_memory_offset.start, &digest[..copied]);
        }
        interpreter.return_data.set_buffer(Bytes::copy_from_slice(&digest));
        true
    } else {
        interpreter.return_data.set_buffer(Bytes::new());
        false
    };
    revm_interpreter::push!(interpreter, U256::from(success));
    Ok(())
}
