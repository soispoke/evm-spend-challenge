//! Count the EVM instructions a candidate executes on one case, using the same
//! interpreter settings and SHA-256 precompile as the scoring harness.
//! Host-side diagnostics only; the scored guest is unchanged.
//!
//! cargo run --release --offline -p spend-challenge --example opcode_profile -- BYTECODE_HEX FIXTURES CASE
use std::{env, fs};

use revm_interpreter::{
    bytecode::{opcode::OpCode, Bytecode},
    host::DummyHost,
    instructions::{gas_table_spec, instruction_table},
    interpreter::{EthInterpreter, ExtBytecode},
    interpreter_types::{Jumps, LoopControl, ReturnData},
    primitives::{Address, Bytes, U256},
    CallInput, CallScheme, FrameInput, InputsImpl, Instruction, Interpreter, InterpreterAction,
    SharedMemory,
};
use sha2::{Digest, Sha256};

fn unhex(text: &str) -> Vec<u8> {
    let text = text.trim();
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let bytecode = unhex(&fs::read_to_string(&args[1]).unwrap());
    let fixtures: serde_json::Value = serde_json::from_str(&fs::read_to_string(&args[2]).unwrap()).unwrap();
    let case = fixtures["cases"].as_array().unwrap().iter().find(|c| c["name"] == args[3].as_str()).unwrap();
    let calldata = unhex(case["input"].as_str().unwrap());

    let spec = spend_evm_engine::EVM_FORK;
    let mut interpreter = Interpreter::<EthInterpreter>::new(
        SharedMemory::new_with_memory_limit(spend_evm_engine::MEMORY_LIMIT),
        ExtBytecode::new(Bytecode::new_raw(Bytes::copy_from_slice(&bytecode))),
        InputsImpl { input: CallInput::Bytes(Bytes::copy_from_slice(&calldata)), ..Default::default() },
        true,
        spec,
        spend_evm_engine::GAS_LIMIT,
    );
    let mut table = instruction_table::<EthInterpreter, DummyHost>();
    for opcode in [0x30, 0x31, 0x32, 0x33, 0x3a, 0x3b, 0x3c, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
        0x47, 0x48, 0x49, 0x4a, 0x54, 0x55, 0x5c, 0x5d, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xf0, 0xf1, 0xf2, 0xf4,
        0xf5, 0xff] {
        table[opcode] = Instruction::unknown();
    }
    let gas_table = gas_table_spec(spec);
    let mut host = DummyHost::new(spec);
    let mut counts = [0u64; 256];
    let mut peak_memory = 0usize;
    let output = loop {
        let error = loop {
            counts[interpreter.bytecode.opcode() as usize] += 1;
            if let Err(error) = interpreter.step(&table, &gas_table, &mut host) {
                break error;
            }
            peak_memory = peak_memory.max(interpreter.memory.len());
        };
        if interpreter.bytecode.action().is_none() {
            interpreter.halt(error);
        }
        match interpreter.take_next_action() {
            InterpreterAction::Return(result) => break result,
            InterpreterAction::NewFrame(FrameInput::Call(call))
                if call.scheme == CallScheme::StaticCall && call.bytecode_address == Address::with_last_byte(2) =>
            {
                let input = match &call.input {
                    CallInput::Bytes(bytes) => bytes.to_vec(),
                    CallInput::SharedBuffer(range) if range.is_empty() => Vec::new(),
                    CallInput::SharedBuffer(range) => interpreter.memory.global_slice_range(range.clone()).to_vec(),
                };
                let cost = 60 + 12 * (input.len() as u64).div_ceil(32);
                assert!(cost <= call.gas_limit);
                interpreter.gas.erase_cost(call.gas_limit - cost);
                let digest: [u8; 32] = Sha256::digest(&input).into();
                let out = call.return_memory_offset.clone();
                let copied = out.len().min(32);
                if copied > 0 {
                    interpreter.memory.set(out.start, &digest[..copied]);
                }
                interpreter.return_data.set_buffer(Bytes::copy_from_slice(&digest));
                assert!(interpreter.stack.push(U256::from(1)));
            }
            other => panic!("unexpected action {other:?}"),
        }
    };
    let mut named: Vec<(String, u64)> = counts.iter().enumerate().filter(|(_, n)| **n > 0)
        .map(|(op, n)| (OpCode::new(op as u8).map_or(format!("0x{op:02x}"), |o| o.as_str().to_owned()), *n)).collect();
    named.sort_by(|a, b| b.1.cmp(&a.1));
    println!("{}", serde_json::json!({
        "case": args[3], "result": format!("{:?}", output.result), "output": output.output.to_string(),
        "instructions": counts.iter().sum::<u64>(), "gas_used": output.gas.spent(),
        "peak_memory_bytes": peak_memory, "opcodes": named,
    }));
}
