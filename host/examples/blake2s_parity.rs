//! Check the BLAKE2s edition's EVM entries under every interpreter against
//! REVM with a BLAKE2s precompile at 0xb2, and report their gas. Generate the
//! compiled programs first with scripts/compile_programs.py.
//!
//! For each entry and case it runs the REVM reference, the interpreter written
//! for proving and the compiled program, all serving BLAKE2s at 0xb2 in
//! software. The two must match the reference's result and gas left, with any
//! exceptional halt counting as the same result, and the reference must return
//! the case's digest exactly when the case is valid.
//!
//! cargo run --release --offline -p spend-challenge --example blake2s_parity -- FIXTURES...
extern crate alloc;

use std::{env, fs, process::ExitCode};

use serde_json::{Value, json};
use spend_evm_interpreters::{Blake2sPrecompile, Error, GAS_LIMIT, Outcome, fast, reference};

mod precompile {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../target/compiled/blake2s_precompile.rs"));
}
mod in_evm {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../target/compiled/blake2s_evm.rs"));
}

fn unhex(text: &str) -> Vec<u8> {
    let text = text.trim();
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn class(outcome: &Outcome) -> (Result<Vec<u8>, String>, u64) {
    let result = match &outcome.result {
        Ok(output) => Ok(output.clone()),
        Err(Error::Halt(_)) => Err("halt".to_owned()),
        Err(other) => Err(format!("{other:?}")),
    };
    (result, outcome.gas_left)
}

fn main() -> ExitCode {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    let mut cases = Vec::new();
    for path in env::args().skip(1) {
        let file: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        cases.extend(file["cases"].as_array().unwrap().iter().cloned());
    }
    let entries: [(&str, &str, fn(&[u8], u64) -> Outcome); 2] = [
        ("precompile", "evm/blake2s/precompile.hex", precompile::run_with::<Blake2sPrecompile>),
        ("blake2s-in-evm", "evm/blake2s/bytecode.hex", in_evm::run_with::<Blake2sPrecompile>),
    ];
    let mut report = Vec::new();
    let mut all_match = true;
    for (name, path, compiled) in entries {
        let code = unhex(&fs::read_to_string(format!("{root}/{path}")).unwrap());
        let (mut mismatches, mut gas_used) = (Vec::new(), Vec::new());
        for case in &cases {
            let input = unhex(case["input"].as_str().unwrap());
            let expected = reference::run_with::<Blake2sPrecompile>(&code, &input, GAS_LIMIT);
            let want = case["valid"].as_bool().unwrap().then(|| unhex(case["digest"].as_str().unwrap()));
            let correct = match (&want, &expected.result) {
                (Some(digest), Ok(output)) => output == digest,
                (None, Err(_)) => true,
                _ => false,
            };
            let interpreted = fast::run_with::<Blake2sPrecompile>(&code, &input, GAS_LIMIT);
            let compiled = compiled(&input, GAS_LIMIT);
            let case_name = case["name"].as_str().unwrap();
            if !correct {
                mismatches.push(json!({"case": case_name, "check": "digest", "got": format!("{:?}", expected.result)}));
            }
            if class(&interpreted) != class(&expected) {
                mismatches.push(json!({"case": case_name, "check": "fast", "got": format!("{interpreted:?}")}));
            }
            if class(&compiled) != class(&expected) {
                mismatches.push(json!({"case": case_name, "check": "compiled", "got": format!("{compiled:?}")}));
            }
            if expected.result.is_ok() {
                gas_used.push(GAS_LIMIT - expected.gas_left);
            }
        }
        all_match &= mismatches.is_empty();
        report.push(json!({"entry": name, "bytecode_bytes": code.len(), "cases": cases.len(), "returned": gas_used.len(),
            "gas_used_max": gas_used.iter().max(), "gas_used_min": gas_used.iter().min(), "mismatches": mismatches}));
    }
    println!("{}", serde_json::to_string_pretty(&json!({"all_match": all_match, "entries": report})).unwrap());
    if all_match { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
