//! Check the faster interpreters against the scoring harness on the test cases
//! and report each program's gas.
//!
//! For every program and case it runs the harness (`spend_evm_engine`), the
//! REVM reference that also reports gas, REVM with the direct SHA-256 call and
//! the purpose-built interpreter. The reference must match the harness exactly;
//! the other two must match the reference's result and gas left, with any
//! exceptional halt counting as the same result.
//!
//! cargo run --release --offline -p spend-challenge --example interpreter_parity -- \
//!     --fixtures fixtures/public.json [--fixtures MORE.json] --program NAME=BYTECODE_HEX ...
use std::{env, fs, process::ExitCode};

use serde_json::{Value, json};
use spend_evm_interpreters::{Error, GAS_LIMIT, Outcome, fast, reference, revm_direct};

fn unhex(text: &str) -> Vec<u8> {
    let text = text.trim();
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

/// Exceptional halts differ only in the reported reason, which is not observable.
fn class(outcome: &Outcome) -> (Result<Vec<u8>, String>, u64) {
    let result = match &outcome.result {
        Ok(output) => Ok(output.clone()),
        Err(Error::Halt(_)) => Err("halt".to_owned()),
        Err(other) => Err(format!("{other:?}")),
    };
    (result, outcome.gas_left)
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut fixtures = Vec::new();
    let mut programs = Vec::new();
    for pair in args.chunks(2) {
        match pair[0].as_str() {
            "--fixtures" => fixtures.push(pair[1].clone()),
            "--program" => {
                let (name, path) = pair[1].split_once('=').unwrap();
                programs.push((name.to_owned(), unhex(&fs::read_to_string(path).unwrap())));
            }
            other => panic!("unknown flag {other}"),
        }
    }
    let mut cases = Vec::new();
    for path in &fixtures {
        let file: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        cases.extend(file["cases"].as_array().unwrap().iter().cloned());
    }
    let mut report = Vec::new();
    let mut all_match = true;
    for (name, code) in &programs {
        let mut mismatches = Vec::new();
        let mut gas_used = Vec::new();
        for case in &cases {
            let input = unhex(case["input"].as_str().unwrap());
            let harness = spend_evm_engine::execute(code, &input);
            let expected = reference::run(code, &input, GAS_LIMIT);
            let direct = revm_direct::run(code, &input, GAS_LIMIT);
            let purpose_built = fast::run(code, &input, GAS_LIMIT);
            let case_name = case["name"].as_str().unwrap();
            if harness != expected.result {
                mismatches.push(json!({"case": case_name, "interpreter": "reference",
                    "harness": format!("{harness:?}"), "got": format!("{:?}", expected.result)}));
            }
            if direct != expected {
                mismatches.push(json!({"case": case_name, "interpreter": "revm-direct",
                    "expected": format!("{expected:?}"), "got": format!("{direct:?}")}));
            }
            if class(&purpose_built) != class(&expected) {
                mismatches.push(json!({"case": case_name, "interpreter": "fast",
                    "expected": format!("{expected:?}"), "got": format!("{purpose_built:?}")}));
            }
            if expected.result.is_ok() {
                gas_used.push(GAS_LIMIT - expected.gas_left);
            }
        }
        all_match &= mismatches.is_empty();
        report.push(json!({"program": name, "bytecode_bytes": code.len(), "cases": cases.len(),
            "returned": gas_used.len(), "gas_used_max": gas_used.iter().max(), "gas_used_min": gas_used.iter().min(),
            "mismatches": mismatches}));
    }
    println!("{}", serde_json::to_string_pretty(&json!({"all_match": all_match, "programs": report})).unwrap());
    if all_match { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
