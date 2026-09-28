//! Check the ahead-of-time compiled programs against the REVM reference on the
//! test cases, including gas. Generate them first with
//! scripts/compile_programs.py.
//!
//! cargo run --release --offline -p spend-challenge --example compiled_parity -- FIXTURES...
extern crate alloc;

use std::{env, fs, process::ExitCode};

use serde_json::{Value, json};
use spend_evm_interpreters::{Error, GAS_LIMIT, Outcome, reference};

macro_rules! programs {
    ($($name:ident => $hex:literal),*) => {
        $(mod $name {
            include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../target/compiled/", stringify!($name), ".rs"));
        })*
        fn all() -> Vec<(&'static str, &'static str, fn(&[u8], u64) -> Outcome)> {
            vec![$((stringify!($name), $hex, $name::run as fn(&[u8], u64) -> Outcome)),*]
        }
    };
}

programs!(solidity => "evm/baseline.hex", yul => "evm/yul/bytecode.hex", bytecode => "evm/bytecode/bytecode.hex",
          calls_55 => "evm/controls/calls-55.hex", calls_0 => "evm/controls/calls-0.hex");

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
    let mut report = Vec::new();
    let mut all_match = true;
    for (name, hex_path, run) in all() {
        let code = unhex(&fs::read_to_string(format!("{root}/{hex_path}")).unwrap());
        let mut mismatches = Vec::new();
        let limits = [GAS_LIMIT, 20_000, 12_000, 5_000, 300];
        for case in &cases {
            let input = unhex(case["input"].as_str().unwrap());
            // Also at small gas limits, so that some runs end out of gas.
            for gas in limits {
                let expected = reference::run(&code, &input, gas);
                let got = run(&input, gas);
                if class(&got) != class(&expected) {
                    mismatches.push(json!({"case": case["name"], "gas_limit": gas,
                        "expected": format!("{expected:?}"), "got": format!("{got:?}")}));
                }
            }
        }
        all_match &= mismatches.is_empty();
        report.push(json!({"program": name, "runs": cases.len() * limits.len(), "mismatches": mismatches}));
    }
    println!("{}", serde_json::to_string_pretty(&json!({"all_match": all_match, "programs": report})).unwrap());
    if all_match { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
