//! Count how many times leanVM executes each instruction of a guest on one
//! case. Prints one JSON object: the total, the program's output and the count
//! per instruction address. `scripts/profile.py` groups the counts by function.
//!
//! cargo run --release --offline -p spend-challenge --example cycle_profile -- ELF FIXTURES CASE
use std::{collections::BTreeMap, env, fs};

use leanvm::Program;

fn unhex(text: &str) -> Vec<u8> {
    let text = text.trim();
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = Program::from_elf(&fs::read(&args[1]).unwrap()).unwrap();
    let fixtures: serde_json::Value = serde_json::from_str(&fs::read_to_string(&args[2]).unwrap()).unwrap();
    let case = fixtures["cases"].as_array().unwrap().iter().find(|c| c["name"] == args[3].as_str()).unwrap();
    let input = unhex(case["input"].as_str().unwrap());
    let digest = unhex(case["digest"].as_str().unwrap_or(&"00".repeat(32)));
    let words = |bytes: &[u8]| -> Vec<u64> {
        bytes.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect()
    };
    // Controls return other digests; the public input only matters for the final check.
    let public: [u64; 4] = words(&digest).try_into().unwrap();
    let mut machine = lean_vm::rv::Machine::new(&program.rv, public, &words(&input));
    let mut counts: BTreeMap<u64, u64> = BTreeMap::new();
    let mut total = 0u64;
    while !machine.halted() {
        match machine.step() {
            Ok(step) => {
                *counts.entry(program.rv.pc_of(step.index)).or_default() += 1;
                total += 1;
            }
            Err(error) => {
                eprintln!("stopped: {error}");
                break;
            }
        }
    }
    // The program's output, as little-endian bytes in hex, when it halted normally.
    let output = machine.halted().then(|| machine.run(1).ok()).flatten().map(|words| {
        words.iter().flat_map(|w| w.to_le_bytes()).map(|b| format!("{b:02x}")).collect::<String>()
    });
    let counts: BTreeMap<String, u64> = counts.into_iter().map(|(pc, n)| (format!("{pc:x}"), n)).collect();
    println!("{}", serde_json::json!({"total": total, "output": output, "counts": counts}));
}
