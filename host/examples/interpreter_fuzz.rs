//! Differential test of the faster interpreters against the REVM reference on
//! random programs, random calldata and random gas limits.
//!
//! Half the programs are generated from weighted instruction templates that
//! reach memory expansion, copies, the SHA-256 call, return data, jumps, gas
//! exhaustion and every opcode byte; the other half mutate the real entries
//! and controls and run them on test inputs. REVM with the direct SHA-256 call
//! must match the reference exactly, including the halt reason; the
//! purpose-built interpreter must match its result and gas left, with any
//! exceptional halt counting as the same result. Programs starting with 0xEF01
//! are skipped: the harness parses them as EIP-7702 designators and panics.
//! With `--precompile blake2s`, the interpreters serve BLAKE2s at 0xb2 instead,
//! generated calls target 0xb2, and REVM with the direct SHA-256 call is not run.
//!
//! cargo run --release --offline -p spend-challenge --example interpreter_fuzz -- \
//!     --iterations N --seed S --fixtures fixtures/public.json --program BYTECODE_HEX ...
use std::{collections::BTreeMap, env, fs, process::ExitCode};

use serde_json::{Value, json};
use spend_evm_interpreters::{Blake2sPrecompile, Error, Outcome, fast, reference, revm_direct};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // splitmix64
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn unhex(text: &str) -> Vec<u8> {
    let text = text.trim();
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// PUSH a value with the shortest encoding.
fn push(code: &mut Vec<u8>, value: u64) {
    if value == 0 {
        code.push(0x5f);
        return;
    }
    let width = (64 - value.leading_zeros() as usize).div_ceil(8);
    code.push(0x5f + width as u8);
    code.extend_from_slice(&value.to_be_bytes()[8 - width..]);
}

/// A small offset or length, sometimes an extreme one.
fn operand(rng: &mut Rng) -> u64 {
    match rng.below(20) {
        0 => rng.next(),
        1 => (1 << 20) - rng.below(64),
        2 => 1 << 20 | rng.below(64),
        3..=5 => 0,
        _ => rng.below(300),
    }
}

fn push_operand(rng: &mut Rng, code: &mut Vec<u8>) {
    if rng.chance(3) {
        // A value above 64 bits, which offsets and lengths must reject.
        code.push(0x7f);
        let mut word = rng.bytes(32);
        word[0] |= 1;
        code.extend_from_slice(&word);
    } else {
        push(code, operand(rng));
    }
}

fn generate(rng: &mut Rng, address: u8) -> Vec<u8> {
    let target = 1 + rng.below(160) as usize;
    let mut code = Vec::new();
    // Start with a few values so fewer programs stop on an empty stack.
    for _ in 0..rng.below(12) {
        push_operand(rng, &mut code);
    }
    while code.len() < target {
        match rng.below(100) {
            0..=24 => push_operand(rng, &mut code),
            25..=29 => {
                let width = 1 + rng.below(32) as usize;
                code.push(0x5f + width as u8);
                code.extend(rng.bytes(width));
            }
            30..=44 => {
                const OPS: [u8; 25] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x10, 0x11,
                    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d];
                code.push(OPS[rng.below(OPS.len() as u64) as usize]);
            }
            45..=54 => code.push(if rng.chance(50) { 0x80 } else { 0x90 } + rng.below(16) as u8),
            55..=62 => {
                const OPS: [u8; 6] = [0x51, 0x52, 0x53, 0x59, 0x5e, 0x50];
                push_operand(rng, &mut code);
                code.push(OPS[rng.below(6) as usize]);
            }
            63..=67 => {
                const OPS: [u8; 5] = [0x35, 0x36, 0x37, 0x38, 0x39];
                code.push(OPS[rng.below(5) as usize]);
            }
            68..=73 => {
                // STATICCALL(gas, to, in_offset, in_len, out_offset, out_len)
                for _ in 0..4 {
                    push_operand(rng, &mut code);
                }
                match rng.below(10) {
                    0 => push(&mut code, rng.below(8)),
                    1 => {
                        // Low 20 bytes are 0x02, higher bytes are not zero.
                        code.push(0x7f);
                        let mut word = rng.bytes(12);
                        word.extend([0u8; 19]);
                        word.push(address);
                        code.extend(word);
                    }
                    _ => push(&mut code, address as u64),
                }
                if rng.chance(70) { code.push(0x5a) } else { push(&mut code, rng.below(400)) }
                code.push(0xfa);
            }
            74..=77 => {
                push_operand(rng, &mut code);
                code.push(if rng.chance(50) { 0x3d } else { 0x3e });
            }
            78..=82 => {
                const OPS: [u8; 6] = [0x20, 0x0a, 0x5a, 0x58, 0x34, 0x5b];
                code.push(OPS[rng.below(6) as usize]);
            }
            83..=88 => {
                // A jump to a random position, often a JUMPDEST.
                push(&mut code, rng.below(target as u64 + 8));
                code.push(if rng.chance(50) { 0x56 } else { 0x57 });
                if rng.chance(60) {
                    code.push(0x5b);
                }
            }
            89..=93 => {
                push_operand(rng, &mut code);
                push_operand(rng, &mut code);
                code.push(match rng.below(4) { 0 => 0xfd, 1 => 0x00, _ => 0xf3 });
            }
            _ => code.push(rng.next() as u8),
        }
    }
    code
}

fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut code = base.to_vec();
    for _ in 0..1 + rng.below(4) {
        let at = rng.below(code.len() as u64) as usize;
        match rng.below(3) {
            0 => code[at] = rng.next() as u8,
            1 => code[at] ^= 1 << rng.below(8),
            _ => code.truncate(at.max(1)),
        }
    }
    code
}

fn gas_limit(rng: &mut Rng) -> u64 {
    match rng.below(10) {
        0 => rng.below(200),
        1 => rng.below(5_000),
        2 => rng.below(100_000),
        3 => 30_000_000,
        _ => rng.below(1_000_000),
    }
}

fn label(outcome: &Outcome) -> String {
    match &outcome.result {
        Ok(_) => "return".to_owned(),
        Err(Error::Revert(_)) => "revert".to_owned(),
        Err(Error::MissingReturn) => "stop-or-empty-return".to_owned(),
        Err(Error::UnsupportedFrame) => "unsupported-call".to_owned(),
        Err(Error::Halt(reason)) => format!("halt:{reason:?}"),
    }
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
    let args: Vec<String> = env::args().skip(1).collect();
    let (mut iterations, mut seed) = (10_000u64, 1u64);
    let mut blake2s = false;
    let (mut inputs, mut bases) = (Vec::new(), Vec::new());
    for pair in args.chunks(2) {
        match pair[0].as_str() {
            "--iterations" => iterations = pair[1].parse().unwrap(),
            "--seed" => seed = pair[1].parse().unwrap(),
            "--fixtures" => {
                let file: Value = serde_json::from_str(&fs::read_to_string(&pair[1]).unwrap()).unwrap();
                inputs.extend(file["cases"].as_array().unwrap().iter().map(|c| unhex(c["input"].as_str().unwrap())));
            }
            "--program" => bases.push(unhex(&fs::read_to_string(&pair[1]).unwrap())),
            "--precompile" => blake2s = pair[1] == "blake2s",
            other => panic!("unknown flag {other}"),
        }
    }
    let mut rng = Rng(seed);
    let mut outcomes: BTreeMap<String, u64> = BTreeMap::new();
    let mut mismatches = Vec::new();
    let mut skipped = 0;
    let mut mismatch_count = 0u64;
    for i in 0..iterations {
        let mutated = !bases.is_empty() && i % 2 == 1;
        let (code, calldata) = if mutated {
            let base = &bases[rng.below(bases.len() as u64) as usize];
            let input = inputs[rng.below(inputs.len() as u64) as usize].clone();
            (mutate(&mut rng, base), input)
        } else {
            let len = rng.below(80) as usize;
            (generate(&mut rng, if blake2s { 0xb2 } else { 2 }), rng.bytes(len))
        };
        if code.starts_with(&[0xef, 0x01]) {
            skipped += 1;
            continue;
        }
        let gas = if mutated && rng.chance(50) { 30_000_000 } else { gas_limit(&mut rng) };
        let (expected, direct, purpose_built) = if blake2s {
            let expected = reference::run_with::<Blake2sPrecompile>(&code, &calldata, gas);
            (expected.clone(), expected, fast::run_with::<Blake2sPrecompile>(&code, &calldata, gas))
        } else {
            (reference::run(&code, &calldata, gas), revm_direct::run(&code, &calldata, gas), fast::run(&code, &calldata, gas))
        };
        *outcomes.entry(format!("{}:{}", if mutated { "mutated" } else { "generated" }, label(&expected))).or_default() += 1;
        let direct_ok = direct == expected;
        let fast_ok = class(&purpose_built) == class(&expected);
        if !(direct_ok && fast_ok) {
            mismatch_count += 1;
        }
        if !(direct_ok && fast_ok) && mismatches.len() < 20 {
            mismatches.push(json!({"iteration": i, "code": hex(&code), "calldata": hex(&calldata), "gas_limit": gas,
                "expected": format!("{expected:?}"), "revm_direct": format!("{direct:?}"),
                "fast": format!("{purpose_built:?}"), "revm_direct_ok": direct_ok, "fast_ok": fast_ok}));
        }
    }
    let ok = mismatch_count == 0;
    println!("{}", serde_json::to_string_pretty(&json!({"iterations": iterations, "seed": seed,
        "precompile": if blake2s { "blake2s at 0xb2" } else { "sha256 at 0x02" },
        "skipped_ef01": skipped, "all_match": ok, "mismatch_count": mismatch_count, "reference_outcomes": outcomes, "mismatches": mismatches})).unwrap());
    if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
