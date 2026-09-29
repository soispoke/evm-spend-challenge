//! Challenge scorer.
//!
//! `check` runs the Rust statement and an EVM candidate natively over a case
//! file and requires exact agreement with the oracle. `execute` runs a leanVM
//! guest over the cases and reports RV64IM cycles, the score. `prove` proves
//! one case with leanVM and verifies the proof.
use std::{collections::BTreeSet, env, fs, process::ExitCode, time::Instant};

use leanvm::{Program, prove, verify};
use serde_json::{Value, json};

fn unhex(text: &str) -> Vec<u8> {
    let text = text.trim();
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn words(bytes: &[u8]) -> Vec<u64> {
    assert!(bytes.len().is_multiple_of(8));
    bytes.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect()
}

fn digest_words(digest: &[u8; 32]) -> [u64; 4] {
    words(digest).try_into().unwrap()
}

/// Decode only the optional, canonically encoded Rule(uint8) custom error.
fn reported_rule(data: &[u8]) -> Option<u8> {
    (data.len() == 36 && data[..4] == [0xa3, 0x32, 0xd2, 0x6d] && data[4..35].iter().all(|&b| b == 0))
        .then(|| data[35])
}

fn execution_matches(output: Option<[u64; 4]>, public: [u64; 4], valid: bool) -> bool {
    if valid { output == Some(public) } else { output.is_none() }
}

fn execution_public(want: Option<[u8; 32]>, case: &Value) -> [u64; 4] {
    // The guest checks its digest against this public input before it halts.
    // A negative test must therefore use its canonical digest too: zero would
    // make a missing rule check look like rejection solely on a digest mismatch.
    let digest = want.unwrap_or_else(|| {
        let hex = case["digest"].as_str().expect("invalid fixture lacks canonical digest; regenerate it with the oracle");
        unhex(hex).try_into().expect("fixture digest must be 32 bytes")
    });
    digest_words(&digest)
}

struct Args {
    rest: Vec<String>,
}

impl Args {
    fn value(&self, flag: &str) -> Option<String> {
        self.rest.iter().position(|a| a == flag).map(|i| self.rest[i + 1].clone())
    }
    fn required(&self, flag: &str) -> String {
        self.value(flag).unwrap_or_else(|| panic!("missing {flag}"))
    }
    fn has(&self, flag: &str) -> bool {
        self.rest.iter().any(|a| a == flag)
    }
}

fn load_cases(path: &str) -> (Vec<Value>, Vec<String>) {
    let fixtures: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let rules = fixtures["rules"].as_array().unwrap().iter().map(|r| r.as_str().unwrap().to_owned()).collect();
    (fixtures["cases"].as_array().unwrap().clone(), rules)
}

/// Expected output of a guest route on one case, or None when it must reject.
fn expected(route: &str, case: &Value) -> Option<[u8; 32]> {
    let input = unhex(case["input"].as_str().unwrap());
    match route {
        "control" => Some(spend_sha256::hash_control(&input)),
        "null" => Some(spend_sha256::null_control(&input)),
        // The EVM start-up control copies input[265..297] to memory 1..33 and returns it.
        "evm-start" => Some(input[265..297].try_into().unwrap()),
        _ if case["valid"].as_bool().unwrap() => Some(unhex(case["digest"].as_str().unwrap()).try_into().unwrap()),
        _ => None,
    }
}

fn check(args: &Args) -> ExitCode {
    let (cases, rules) = load_cases(&args.required("--fixtures"));
    let bytecode = args.value("--evm").map(|path| unhex(&fs::read_to_string(path).unwrap()));
    // `--hash blake2s` checks the BLAKE2s edition: the Rust statement with BLAKE2s,
    // and EVM candidates under REVM with a BLAKE2s precompile at 0xb2.
    let blake2s = args.value("--hash").as_deref() == Some("blake2s");
    let mut failures = Vec::new();
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let input = unhex(case["input"].as_str().unwrap());
        let valid = case["valid"].as_bool().unwrap();
        let want = valid.then(|| unhex(case["digest"].as_str().unwrap()));
        let rule = case["rule"].as_str();
        let native = if blake2s {
            spend_sha256::verify_with::<spend_sha256::Blake2sHash>(&input)
        } else {
            spend_sha256::verify(&input)
        };
        let native_ok = match (&want, native) {
            (Some(digest), Ok(got)) => got.as_slice() == digest.as_slice(),
            (None, Err(got)) => Some(got.name()) == rule,
            _ => false,
        };
        if !native_ok {
            failures.push(json!({"case": name, "route": "native", "result": format!("{native:?}")}));
        }
        if let Some(code) = &bytecode {
            let evm = if blake2s {
                use spend_evm_interpreters::{Blake2sPrecompile, GAS_LIMIT, reference};
                reference::run_with::<Blake2sPrecompile>(code, &input, GAS_LIMIT).result
            } else {
                spend_evm_engine::execute(code, &input)
            };
            let evm_ok = match (&want, &evm) {
                (Some(digest), Ok(got)) => got == digest,
                // A rejected case must not return output. When the candidate
                // reports `Rule(uint8)`, the code must name the targeted rule.
                (None, Err(spend_evm_engine::Error::Revert(data))) => {
                    reported_rule(data).is_none_or(|code| rules.get(code as usize).map(String::as_str) == rule)
                }
                (None, Err(_)) => true,
                _ => false,
            };
            if !evm_ok {
                failures.push(json!({"case": name, "route": "evm", "result": format!("{evm:?}")}));
            }
        }
    }
    let valid = cases.iter().filter(|c| c["valid"].as_bool().unwrap()).count();
    println!("{}", json!({"cases": cases.len(), "valid": valid, "invalid": cases.len() - valid,
        "evm_checked": bytecode.is_some(), "failures": failures}));
    if failures.is_empty() { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

fn execute(args: &Args) -> ExitCode {
    let route = args.required("--route");
    let elf = fs::read(args.required("--elf")).unwrap();
    let program = Program::from_elf(&elf).unwrap();
    let (cases, _) = load_cases(&args.required("--fixtures"));
    let valid_only = args.has("--valid-only");
    let cycle_cap: u64 = args.value("--cycle-cap").map_or(200_000_000, |v| v.parse().unwrap());
    let mut failures = Vec::new();
    let mut valid_cycles = Vec::new();
    let (mut padded, mut padded_shapes, mut witness) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for case in &cases {
        let input_bytes = unhex(case["input"].as_str().unwrap());
        // Guests read a fixed 1,680-byte input; wrong lengths are a host-side check.
        if input_bytes.len() != spend_sha256::INPUT_BYTES {
            continue;
        }
        let want = expected(&route, case);
        if valid_only && want.is_none() {
            continue;
        }
        let public = execution_public(want, case);
        let t = Instant::now();
        let mut machine = lean_vm::rv::Machine::new(&program.rv, public, &words(&input_bytes));
        let mut cycles = 0u64;
        let mut base_counts = [0usize; lean_vm::tables::N_TABLES];
        let mut error = None;
        while !machine.halted() && cycles < cycle_cap {
            match machine.step() {
                Ok(step) => {
                    if let Some(table) = lean_vm::tables::table_of(program.rv.entries[step.index].class) {
                        base_counts[table] += 1;
                    }
                }
                Err(e) => {
                    error = Some(e.to_string());
                    break;
                }
            }
            cycles += 1;
        }
        let output = if error.is_none() { machine.run(1).ok() } else { None };
        let accepted = output.is_some();
        let correct = execution_matches(output, public, want.is_some());
        let name = case["name"].as_str().unwrap();
        let mut record = json!({"case": name, "valid": want.is_some(), "accepted": accepted,
            "cycles": cycles, "execution_s": t.elapsed().as_secs_f64()});
        if correct && want.is_some() {
            let filled = lean_vm::cpu::filler::filled(base_counts, &lean_vm::cpu::filler::solve(base_counts));
            let taus = filled.map(|count| count.trailing_zeros() as usize);
            let mut sizes = vec![0usize];
            sizes.extend(taus);
            let sources = lean_vm::cpu::layout::col_kappa_sources(lean_vm::cpu::layout::Sizes::of(&program.rv));
            let kappas = sources.iter()
                .map(|source| source.map(|(index, adjustment)| sizes[index] + adjustment))
                .collect::<Vec<_>>();
            let (_, shape) = lean_vm::witness::placements_of(&kappas);
            let padded_cycles: usize = filled.iter().sum();
            record["padded_cycles"] = json!(padded_cycles);
            record["padded_counts"] = json!(filled);
            record["committed_words"] = json!(shape.committed_len());
            record["witness_log_size"] = json!(shape.mu);
            record["base_counts"] = json!(base_counts);
            padded.insert(padded_cycles);
            padded_shapes.insert(filled.to_vec());
            witness.insert(shape.mu);
            valid_cycles.push(cycles);
        }
        if !correct {
            failures.push(name.to_owned());
        }
        println!("{record}");
    }
    let summary = json!({"summary": true, "route": route, "valid_cases": valid_cycles.len(),
        "score_max_cycles": valid_cycles.iter().max(), "min_cycles": valid_cycles.iter().min(),
        "distinct_padded_cycles": padded, "distinct_padded_counts": padded_shapes, "distinct_witness_log_size": witness,
        "within_proof_size_bound": witness.iter().all(|&mu| mu <= 28), "failures": failures});
    println!("{summary}");
    if failures.is_empty() { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

fn prove_case(args: &Args) -> ExitCode {
    let route = args.required("--route");
    let elf = fs::read(args.required("--elf")).unwrap();
    let t = Instant::now();
    let program = Program::from_elf(&elf).unwrap();
    let load_s = t.elapsed().as_secs_f64();
    let (cases, _) = load_cases(&args.required("--fixtures"));
    let name = args.required("--case");
    let case = cases.iter().find(|c| c["name"] == name.as_str()).expect("case");
    // `--public HEX` proves a guest whose output no route computes, such as the
    // hash comparisons in guests/hash-choice.
    let public = match args.value("--public") {
        Some(hex) => digest_words(&unhex(&hex).try_into().expect("32 bytes")),
        None => digest_words(&expected(&route, case).expect("a provable case")),
    };
    let advice = words(&unhex(case["input"].as_str().unwrap()));
    let warmups: usize = args.value("--warmups").map_or(1, |v| v.parse().unwrap());
    let repetitions: usize = args.value("--repetitions").map_or(3, |v| v.parse().unwrap());
    leanvm::setup_prover();
    let topology = parallel::topology();
    for run in 0..warmups + repetitions {
        let t = Instant::now();
        let (proof, output, stats) = prove(&program, public, &advice, leanvm::MIN_LOG_INV_RATE).unwrap();
        let proving_s = t.elapsed().as_secs_f64();
        assert_eq!(output, public, "the program must accept the expected statement");
        let t = Instant::now();
        verify(&program, &public, &output, &proof).unwrap();
        let verification_s = t.elapsed().as_secs_f64();
        let mut wrong = public;
        wrong[0] ^= 1;
        assert!(verify(&program, &wrong, &output, &proof).is_err());
        println!("{}", json!({"route": route, "case": name, "warmup": run < warmups, "run": run,
            "proving_s": proving_s, "verification_s": verification_s,
            "cycles": stats.base_counts.iter().sum::<usize>(), "padded_cycles": stats.cycles,
            "committed_words": stats.committed, "proof_bytes": bincode::serialized_size(&proof).unwrap(),
            "peak_rss_bytes": primitives::bench::peak_rss_bytes(), "load_s": load_s,
            "performance_workers": topology.perf, "efficiency_workers": topology.efficiency,
            "log_inv_rate": leanvm::MIN_LOG_INV_RATE, "zero_knowledge": false,
            "verified": true, "wrong_public_input_rejected": true}));
    }
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let mut rest: Vec<String> = env::args().skip(1).collect();
    assert!(!rest.is_empty(), "spend-challenge check|execute|prove [flags]");
    let mode = rest.remove(0);
    let args = Args { rest };
    match mode.as_str() {
        "check" => check(&args),
        "execute" => execute(&args),
        "prove" => prove_case(&args),
        other => panic!("unknown mode {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_execution_cannot_succeed_even_with_zero_or_unexpected_output() {
        assert!(!execution_matches(Some([0; 4]), [0; 4], false));
        assert!(!execution_matches(Some([1; 4]), [0; 4], false));
        assert!(execution_matches(None, [0; 4], false));
        assert!(execution_matches(Some([1; 4]), [1; 4], true));
        assert!(!execution_matches(Some([0; 4]), [1; 4], true));
        assert!(!execution_matches(None, [1; 4], true));
    }

    #[test]
    fn invalid_execution_uses_the_oracles_digest() {
        let case = json!({"valid": false, "digest": "01".repeat(32)});
        assert_eq!(execution_public(None, &case), [0x0101_0101_0101_0101; 4]);
    }

    #[test]
    #[should_panic(expected = "invalid fixture lacks canonical digest")]
    fn invalid_execution_requires_a_digest() {
        execution_public(None, &json!({"valid": false}));
    }

    #[test]
    fn optional_rule_error_requires_its_selector_and_canonical_argument() {
        let mut data = [0u8; 36];
        data[..4].copy_from_slice(&[0xa3, 0x32, 0xd2, 0x6d]);
        data[35] = 7;
        assert_eq!(reported_rule(&data), Some(7));
        data[0] ^= 1;
        assert_eq!(reported_rule(&data), None);
        data[0] ^= 1;
        data[4] = 1;
        assert_eq!(reported_rule(&data), None);
        assert_eq!(reported_rule(&[]), None);
    }
}
