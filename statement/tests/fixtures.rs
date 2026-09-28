//! The Rust statement must agree with the Python oracle on every public case:
//! the exact digest for valid inputs and the targeted rule for invalid ones.
use spend_sha256::{hash_control, null_control, verify, HASH_SCHEDULE, INPUT_BYTES};

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn cases() -> Vec<serde_json::Value> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/public.json");
    let fixtures: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    fixtures["cases"].as_array().unwrap().clone()
}

#[test]
fn matches_oracle_on_public_cases() {
    let cases = cases();
    assert_eq!(cases.len(), 59);
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let result = verify(&unhex(case["input"].as_str().unwrap()));
        if case["valid"].as_bool().unwrap() {
            assert_eq!(result, Ok(unhex(case["digest"].as_str().unwrap()).try_into().unwrap()), "{name}");
        } else {
            assert_eq!(result.map_err(|rule| rule.name()), Err(case["rule"].as_str().unwrap()), "{name}");
        }
    }
}

#[test]
fn controls_cover_the_statement_hashing() {
    // 105 SHA-256 compressions: ceil((length + 9) / 64) per call.
    let blocks: usize = HASH_SCHEDULE.iter().map(|length| (length + 9).div_ceil(64)).sum();
    assert_eq!(blocks, 105);
    let input = unhex(cases()[0]["input"].as_str().unwrap());
    assert_eq!(input.len(), INPUT_BYTES);
    assert_ne!(hash_control(&input), null_control(&input));
}
