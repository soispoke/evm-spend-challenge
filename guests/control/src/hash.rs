//! The statement's 55 SHA-256 calls and nothing else.
#![no_std]
#![no_main]

#[unsafe(no_mangle)]
extern "C" fn main() {
    spend_runtime::finish(spend_sha256::hash_control(spend_runtime::challenge_input()));
}
