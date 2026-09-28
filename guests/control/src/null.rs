//! Start, read the input, return a digest: the fixed cost with no hashing.
#![no_std]
#![no_main]

#[unsafe(no_mangle)]
extern "C" fn main() {
    spend_runtime::finish(spend_sha256::null_control(spend_runtime::challenge_input()));
}
