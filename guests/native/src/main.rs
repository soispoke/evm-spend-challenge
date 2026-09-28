//! Direct RISC-V route: the Rust statement compiled for RV64IM.
#![no_std]
#![no_main]

#[unsafe(no_mangle)]
extern "C" fn main() {
    let digest = spend_sha256::verify(spend_runtime::challenge_input()).unwrap();
    spend_runtime::finish(digest);
}
