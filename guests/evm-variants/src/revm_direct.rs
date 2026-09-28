//! EVM route with the SHA-256 call computed inside REVM's STATICCALL. Runs the
//! same bytecode as the scored guest, from guests/evm/bytecode.bin.
#![no_std]
#![no_main]
extern crate alloc;

#[unsafe(no_mangle)]
extern "C" fn main() {
    let returned = spend_evm_interpreters::revm_direct::execute(
        include_bytes!("../../evm/bytecode.bin"),
        spend_runtime::challenge_input(),
    )
    .unwrap();
    spend_runtime::finish(returned.as_slice().try_into().unwrap());
}
