//! EVM route under the REVM copy that reports gas (interpreters/src/reference.rs),
//! to check it costs the same as the scoring harness. Runs guests/evm/bytecode.bin.
#![no_std]
#![no_main]
extern crate alloc;

#[unsafe(no_mangle)]
extern "C" fn main() {
    let returned = spend_evm_interpreters::reference::run(
        include_bytes!("../../evm/bytecode.bin"),
        spend_runtime::challenge_input(),
        spend_evm_interpreters::GAS_LIMIT,
    )
    .result
    .unwrap();
    spend_runtime::finish(returned.as_slice().try_into().unwrap());
}
