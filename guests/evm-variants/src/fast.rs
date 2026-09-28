//! EVM route with the interpreter written for proving cost. Runs the same
//! bytecode as the scored guest, from guests/evm/bytecode.bin.
#![no_std]
#![no_main]
extern crate alloc;

#[unsafe(no_mangle)]
extern "C" fn main() {
    let returned = spend_evm_interpreters::fast::execute(
        include_bytes!("../../evm/bytecode.bin"),
        spend_runtime::challenge_input(),
    )
    .unwrap();
    spend_runtime::finish(returned.as_slice().try_into().unwrap());
}
