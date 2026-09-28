//! EVM route: the candidate's runtime bytecode, interpreted by pinned REVM
//! inside the RV64IM guest. The calldata is the raw challenge input.
#![no_std]
#![no_main]
extern crate alloc;

#[unsafe(no_mangle)]
extern "C" fn main() {
    let returned = spend_evm_engine::execute(include_bytes!("../bytecode.bin"), spend_runtime::challenge_input())
        .unwrap();
    spend_runtime::finish(returned.as_slice().try_into().unwrap());
}
