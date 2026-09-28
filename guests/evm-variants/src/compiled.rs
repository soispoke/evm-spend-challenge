//! EVM route with the entry compiled ahead of time into Rust by
//! interpreters/compile.py; compiled_program.rs is generated from
//! guests/evm/bytecode.bin before the build.
#![no_std]
#![no_main]
extern crate alloc;

mod program {
    include!("../compiled_program.rs");
}

#[unsafe(no_mangle)]
extern "C" fn main() {
    let returned = program::execute(spend_runtime::challenge_input()).unwrap();
    spend_runtime::finish(returned.as_slice().try_into().unwrap());
}
