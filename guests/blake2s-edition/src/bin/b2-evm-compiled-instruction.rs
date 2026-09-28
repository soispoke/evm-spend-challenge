#![no_std]
#![no_main]
extern crate alloc;

mod program {
    include!("../../compiled_program.rs");
}
#[unsafe(no_mangle)]
extern "C" fn main() {
    let input = spend_runtime::challenge_input();
    spend_blake2s_edition_guests::finish(program::run_with::<spend_blake2s_edition_guests::InstructionPrecompile>(input, spend_evm_interpreters::GAS_LIMIT).result);
}
