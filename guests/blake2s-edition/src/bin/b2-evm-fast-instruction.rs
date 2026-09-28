#![no_std]
#![no_main]
extern crate alloc;

#[unsafe(no_mangle)]
extern "C" fn main() {
    let input = spend_runtime::challenge_input();
    spend_blake2s_edition_guests::finish(spend_evm_interpreters::fast::run_with::<spend_blake2s_edition_guests::InstructionPrecompile>(include_bytes!("../../bytecode.bin"), input, spend_evm_interpreters::GAS_LIMIT).result);
}
