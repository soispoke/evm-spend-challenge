#![no_std]
#![no_main]
extern crate alloc;

#[unsafe(no_mangle)]
extern "C" fn main() {
    let input = spend_runtime::challenge_input();
    spend_runtime::finish(spend_sha256::verify_with::<spend_blake2s_edition_guests::SoftwareHash>(input).unwrap());
}
