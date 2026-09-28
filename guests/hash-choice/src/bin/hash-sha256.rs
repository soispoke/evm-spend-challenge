#![no_std]
#![no_main]

#[unsafe(no_mangle)]
extern "C" fn main() {
    let input = spend_runtime::challenge_input();
    spend_hash_choice_guests::publish(spend_hash_choice_guests::control(input, |m| { use sha2::Digest; sha2::Sha256::digest(m).into() }));
}
