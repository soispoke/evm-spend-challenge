//! The challenge statement: the minimal shielded pool's two-input, two-output
//! spend over a depth-20 tree, with SHA-256 as its only hash.
//!
//! `verify` is the direct RISC-V side of the comparison and the Rust twin of
//! `oracle/spend_sha256.py`. It returns the 32-byte statement digest or the
//! violated rule. Checks on private data avoid explicit short-circuit
//! evaluation; compiled cycle counts can still vary by input. `verify_with`
//! checks the same statement with another hash: the BLAKE2s edition uses
//! BLAKE2s-256 for every hash and changes nothing else.
#![no_std]

use sha2::{Digest, Sha256};

pub mod blake2s;

/// The hash every message of the statement goes through.
pub trait StatementHash {
    fn digest(message: &[u8]) -> [u8; 32];
}

/// SHA-256, the challenge's hash.
pub struct Sha256Hash;

impl StatementHash for Sha256Hash {
    fn digest(message: &[u8]) -> [u8; 32] {
        digest(message)
    }
}

/// BLAKE2s-256 in software, for the BLAKE2s edition.
pub struct Blake2sHash;

impl StatementHash for Blake2sHash {
    #[inline(always)]
    fn digest(message: &[u8]) -> [u8; 32] {
        blake2s::hash(message)
    }
}

pub const DEPTH: usize = 20;
pub const INPUT_BYTES: usize = 1680;
const NOTE_BYTES: usize = 32 + 32 + 16 + 4 + 32 * DEPTH;
const NOTES_AT: usize = 136;
const OUTPUTS_AT: usize = NOTES_AT + 2 * NOTE_BYTES;
const OUTPUT_BYTES: usize = 48;

const TAG_PK: u8 = 1;
const TAG_COMMIT: u8 = 2;
const TAG_NULL: u8 = 3;
const TAG_NODE: u8 = 4;
const TAG_INNER: u8 = 5;
const TAG_NK: u8 = 6;
const TAG_OCC: u8 = 7;
const TAG_STATEMENT: u8 = 8;

/// Position-specific inners for zero-value outputs: 1 and 2 as 32-byte words.
const SINK: [[u8; 32]; 2] = {
    let mut sink = [[0u8; 32]; 2];
    sink[0][31] = 1;
    sink[1][31] = 2;
    sink
};

/// The rules of the statement, in the oracle's order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    Length,
    IndexRange,
    Membership,
    NonzeroInput,
    Conservation,
    ZeroOutputSink,
    PositiveOutputNotSink,
    AuthorizerNonzero,
    RecipientMatchesAmount,
    DistinctNullifiers,
    DistinctOutputs,
}

impl Rule {
    pub const fn name(self) -> &'static str {
        match self {
            Rule::Length => "length",
            Rule::IndexRange => "index_range",
            Rule::Membership => "membership",
            Rule::NonzeroInput => "nonzero_input",
            Rule::Conservation => "conservation",
            Rule::ZeroOutputSink => "zero_output_sink",
            Rule::PositiveOutputNotSink => "positive_output_not_sink",
            Rule::AuthorizerNonzero => "authorizer_nonzero",
            Rule::RecipientMatchesAmount => "recipient_matches_amount",
            Rule::DistinctNullifiers => "distinct_nullifiers",
            Rule::DistinctOutputs => "distinct_outputs",
        }
    }
}

fn digest(message: &[u8]) -> [u8; 32] {
    Sha256::digest(message).into()
}

fn word(input: &[u8], at: usize) -> [u8; 32] {
    input[at..at + 32].try_into().unwrap()
}

fn u128_at(input: &[u8], at: usize) -> u128 {
    u128::from_be_bytes(input[at..at + 16].try_into().unwrap())
}

/// Equality without an early exit.
fn same<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    let mut difference = 0u8;
    for i in 0..N {
        difference |= a[i] ^ b[i];
    }
    difference == 0
}

/// H(tag || a || b) for two 32-byte words: 65 bytes, two SHA-256 compressions.
fn hash2<H: StatementHash>(tag: u8, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut message = [0u8; 65];
    message[0] = tag;
    message[1..33].copy_from_slice(a);
    message[33..65].copy_from_slice(b);
    H::digest(&message)
}

/// H(tag || word || tail) for a short fixed tail; one compression.
fn hash_tail<H: StatementHash, const N: usize>(tag: u8, a: &[u8; 32], tail: [u8; N]) -> [u8; 32] {
    let mut message = [0u8; 65];
    message[0] = tag;
    message[1..33].copy_from_slice(a);
    message[33..33 + N].copy_from_slice(&tail);
    H::digest(&message[..33 + N])
}

/// Merkle step with the current node on the right exactly when `bit` is 1,
/// chosen by masking rather than by branching on the private bit.
fn node<H: StatementHash>(current: &[u8; 32], sibling: &[u8; 32], bit: u32) -> [u8; 32] {
    let mask = 0u8.wrapping_sub(bit as u8);
    let mut message = [0u8; 65];
    message[0] = TAG_NODE;
    for i in 0..32 {
        let swap = (current[i] ^ sibling[i]) & mask;
        message[1 + i] = current[i] ^ swap;
        message[33 + i] = sibling[i] ^ swap;
    }
    H::digest(&message)
}

/// Check the statement and return its digest.
pub fn verify(input: &[u8]) -> Result<[u8; 32], Rule> {
    verify_with::<Sha256Hash>(input)
}

/// Check the statement with `H` as its hash. Inlined so that `verify` compiles
/// to the same code as before the hash became a parameter.
#[inline(always)]
pub fn verify_with<H: StatementHash>(input: &[u8]) -> Result<[u8; 32], Rule> {
    if input.len() != INPUT_BYTES {
        return Err(Rule::Length);
    }
    let root = word(input, 0);
    let domain = word(input, 32);
    let public_amount = u128_at(input, 64);
    let fee = u128_at(input, 80);
    let recipient: [u8; 20] = input[96..116].try_into().unwrap();
    let authorizer: [u8; 20] = input[116..136].try_into().unwrap();

    let mut nullifiers = [[0u8; 32]; 2];
    let mut values = [0u128; 2];
    for k in 0..2 {
        let at = NOTES_AT + k * NOTE_BYTES;
        let spend_key = word(input, at);
        let rho = word(input, at + 32);
        let value = u128_at(input, at + 64);
        let index = u32::from_be_bytes(input[at + 80..at + 84].try_into().unwrap());
        if index >= 1 << DEPTH {
            return Err(Rule::IndexRange);
        }
        let mut owner_message = [0u8; 33];
        owner_message[0] = TAG_PK;
        owner_message[1..].copy_from_slice(&spend_key);
        let owner = H::digest(&owner_message);
        let inner = hash2::<H>(TAG_INNER, &owner, &rho);
        let commitment = hash_tail::<H, 16>(TAG_COMMIT, &inner, value.to_be_bytes());
        let mut current = commitment;
        for level in 0..DEPTH {
            let sibling = word(input, at + 84 + 32 * level);
            current = node::<H>(&current, &sibling, (index >> level) & 1);
        }
        // Dummy inputs carry zero value and need not be members.
        if !(same(&current, &root) | (value == 0)) {
            return Err(Rule::Membership);
        }
        let occurrence = hash_tail::<H, 4>(TAG_OCC, &commitment, index.to_be_bytes());
        let nullifier_key = hash2::<H>(TAG_NK, &domain, &spend_key);
        nullifiers[k] = hash2::<H>(TAG_NULL, &nullifier_key, &occurrence);
        values[k] = value;
    }

    let mut commitments = [[0u8; 32]; 2];
    let mut outputs = [0u128; 2];
    for k in 0..2 {
        let at = OUTPUTS_AT + k * OUTPUT_BYTES;
        let inner = word(input, at);
        let value = u128_at(input, at + 32);
        let is_sink = same(&inner, &SINK[0]) | same(&inner, &SINK[1]);
        if !((value != 0) | same(&inner, &SINK[k])) {
            return Err(Rule::ZeroOutputSink);
        }
        if !((value == 0) | !is_sink) {
            return Err(Rule::PositiveOutputNotSink);
        }
        commitments[k] = hash_tail::<H, 16>(TAG_COMMIT, &inner, value.to_be_bytes());
        outputs[k] = value;
    }

    // Exact integer sums: two u128 inputs fit in 129 bits, four u128 outputs in 130.
    let (inputs_low, inputs_carry) = values[0].overflowing_add(values[1]);
    let inputs_high = inputs_carry as u32;
    let mut outputs_low = 0u128;
    let mut outputs_high = 0u32;
    for part in [outputs[0], outputs[1], public_amount, fee] {
        let (sum, carry) = outputs_low.overflowing_add(part);
        outputs_low = sum;
        outputs_high += carry as u32;
    }
    if (inputs_low == 0) & (inputs_high == 0) {
        return Err(Rule::NonzeroInput);
    }
    if !((inputs_low == outputs_low) & (inputs_high == outputs_high)) {
        return Err(Rule::Conservation);
    }
    if same(&authorizer, &[0u8; 20]) {
        return Err(Rule::AuthorizerNonzero);
    }
    if (public_amount == 0) != same(&recipient, &[0u8; 20]) {
        return Err(Rule::RecipientMatchesAmount);
    }
    if same(&nullifiers[0], &nullifiers[1]) {
        return Err(Rule::DistinctNullifiers);
    }
    if same(&commitments[0], &commitments[1]) {
        return Err(Rule::DistinctOutputs);
    }

    let mut statement = [0u8; 265];
    statement[0] = TAG_STATEMENT;
    statement[1..33].copy_from_slice(&nullifiers[0]);
    statement[33..65].copy_from_slice(&nullifiers[1]);
    statement[65..97].copy_from_slice(&commitments[0]);
    statement[97..129].copy_from_slice(&commitments[1]);
    statement[129..161].copy_from_slice(&root);
    statement[161..193].copy_from_slice(&domain);
    statement[193..209].copy_from_slice(&public_amount.to_be_bytes());
    statement[209..225].copy_from_slice(&fee.to_be_bytes());
    statement[225..245].copy_from_slice(&recipient);
    statement[245..265].copy_from_slice(&authorizer);
    Ok(H::digest(&statement))
}

/// Message lengths of the statement's 55 SHA-256 calls: per input the owner
/// key, inner, commitment, 20 nodes, occurrence, nullifier key and nullifier;
/// then two output commitments and the statement digest. 105 compressions.
pub const HASH_SCHEDULE: [usize; 55] = {
    let per_input = [33, 65, 49, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
        65, 65, 65, 65, 65, 37, 65, 65];
    let mut schedule = [0usize; 55];
    let mut i = 0;
    while i < 26 {
        schedule[i] = per_input[i];
        schedule[26 + i] = per_input[i];
        i += 1;
    }
    schedule[52] = 49;
    schedule[53] = 49;
    schedule[54] = 265;
    schedule
};

/// The same SHA-256 calls as `verify`, chained so none can be skipped, with no
/// other work. The guest built from it measures the cost of the hashing alone.
pub fn hash_control(input: &[u8]) -> [u8; 32] {
    let mut message = [0u8; 265];
    message.copy_from_slice(&input[..265]);
    let mut state = word(input, 265);
    for (call, &length) in HASH_SCHEDULE.iter().enumerate() {
        message[0] = call as u8;
        message[1..33].copy_from_slice(&state);
        state = digest(&message[..length]);
    }
    state
}

/// Folds the input to 32 bytes: the fixed cost of starting the guest, reading
/// its input and returning a digest, without any hashing.
pub fn null_control(input: &[u8]) -> [u8; 32] {
    let mut state = [0u64; 4];
    for (i, chunk) in input.chunks_exact(8).enumerate() {
        state[i % 4] ^= u64::from_le_bytes(chunk.try_into().unwrap());
    }
    let mut out = [0u8; 32];
    for (i, lane) in state.iter().enumerate() {
        out[8 * i..8 * i + 8].copy_from_slice(&lane.to_le_bytes());
    }
    out
}
