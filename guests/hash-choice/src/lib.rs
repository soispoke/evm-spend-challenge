//! The statement's 55 hash calls with a choice of hash, to compare what hashing
//! costs on leanVM: the calls are chained as in `spend_sha256::hash_control`,
//! and each binary outputs the final digest without checking it.
#![no_std]

pub use spend_sha256::HASH_SCHEDULE;

/// The 55 calls, message lengths as in the statement, each message carrying the
/// previous digest.
pub fn control(input: &[u8], hash: impl Fn(&[u8]) -> [u8; 32]) -> [u8; 32] {
    let mut message = [0u8; 265];
    message.copy_from_slice(&input[..265]);
    let mut state: [u8; 32] = input[265..297].try_into().unwrap();
    for (call, &length) in HASH_SCHEDULE.iter().enumerate() {
        message[0] = call as u8;
        message[1..33].copy_from_slice(&state);
        state = hash(&message[..length]);
    }
    state
}

pub fn publish(digest: [u8; 32]) {
    let words = core::array::from_fn(|i| u64::from_le_bytes(digest[8 * i..8 * i + 8].try_into().unwrap()));
    spend_runtime::output(words);
}

const IV: [u32; 8] = [
    0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A, 0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19,
];

#[inline(always)]
fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

#[inline(always)]
fn round(v: &mut [u32; 16], m: &[u32; 16], s: &[usize; 16]) {
    g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
    g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
    g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
    g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
    g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
    g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
    g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
}

fn words(block: &[u8]) -> [u32; 16] {
    let mut padded = [0u8; 64];
    padded[..block.len()].copy_from_slice(block);
    core::array::from_fn(|i| u32::from_le_bytes(padded[4 * i..4 * i + 4].try_into().unwrap()))
}

/// BLAKE2s-256 in software, as in leanVM's own `guests/blake2s` example.
pub fn blake2s(data: &[u8]) -> [u8; 32] {
    const SIGMA: [[usize; 16]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ];
    let mut h = IV;
    h[0] ^= 0x0101_0020;
    let blocks = data.len().div_ceil(64).max(1);
    for i in 0..blocks {
        let block = &data[64 * i..data.len().min(64 * i + 64)];
        let last = i == blocks - 1;
        let counter = if last { data.len() as u64 } else { 64 * (i as u64 + 1) };
        let m = words(block);
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= counter as u32;
        v[13] ^= (counter >> 32) as u32;
        if last {
            v[14] = !v[14];
        }
        for s in &SIGMA {
            round(&mut v, &m, s);
        }
        for k in 0..8 {
            h[k] ^= v[k] ^ v[k + 8];
        }
    }
    let mut out = [0u8; 32];
    for (chunk, word) in out.chunks_exact_mut(4).zip(&h) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// BLAKE3-256 in software, for inputs of at most one 1,024-byte chunk.
pub fn blake3(data: &[u8]) -> [u8; 32] {
    const PERMUTED: [[usize; 16]; 7] = {
        const P: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
        let mut s = [[0usize; 16]; 7];
        let mut i = 0;
        while i < 16 {
            s[0][i] = i;
            i += 1;
        }
        let mut r = 1;
        while r < 7 {
            let mut i = 0;
            while i < 16 {
                s[r][i] = s[r - 1][P[i]];
                i += 1;
            }
            r += 1;
        }
        s
    };
    assert!(data.len() <= 1024);
    let mut cv = IV;
    let blocks = data.len().div_ceil(64).max(1);
    for i in 0..blocks {
        let block = &data[64 * i..data.len().min(64 * i + 64)];
        let flags = if i == 0 { 1 } else { 0 } | if i == blocks - 1 { 2 | 8 } else { 0 };
        let m = words(block);
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&cv);
        v[8..12].copy_from_slice(&IV[..4]);
        v[14] = block.len() as u32;
        v[15] = flags;
        for s in &PERMUTED {
            round(&mut v, &m, s);
        }
        for k in 0..8 {
            cv[k] = v[k] ^ v[k + 8];
        }
    }
    let mut out = [0u8; 32];
    for (chunk, word) in out.chunks_exact_mut(4).zip(&cv) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    out
}
