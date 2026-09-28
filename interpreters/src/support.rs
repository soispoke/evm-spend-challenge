//! Helpers shared by the purpose-built interpreter and by programs compiled
//! ahead of time with `interpreters/compile.py`: EVM memory with its expansion
//! gas, word conversions and copies, with the harness semantics.

use alloc::vec::Vec;
use core::cmp::min;
use revm_interpreter::{primitives::U256, InstructionResult};

use crate::MEMORY_LIMIT;

/// EVM memory with its expansion cost so far.
pub struct Memory {
    pub data: Vec<u8>,
    pub cost: u64,
}

impl Default for Memory {
    fn default() -> Self {
        Self { data: Vec::with_capacity(4096), cost: 0 }
    }
}

impl Memory {
    /// Expand to cover `offset..offset + len` (`len > 0`), returning the gas
    /// left after the expansion cost. Gas is passed by value so that it stays
    /// in a register in the interpreter loop.
    #[inline(always)]
    pub fn ensure(&mut self, gas: i64, offset: usize, len: usize) -> Result<i64, InstructionResult> {
        let end = offset.saturating_add(len);
        if end <= self.data.len() {
            return Ok(gas);
        }
        self.grow(gas, end)
    }

    #[cold]
    #[inline(never)]
    fn grow(&mut self, gas: i64, end: usize) -> Result<i64, InstructionResult> {
        let words = end.div_ceil(32);
        if words.saturating_mul(32) as u64 > MEMORY_LIMIT {
            return Err(InstructionResult::MemoryLimitOOG);
        }
        let w = words as u64;
        let cost = 3 * w + w * w / 512;
        let extra = cost - self.cost;
        if gas < extra as i64 {
            return Err(InstructionResult::MemoryOOG);
        }
        self.cost = cost;
        self.data.resize(words * 32, 0);
        Ok(gas - extra as i64)
    }
}

#[inline(always)]
pub fn to_usize(v: &U256) -> Option<usize> {
    let l = v.as_limbs();
    if (l[1] | l[2] | l[3]) != 0 { None } else { usize::try_from(l[0]).ok() }
}

#[inline(always)]
pub fn saturated(v: &U256) -> usize {
    to_usize(v).unwrap_or(usize::MAX)
}

#[inline(always)]
pub fn words(len: usize) -> u64 {
    len.div_ceil(32) as u64
}

#[inline(always)]
fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes(b.try_into().unwrap())
}

#[inline(always)]
pub fn load_word(b: &[u8]) -> U256 {
    U256::from_limbs([be64(&b[24..32]), be64(&b[16..24]), be64(&b[8..16]), be64(&b[0..8])])
}

#[inline(always)]
pub fn store_word(b: &mut [u8], v: &U256) {
    let l = v.as_limbs();
    b[0..8].copy_from_slice(&l[3].to_be_bytes());
    b[8..16].copy_from_slice(&l[2].to_be_bytes());
    b[16..24].copy_from_slice(&l[1].to_be_bytes());
    b[24..32].copy_from_slice(&l[0].to_be_bytes());
}

/// The value of PUSHn's `n` immediate bytes, big-endian.
#[inline(always)]
pub fn push_value(b: &[u8]) -> U256 {
    let mut limbs = [0u64; 4];
    let mut end = b.len();
    let mut i = 0;
    while end > 0 {
        let start = end.saturating_sub(8);
        let mut w = 0u64;
        for &byte in &b[start..end] {
            w = (w << 8) | byte as u64;
        }
        limbs[i] = w;
        i += 1;
        end = start;
    }
    U256::from_limbs(limbs)
}

pub fn calldata_word(data: &[u8], offset: usize) -> U256 {
    if offset >= data.len() {
        return U256::ZERO;
    }
    if data.len() - offset >= 32 {
        return load_word(&data[offset..offset + 32]);
    }
    let mut word = [0u8; 32];
    word[..data.len() - offset].copy_from_slice(&data[offset..]);
    U256::from_be_bytes(word)
}

/// Copy `len` bytes of `src` from `src_offset` into `dst` at `dst_offset`,
/// with zeros past the end of `src`.
pub fn set_data(dst: &mut [u8], src: &[u8], dst_offset: usize, src_offset: usize, len: usize) {
    let dst = &mut dst[dst_offset..dst_offset + len];
    if src_offset >= src.len() {
        dst.fill(0);
        return;
    }
    let n = min(len, src.len() - src_offset);
    dst[..n].copy_from_slice(&src[src_offset..src_offset + n]);
    dst[n..].fill(0);
}

pub fn signextend(ext: U256, x: U256) -> U256 {
    if ext < U256::from(31) {
        let bit_index = (8 * ext.as_limbs()[0] + 7) as usize;
        let mask = (U256::from(1) << bit_index) - U256::from(1);
        if x.bit(bit_index) { x | !mask } else { x & mask }
    } else {
        x
    }
}

/// JUMPDEST positions outside PUSH data, as a bitmap.
pub fn analyze(code: &[u8]) -> Vec<u8> {
    let mut map = alloc::vec![0u8; code.len().div_ceil(8)];
    let mut i = 0;
    while i < code.len() {
        let op = code[i];
        if op == 0x5b {
            map[i >> 3] |= 1 << (i & 7);
            i += 1;
        } else if op.wrapping_sub(0x60) < 32 {
            i += (op - 0x5f) as usize + 1;
        } else {
            i += 1;
        }
    }
    map
}

#[inline(always)]
pub fn valid_jump(map: &mut Option<Vec<u8>>, code: &[u8], target: usize) -> bool {
    target < code.len() && {
        let map = map.get_or_insert_with(|| analyze(code));
        map[target >> 3] & (1 << (target & 7)) != 0
    }
}

/// The low 20 bytes of a word, as an address, equal `address`.
#[inline(always)]
pub fn is_precompile(to: &U256, address: u8) -> bool {
    let l = to.as_limbs();
    l[0] == address as u64 && l[1] == 0 && (l[2] & 0xffff_ffff) == 0
}

