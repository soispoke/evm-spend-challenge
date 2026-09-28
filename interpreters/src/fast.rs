//! An EVM interpreter written for proving cost.
//!
//! It keeps the harness rules and changes only how they are executed: one
//! dispatch loop over a zero-padded copy of the code, the stack in a fixed
//! buffer, jump destinations analyzed only when a jump is taken, and the
//! SHA-256 precompile hashed straight from EVM memory into EVM memory without
//! a call frame. Arithmetic uses the same `ruint` operations and REVM signed
//! helpers as the harness, and gas follows the harness schedule exactly.

use alloc::vec::Vec;
use core::cmp::{max, min, Ordering};
use revm_interpreter::{
    instructions::i256::{i256_cmp, i256_div, i256_mod},
    primitives::{keccak256, KECCAK_EMPTY, U256},
    InstructionResult,
};
use crate::support::*;
use crate::{Error, HashPrecompile, Outcome, Sha256Precompile, GAS_LIMIT};

const STACK_LIMIT: usize = 1024;
/// Zero bytes after the code: a PUSH32 in the last byte reads zeros, and
/// execution past the end reads STOP.
const PADDING: usize = 33;

pub fn execute(bytecode: &[u8], calldata: &[u8]) -> Result<Vec<u8>, Error> {
    run(bytecode, calldata, GAS_LIMIT).result
}

pub fn run(bytecode: &[u8], calldata: &[u8], gas_limit: u64) -> Outcome {
    run_with::<Sha256Precompile>(bytecode, calldata, gas_limit)
}

/// `run` with `P` as the hash precompile.
pub fn run_with<P: HashPrecompile>(bytecode: &[u8], calldata: &[u8], gas_limit: u64) -> Outcome {
    let code_len = bytecode.len();
    let mut padded = Vec::with_capacity(code_len + PADDING);
    padded.extend_from_slice(bytecode);
    padded.resize(code_len + PADDING, 0);
    let code = padded.as_slice();
    let mut stack: Vec<U256> = Vec::with_capacity(STACK_LIMIT);
    let s = stack.as_mut_ptr();
    let mut sp = 0usize;
    let mut pc = 0usize;
    let mut gas = gas_limit.min(i64::MAX as u64) as i64;
    let mut memory = Memory::default();
    let mut ret = [0u8; 32];
    let mut ret_len = 0usize;
    let mut jumps: Option<Vec<u8>> = None;

    macro_rules! done {
        ($result:expr, $gas:expr) => {
            return Outcome { result: $result, gas_left: $gas as u64 }
        };
    }
    macro_rules! halt {
        ($reason:ident) => {
            done!(Err(Error::Halt(InstructionResult::$reason)), 0)
        };
    }
    macro_rules! expand {
        ($offset:expr, $len:expr) => {
            match memory.ensure(gas, $offset, $len) {
                Ok(left) => gas = left,
                Err(reason) => done!(Err(Error::Halt(reason)), 0),
            }
        };
    }
    // Static costs are subtracted without a check. The balance is checked
    // wherever gas is observable (jumps, GAS, calls, memory growth, return,
    // revert, stop), so running out in between still ends in a halt before
    // anything leaves the interpreter.
    macro_rules! take {
        ($cost:expr) => {
            gas -= $cost
        };
    }
    macro_rules! sync {
        () => {
            if gas < 0 {
                halt!(OutOfGas)
            }
        };
    }
    // Dynamic costs are checked when charged.
    macro_rules! charge {
        ($cost:expr) => {{
            let cost: u64 = $cost;
            if gas < 0 || cost > gas as u64 {
                halt!(OutOfGas)
            }
            gas -= cost as i64;
        }};
    }
    macro_rules! need {
        ($n:expr) => {
            if sp < $n {
                halt!(StackUnderflow)
            }
        };
    }
    // Item `i` from the top; callers check the stack height first.
    macro_rules! get {
        ($i:expr) => {
            unsafe { *s.add(sp - 1 - $i) }
        };
    }
    macro_rules! set {
        ($i:expr, $v:expr) => {{
            let v = $v;
            unsafe { *s.add(sp - 1 - $i) = v }
        }};
    }
    macro_rules! push {
        ($v:expr) => {{
            let v = $v;
            unsafe { *s.add(sp) = v }
            sp += 1;
        }};
    }
    macro_rules! usize_or_halt {
        ($v:expr) => {
            match to_usize(&$v) {
                Some(x) => x,
                None => halt!(InvalidOperandOOG),
            }
        };
    }
    // Pop two, push f(top, second).
    macro_rules! binary {
        ($cost:expr, |$a:ident, $b:ident| $e:expr) => {{
            take!($cost);
            need!(2);
            let $a = get!(0);
            let $b = get!(1);
            set!(1, $e);
            sp -= 1;
            pc += 1;
        }};
    }
    macro_rules! unary {
        ($cost:expr, |$a:ident| $e:expr) => {{
            take!($cost);
            need!(1);
            let $a = get!(0);
            set!(0, $e);
            pc += 1;
        }};
    }
    macro_rules! push_value {
        ($cost:expr, $v:expr) => {{
            take!($cost);
            if sp >= STACK_LIMIT {
                halt!(StackOverflow)
            }
            push!($v);
            pc += 1;
        }};
    }

    loop {
        let op = unsafe { *code.get_unchecked(pc) };
        match op {
            0x00 => {
                sync!();
                done!(Err(Error::MissingReturn), gas)
            }
            0x01 => binary!(3, |a, b| a.wrapping_add(b)),
            0x02 => binary!(5, |a, b| a.wrapping_mul(b)),
            0x03 => binary!(3, |a, b| a.wrapping_sub(b)),
            0x04 => binary!(5, |a, b| if b.is_zero() { b } else { a.wrapping_div(b) }),
            0x05 => binary!(5, |a, b| i256_div(a, b)),
            0x06 => binary!(5, |a, b| if b.is_zero() { b } else { a.wrapping_rem(b) }),
            0x07 => binary!(5, |a, b| i256_mod(a, b)),
            0x08 | 0x09 => {
                take!(8);
                need!(3);
                let (a, b, n) = (get!(0), get!(1), get!(2));
                set!(2, if op == 0x08 { a.add_mod(b, n) } else { a.mul_mod(b, n) });
                sp -= 2;
                pc += 1;
            }
            0x0a => {
                take!(10);
                need!(2);
                let (a, b) = (get!(0), get!(1));
                if !b.is_zero() {
                    charge!(50 * ((255 - b.leading_zeros() as u64) / 8 + 1));
                }
                set!(1, a.pow(b));
                sp -= 1;
                pc += 1;
            }
            0x0b => binary!(5, |ext, x| signextend(ext, x)),
            0x10 => binary!(3, |a, b| U256::from(a < b)),
            0x11 => binary!(3, |a, b| U256::from(a > b)),
            0x12 => binary!(3, |a, b| U256::from(i256_cmp(&a, &b) == Ordering::Less)),
            0x13 => binary!(3, |a, b| U256::from(i256_cmp(&a, &b) == Ordering::Greater)),
            0x14 => binary!(3, |a, b| U256::from(a == b)),
            0x15 => unary!(3, |a| U256::from(a.is_zero())),
            0x16 => binary!(3, |a, b| a & b),
            0x17 => binary!(3, |a, b| a | b),
            0x18 => binary!(3, |a, b| a ^ b),
            0x19 => unary!(3, |a| !a),
            0x1a => binary!(3, |i, x| {
                let i = saturated(&i);
                if i < 32 { U256::from(x.byte(31 - i)) } else { U256::ZERO }
            }),
            0x1b => binary!(3, |n, x| {
                let n = saturated(&n);
                if n < 256 { x << n } else { U256::ZERO }
            }),
            0x1c => binary!(3, |n, x| {
                let n = saturated(&n);
                if n < 256 { x >> n } else { U256::ZERO }
            }),
            0x1d => binary!(3, |n, x| {
                let n = saturated(&n);
                if n < 256 {
                    x.arithmetic_shr(n)
                } else if x.bit(255) {
                    U256::MAX
                } else {
                    U256::ZERO
                }
            }),
            0x20 => {
                take!(30);
                need!(2);
                let offset = get!(0);
                let len = usize_or_halt!(get!(1));
                charge!(6u64.saturating_mul(words(len)));
                let hash = if len == 0 {
                    KECCAK_EMPTY
                } else {
                    let offset = usize_or_halt!(offset);
                    expand!(offset, len);
                    keccak256(&memory.data[offset..offset + len])
                };
                sp -= 1;
                set!(0, U256::from_be_bytes(hash.0));
                pc += 1;
            }
            0x34 => push_value!(2, U256::ZERO),
            0x35 => {
                take!(3);
                need!(1);
                set!(0, calldata_word(calldata, saturated(&get!(0))));
                pc += 1;
            }
            0x36 => push_value!(2, U256::from(calldata.len())),
            0x37 | 0x39 => {
                take!(3);
                need!(3);
                let (dst, src, len) = (get!(0), get!(1), get!(2));
                sp -= 3;
                let len = usize_or_halt!(len);
                charge!(3u64.saturating_mul(words(len)));
                if len != 0 {
                    let dst = usize_or_halt!(dst);
                    expand!(dst, len);
                    let source = if op == 0x37 { calldata } else { &code[..code_len] };
                    set_data(&mut memory.data, source, dst, saturated(&src), len);
                }
                pc += 1;
            }
            0x38 => push_value!(2, U256::from(code_len)),
            0x3d => push_value!(2, U256::from(ret_len)),
            0x3e => {
                take!(3);
                need!(3);
                let (dst, src, len) = (get!(0), get!(1), get!(2));
                sp -= 3;
                let len = usize_or_halt!(len);
                let src = saturated(&src);
                if src.saturating_add(len) > ret_len {
                    halt!(OutOfOffset)
                }
                charge!(3u64.saturating_mul(words(len)));
                if len != 0 {
                    let dst = usize_or_halt!(dst);
                    expand!(dst, len);
                    set_data(&mut memory.data, &ret[..ret_len], dst, src, len);
                }
                pc += 1;
            }
            0x50 => {
                take!(2);
                need!(1);
                sp -= 1;
                pc += 1;
            }
            0x51 => {
                take!(3);
                need!(1);
                let offset = usize_or_halt!(get!(0));
                expand!(offset, 32);
                set!(0, load_word(&memory.data[offset..offset + 32]));
                pc += 1;
            }
            0x52 => {
                take!(3);
                need!(2);
                let (offset, value) = (get!(0), get!(1));
                sp -= 2;
                let offset = usize_or_halt!(offset);
                expand!(offset, 32);
                store_word(&mut memory.data[offset..offset + 32], &value);
                pc += 1;
            }
            0x53 => {
                take!(3);
                need!(2);
                let (offset, value) = (get!(0), get!(1));
                sp -= 2;
                let offset = usize_or_halt!(offset);
                expand!(offset, 1);
                memory.data[offset] = value.as_limbs()[0] as u8;
                pc += 1;
            }
            0x56 => {
                take!(8);
                sync!();
                need!(1);
                let target = saturated(&get!(0));
                sp -= 1;
                if !valid_jump(&mut jumps, &code[..code_len], target) {
                    halt!(InvalidJump)
                }
                pc = target;
            }
            0x57 => {
                take!(10);
                sync!();
                need!(2);
                let (target, condition) = (get!(0), get!(1));
                sp -= 2;
                if condition.is_zero() {
                    pc += 1;
                } else {
                    let target = saturated(&target);
                    if !valid_jump(&mut jumps, &code[..code_len], target) {
                        halt!(InvalidJump)
                    }
                    pc = target;
                }
            }
            0x58 => push_value!(2, U256::from(pc)),
            0x59 => push_value!(2, U256::from(memory.data.len())),
            0x5a => {
                take!(2);
                sync!();
                if sp >= STACK_LIMIT {
                    halt!(StackOverflow)
                }
                push!(U256::from(gas as u64));
                pc += 1;
            }
            0x5b => {
                take!(1);
                pc += 1;
            }
            0x5e => {
                take!(3);
                need!(3);
                let (dst, src, len) = (get!(0), get!(1), get!(2));
                sp -= 3;
                let len = usize_or_halt!(len);
                charge!(3u64.saturating_mul(words(len)));
                if len != 0 {
                    let dst = usize_or_halt!(dst);
                    let src = usize_or_halt!(src);
                    expand!(max(dst, src), len);
                    memory.data.copy_within(src..src + len, dst);
                }
                pc += 1;
            }
            0x5f => push_value!(2, U256::ZERO),
            // The padding keeps every immediate read inside `code`.
            0x60 => {
                take!(3);
                if sp >= STACK_LIMIT {
                    halt!(StackOverflow)
                }
                push!(U256::from_limbs([unsafe { *code.get_unchecked(pc + 1) } as u64, 0, 0, 0]));
                pc += 2;
            }
            0x61 => {
                take!(3);
                if sp >= STACK_LIMIT {
                    halt!(StackOverflow)
                }
                let (hi, lo) = unsafe { (*code.get_unchecked(pc + 1), *code.get_unchecked(pc + 2)) };
                push!(U256::from_limbs([(hi as u64) << 8 | lo as u64, 0, 0, 0]));
                pc += 3;
            }
            0x62..=0x7f => {
                take!(3);
                if sp >= STACK_LIMIT {
                    halt!(StackOverflow)
                }
                let n = (op - 0x5f) as usize;
                push!(push_value(&code[pc + 1..pc + 1 + n]));
                pc += 1 + n;
            }
            0x80..=0x8f => {
                take!(3);
                let n = (op - 0x7f) as usize;
                if sp < n || sp >= STACK_LIMIT {
                    halt!(StackOverflow)
                }
                push!(get!(n - 1));
                pc += 1;
            }
            0x90..=0x9f => {
                take!(3);
                let n = (op - 0x8f) as usize;
                if n >= sp {
                    halt!(StackUnderflow)
                }
                unsafe { core::ptr::swap_nonoverlapping(s.add(sp - 1), s.add(sp - 1 - n), 1) };
                pc += 1;
            }
            0xf3 | 0xfd => {
                sync!();
                need!(2);
                let (offset, len) = (get!(0), get!(1));
                let len = usize_or_halt!(len);
                let mut output = Vec::new();
                if len != 0 {
                    let offset = usize_or_halt!(offset);
                    expand!(offset, len);
                    output = memory.data[offset..offset + len].to_vec();
                }
                sync!();
                if op == 0xfd {
                    done!(Err(Error::Revert(output)), gas)
                }
                if output.is_empty() {
                    done!(Err(Error::MissingReturn), gas)
                }
                done!(Ok(output), gas)
            }
            0xfa => {
                take!(100);
                sync!();
                need!(6);
                let (requested, to) = (get!(0), get!(1));
                let (in_offset, in_len, out_offset, out_len) = (get!(2), get!(3), get!(4), get!(5));
                sp -= 6;
                let requested = u64::try_from(requested).unwrap_or(u64::MAX);
                let in_len = usize_or_halt!(in_len);
                let mut input_at = 0;
                if in_len != 0 {
                    input_at = usize_or_halt!(in_offset);
                    expand!(input_at, in_len);
                }
                let out_len = usize_or_halt!(out_len);
                let mut output_at = 0;
                if out_len != 0 {
                    output_at = usize_or_halt!(out_offset);
                    expand!(output_at, out_len);
                }
                // The harness host reports every account warm, so the access
                // costs only the static 100. EIP-150: forward at most 63/64.
                sync!();
                let available = gas as u64;
                let limit = min(available - available / 64, requested);
                gas -= limit as i64;
                if !is_precompile(&to, P::ADDRESS) {
                    done!(Err(Error::UnsupportedFrame), 0)
                }
                let cost = P::cost(in_len);
                let success = cost <= limit;
                if success {
                    gas += (limit - cost) as i64;
                    ret = P::hash(&memory.data[input_at..input_at + in_len]);
                    ret_len = 32;
                    let n = min(out_len, 32);
                    memory.data[output_at..output_at + n].copy_from_slice(&ret[..n]);
                } else {
                    ret_len = 0;
                }
                push!(U256::from(success));
                pc += 1;
            }
            0xfe => halt!(InvalidFEOpcode),
            // An explicit 0xff arm lets the dispatch table cover all 256 bytes.
            0xff => halt!(OpcodeNotFound),
            _ => halt!(OpcodeNotFound),
        }
    }
}
