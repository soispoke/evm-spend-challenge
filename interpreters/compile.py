#!/usr/bin/env python3
"""Compile EVM bytecode ahead of time into one Rust function.

This measures the cost of running an EVM program with no interpreter at all:
the generated function has no dispatch loop, keeps stack values in local
variables within each basic block, and checks stack bounds once per block.
It keeps the harness rules: the same gas for every instruction, the same
halting conditions and the same results, using the helpers in
`interpreters/src/support.rs`. Static gas is subtracted without a check and
the balance is checked wherever gas is observable (jumps, GAS, calls, memory
growth, return, revert, stop); a block ends after every instruction that can
end the run without a halt, so checking a block's stack bounds at its start
cannot turn such an ending into a halt.

A prover using compiled code would need the verifier to trust the compiler or
a proof that the compiled program matches the bytecode; this is a measurement
of the limit, not a proposal.

Usage: python3 interpreters/compile.py BYTECODE_HEX OUT.rs
"""
import sys
from pathlib import Path

DISABLED = {0x30, 0x31, 0x32, 0x33, 0x3A, 0x3B, 0x3C, 0x3F, *range(0x40, 0x4B), 0x54, 0x55, 0x5C, 0x5D,
            *range(0xA0, 0xA5), 0xF0, 0xF1, 0xF2, 0xF4, 0xF5, 0xFF}
STATIC_GAS = {0x00: 0, 0x01: 3, 0x02: 5, 0x03: 3, 0x04: 5, 0x05: 5, 0x06: 5, 0x07: 5, 0x08: 8, 0x09: 8, 0x0A: 10,
              0x0B: 5, **{op: 3 for op in range(0x10, 0x1E)}, 0x20: 30, 0x34: 2, 0x35: 3, 0x36: 2, 0x37: 3, 0x38: 2,
              0x39: 3, 0x3D: 2, 0x3E: 3, 0x50: 2, 0x51: 3, 0x52: 3, 0x53: 3, 0x56: 8, 0x57: 10, 0x58: 2, 0x59: 2,
              0x5A: 2, 0x5B: 1, 0x5E: 3, 0x5F: 2, **{op: 3 for op in range(0x60, 0xA0)}, 0xF3: 0, 0xFA: 100, 0xFD: 0}
BINARY = {
    0x01: "{a}.wrapping_add({b})", 0x02: "{a}.wrapping_mul({b})", 0x03: "{a}.wrapping_sub({b})",
    0x04: "if {b}.is_zero() {{ {b} }} else {{ {a}.wrapping_div({b}) }}", 0x05: "i256_div({a}, {b})",
    0x06: "if {b}.is_zero() {{ {b} }} else {{ {a}.wrapping_rem({b}) }}", 0x07: "i256_mod({a}, {b})",
    0x0B: "signextend({a}, {b})", 0x10: "U256::from({a} < {b})", 0x11: "U256::from({a} > {b})",
    0x12: "U256::from(i256_cmp(&{a}, &{b}) == core::cmp::Ordering::Less)",
    0x13: "U256::from(i256_cmp(&{a}, &{b}) == core::cmp::Ordering::Greater)", 0x14: "U256::from({a} == {b})",
    0x16: "{a} & {b}", 0x17: "{a} | {b}", 0x18: "{a} ^ {b}",
    0x1A: "{{ let i = saturated(&{a}); if i < 32 {{ U256::from({b}.byte(31 - i)) }} else {{ U256::ZERO }} }}",
    0x1B: "{{ let n = saturated(&{a}); if n < 256 {{ {b} << n }} else {{ U256::ZERO }} }}",
    0x1C: "{{ let n = saturated(&{a}); if n < 256 {{ {b} >> n }} else {{ U256::ZERO }} }}",
    0x1D: "{{ let n = saturated(&{a}); if n < 256 {{ {b}.arithmetic_shr(n) }} else if {b}.bit(255) {{ U256::MAX }} "
          "else {{ U256::ZERO }} }}",
}
UNARY = {0x15: "U256::from({a}.is_zero())", 0x19: "!{a}"}
# Instructions that push through REVM's checked push, so they can overflow.
CHECKED_PUSH = {0x34, 0x36, 0x38, 0x3D, 0x58, 0x59, 0x5A, 0x5F, *range(0x60, 0x90)}
# A block ends after these: jumps, and every instruction that can end the run.
ENDS_BLOCK = {0x00, 0x56, 0x57, 0xF3, 0xFA, 0xFD, 0xFE}


def decode(code: bytes):
    instructions, pc = [], 0
    while pc < len(code):
        op = code[pc]
        width = op - 0x5F if 0x60 <= op <= 0x7F else 0
        immediate = code[pc + 1:pc + 1 + width].ljust(width, b"\0")
        instructions.append((pc, op, int.from_bytes(immediate, "big") if width else 0))
        pc += 1 + width
    return instructions


def supported(op: int) -> bool:
    return op in STATIC_GAS and op not in DISABLED


def blocks_of(instructions):
    blocks, current = [], []
    for pc, op, value in instructions:
        if op == 0x5B and current:
            blocks.append(current)
            current = []
        current.append((pc, op, value))
        if op in ENDS_BLOCK or not supported(op):
            blocks.append(current)
            current = []
    if current:
        blocks.append(current)
    return blocks


def limbs(value: int) -> str:
    return "[" + ", ".join(f"{(value >> (64 * i)) & (2**64 - 1):#x}" for i in range(4)) + "]"


class Block:
    """Symbolic stack for one basic block: values are Rust locals."""

    def __init__(self):
        self.lines, self.model, self.consumed = [], [], 0
        self.need, self.grow, self.count, self.constants = 0, 0, 0, {}

    def height(self):
        return len(self.model) - self.consumed

    def require(self, k: int):
        self.need = max(self.need, k - self.height())
        while len(self.model) < k:
            name = f"e{self.consumed}"
            self.lines.append(f"let {name} = unsafe {{ *s.add(b - {self.consumed + 1}) }};")
            self.model.insert(0, name)
            self.consumed += 1

    def pop(self):
        return self.model.pop()

    def new(self, expression: str, checked: bool = False, constant=None) -> str:
        name = f"v{self.count}"
        self.count += 1
        self.lines.append(f"let {name}: U256 = {expression};")
        self.model.append(name)
        if constant is not None:
            self.constants[name] = constant
        if checked:
            self.grow = max(self.grow, self.height())
        return name

    def write_back(self):
        for i, name in enumerate(self.model):
            if name == f"e{self.consumed - 1 - i}":
                continue
            self.lines.append(f"unsafe {{ *s.add(b - {self.consumed} + {i}) = {name} }};")
        self.lines.append(f"sp = b - {self.consumed} + {len(self.model)};")


def compile_program(code: bytes) -> str:
    instructions = decode(code)
    blocks = blocks_of(instructions)
    ids = {block[0][0]: i for i, block in enumerate(blocks)}
    jumpdests = {block[0][0]: i for i, block in enumerate(blocks) if block[0][1] == 0x5B}

    def jump(target: str, blk: Block) -> str:
        if target in blk.constants:
            value = blk.constants[target]
            return f"block = {jumpdests[value]};" if value in jumpdests else "halt!(InvalidJump)"
        arms = " ".join(f"{pc} => {i}," for pc, i in sorted(jumpdests.items()))
        return f"block = match saturated(&{target}) {{ {arms} _ => halt!(InvalidJump) }};"

    arms = []
    for index, block in enumerate(blocks):
        blk = Block()
        ended = False
        for pc, op, value in block:
            if not supported(op):
                blk.lines.append("halt!(InvalidFEOpcode)" if op == 0xFE else "halt!(OpcodeNotFound)")
                ended = True
                break
            if STATIC_GAS[op]:
                blk.lines.append(f"gas -= {STATIC_GAS[op]};")
            if op in BINARY:
                blk.require(2)
                a, b = blk.pop(), blk.pop()
                blk.new(BINARY[op].format(a=a, b=b))
            elif op in UNARY:
                blk.require(1)
                blk.new(UNARY[op].format(a=blk.pop()))
            elif op in (0x08, 0x09):
                blk.require(3)
                a, b, c = blk.pop(), blk.pop(), blk.pop()
                blk.new(f"{a}.{'add_mod' if op == 0x08 else 'mul_mod'}({b}, {c})")
            elif op == 0x0A:
                blk.require(2)
                a, b = blk.pop(), blk.pop()
                blk.lines.append(f"if !{b}.is_zero() {{ charge!(50 * ((255 - {b}.leading_zeros() as u64) / 8 + 1)); }}")
                blk.new(f"{a}.pow({b})")
            elif op == 0x20:
                blk.require(2)
                a, b = blk.pop(), blk.pop()
                blk.new(f"{{ let len = usize_or_halt!({b}); charge!(6u64.saturating_mul(words(len))); "
                        f"let h = if len == 0 {{ KECCAK_EMPTY }} else {{ let o = usize_or_halt!({a}); expand!(o, len); "
                        f"keccak256(&memory.data[o..o + len]) }}; U256::from_be_bytes(h.0) }}")
            elif op == 0x34:
                blk.new("U256::ZERO", checked=True, constant=0)
            elif op == 0x35:
                blk.require(1)
                blk.new(f"calldata_word(calldata, saturated(&{blk.pop()}))")
            elif op == 0x36:
                blk.new("U256::from(calldata.len())", checked=True)
            elif op in (0x37, 0x39, 0x3E, 0x5E):
                blk.require(3)
                a, b, c = blk.pop(), blk.pop(), blk.pop()
                check = (f"let src = saturated(&{b}); if src.saturating_add(len) > ret_len {{ halt!(OutOfOffset) }} "
                         if op == 0x3E else "")
                if op == 0x5E:
                    body = (f"let d = usize_or_halt!({a}); let src = usize_or_halt!({b}); "
                            f"expand!(core::cmp::max(d, src), len); memory.data.copy_within(src..src + len, d);")
                else:
                    source = {0x37: "calldata", 0x39: "&CODE[..]", 0x3E: "&ret[..ret_len]"}[op]
                    src = "src" if op == 0x3E else f"saturated(&{b})"
                    body = f"let d = usize_or_halt!({a}); expand!(d, len); set_data(&mut memory.data, {source}, d, {src}, len);"
                blk.lines.append(f"{{ let len = usize_or_halt!({c}); {check}charge!(3u64.saturating_mul(words(len))); "
                                 f"if len != 0 {{ {body} }} }}")
            elif op == 0x38:
                blk.new(f"U256::from({len(code)}u64)", checked=True, constant=len(code))
            elif op == 0x3D:
                blk.new("U256::from(ret_len)", checked=True)
            elif op == 0x50:
                blk.require(1)
                blk.pop()
            elif op == 0x51:
                blk.require(1)
                blk.new(f"{{ let o = usize_or_halt!({blk.pop()}); expand!(o, 32); load_word(&memory.data[o..o + 32]) }}")
            elif op in (0x52, 0x53):
                blk.require(2)
                a, b = blk.pop(), blk.pop()
                if op == 0x52:
                    blk.lines.append(f"{{ let o = usize_or_halt!({a}); expand!(o, 32); "
                                     f"store_word(&mut memory.data[o..o + 32], &{b}); }}")
                else:
                    blk.lines.append(f"{{ let o = usize_or_halt!({a}); expand!(o, 1); "
                                     f"memory.data[o] = {b}.as_limbs()[0] as u8; }}")
            elif op == 0x56:
                blk.require(1)
                blk.lines.append("sync!();")
                target = blk.pop()
                blk.write_back()
                blk.lines.append(jump(target, blk))
                ended = True
            elif op == 0x57:
                blk.require(2)
                blk.lines.append("sync!();")
                target, condition = blk.pop(), blk.pop()
                blk.write_back()
                following = ids.get(block[-1][0] + 1 + (block[-1][1] - 0x5F if 0x60 <= block[-1][1] <= 0x7F else 0))
                fallthrough = f"block = {following};" if following is not None else "sync!(); done!(Err(Error::MissingReturn), gas)"
                blk.lines.append(f"if !{condition}.is_zero() {{ {jump(target, blk)} }} else {{ {fallthrough} }}")
                ended = True
            elif op == 0x58:
                blk.new(f"U256::from({pc}u64)", checked=True, constant=pc)
            elif op == 0x59:
                blk.new("U256::from(memory.data.len())", checked=True)
            elif op == 0x5A:
                blk.lines.append("sync!();")
                blk.new("U256::from(gas as u64)", checked=True)
            elif op == 0x5B:
                pass
            elif op == 0x5F or 0x60 <= op <= 0x7F:
                blk.new(f"U256::from_limbs({limbs(value)})", checked=True, constant=value)
            elif 0x80 <= op <= 0x8F:
                n = op - 0x7F
                blk.require(n)
                blk.model.append(blk.model[-n])
                blk.grow = max(blk.grow, blk.height())
            elif 0x90 <= op <= 0x9F:
                n = op - 0x8F
                blk.require(n + 1)
                blk.model[-1], blk.model[-1 - n] = blk.model[-1 - n], blk.model[-1]
            elif op == 0x00:
                blk.lines.append("sync!(); done!(Err(Error::MissingReturn), gas)")
                ended = True
            elif op in (0xF3, 0xFD):
                blk.require(2)
                a, b = blk.pop(), blk.pop()
                result = ("Err(Error::Revert(output))" if op == 0xFD else
                          "if output.is_empty() { Err(Error::MissingReturn) } else { Ok(output) }")
                blk.lines.append(f"sync!(); let len = usize_or_halt!({b}); let mut output = Vec::new(); "
                                 f"if len != 0 {{ let o = usize_or_halt!({a}); expand!(o, len); "
                                 f"output = memory.data[o..o + len].to_vec(); }} done!({result}, gas)")
                ended = True
            elif op == 0xFA:
                blk.require(6)
                blk.lines.append("sync!();")
                g, to, io, il, oo, ol = (blk.pop() for _ in range(6))
                blk.new(f"""{{
                    let requested = u64::try_from({g}).unwrap_or(u64::MAX);
                    let in_len = usize_or_halt!({il});
                    let mut input_at = 0;
                    if in_len != 0 {{ input_at = usize_or_halt!({io}); expand!(input_at, in_len); }}
                    let out_len = usize_or_halt!({ol});
                    let mut output_at = 0;
                    if out_len != 0 {{ output_at = usize_or_halt!({oo}); expand!(output_at, out_len); }}
                    let available = gas as u64;
                    let limit = core::cmp::min(available - available / 64, requested);
                    gas -= limit as i64;
                    if !is_precompile(&{to}, P::ADDRESS) {{ done!(Err(Error::UnsupportedFrame), 0) }}
                    let cost = P::cost(in_len);
                    let success = cost <= limit;
                    if success {{
                        gas += (limit - cost) as i64;
                        ret = P::hash(&memory.data[input_at..input_at + in_len]);
                        ret_len = 32;
                        let n = core::cmp::min(out_len, 32);
                        memory.data[output_at..output_at + n].copy_from_slice(&ret[..n]);
                    }} else {{
                        ret_len = 0;
                    }}
                    U256::from(success)
                }}""")
            else:
                raise AssertionError(f"unhandled opcode {op:#x}")
        if not ended:
            last_pc, last_op, _ = block[-1]
            next_pc = last_pc + 1 + (last_op - 0x5F if 0x60 <= last_op <= 0x7F else 0)
            blk.write_back()
            blk.lines.append(f"block = {ids[next_pc]};" if next_pc in ids else "sync!(); done!(Err(Error::MissingReturn), gas)")
        checks = []
        if blk.need > 0:
            checks.append(f"if b < {blk.need} {{ halt!(StackUnderflow) }}")
        if blk.grow > 0:
            checks.append(f"if b + {blk.grow} > 1024 {{ halt!(StackOverflow) }}")
        body = "\n                ".join(["let b = sp;", *checks, *blk.lines])
        arms.append(f"            {index} => {{ // pc {block[0][0]}\n                {body}\n            }}")
    code_bytes = ", ".join(str(x) for x in code)
    return f"""// Generated by interpreters/compile.py from {len(code)} bytes of EVM code. Do not edit.
#[allow(unused_imports)]
use alloc::vec::Vec;
#[allow(unused_imports)]
use spend_evm_interpreters::{{
    i256_cmp, i256_div, i256_mod, keccak256, support::*, Error, HashPrecompile, InstructionResult, Outcome,
    Sha256Precompile, GAS_LIMIT, KECCAK_EMPTY, U256,
}};

#[allow(dead_code)]
const CODE: [u8; {len(code)}] = [{code_bytes}];

#[allow(dead_code)]
pub fn execute(calldata: &[u8]) -> Result<Vec<u8>, Error> {{
    run(calldata, GAS_LIMIT).result
}}

#[allow(dead_code)]
pub fn run(calldata: &[u8], gas_limit: u64) -> Outcome {{
    run_with::<Sha256Precompile>(calldata, gas_limit)
}}

/// `run` with `P` as the hash precompile.
#[allow(unused_mut, unused_variables, unused_assignments, unreachable_code, clippy::all)]
pub fn run_with<P: HashPrecompile>(calldata: &[u8], gas_limit: u64) -> Outcome {{
    let mut stack: Vec<U256> = Vec::with_capacity(1024);
    let s = stack.as_mut_ptr();
    let mut sp = 0usize;
    let mut gas = gas_limit.min(i64::MAX as u64) as i64;
    let mut memory = Memory::default();
    let mut ret = [0u8; 32];
    let mut ret_len = 0usize;
    let mut block = 0u32;
    macro_rules! done {{
        ($result:expr, $gas:expr) => {{
            return Outcome {{ result: $result, gas_left: $gas as u64 }}
        }};
    }}
    macro_rules! halt {{
        ($reason:ident) => {{
            done!(Err(Error::Halt(InstructionResult::$reason)), 0)
        }};
    }}
    macro_rules! sync {{
        () => {{
            if gas < 0 {{
                halt!(OutOfGas)
            }}
        }};
    }}
    macro_rules! charge {{
        ($cost:expr) => {{{{
            let cost: u64 = $cost;
            if gas < 0 || cost > gas as u64 {{
                halt!(OutOfGas)
            }}
            gas -= cost as i64;
        }}}};
    }}
    macro_rules! expand {{
        ($offset:expr, $len:expr) => {{
            match memory.ensure(gas, $offset, $len) {{
                Ok(left) => gas = left,
                Err(reason) => done!(Err(Error::Halt(reason)), 0),
            }}
        }};
    }}
    macro_rules! usize_or_halt {{
        ($v:expr) => {{
            match to_usize(&$v) {{
                Some(x) => x,
                None => halt!(InvalidOperandOOG),
            }}
        }};
    }}
    loop {{
        match block {{
{chr(10).join(arms)}
            _ => unreachable!(),
        }}
    }}
}}
"""


def main() -> int:
    code = bytes.fromhex(Path(sys.argv[1]).read_text().strip())
    if code[:2] == b"\xef\x01":
        raise SystemExit("0xEF01 prefix: not a legacy program")
    Path(sys.argv[2]).write_text(compile_program(code))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
