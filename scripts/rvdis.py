"""Minimal RV64IM disassembler for reading guest profiles (scripts/profile.py)."""
import struct
from pathlib import Path

REG = ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
       "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"]


def text_words(elf: Path) -> dict:
    """Map address -> 32-bit instruction word for every executable section."""
    data = elf.read_bytes()
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)
    words = {}
    for i in range(shnum):
        base = shoff + i * shentsize
        _, sh_type, flags, addr, offset, size = struct.unpack_from("<IIQQQQ", data, base)
        if sh_type == 1 and flags & 0x4:  # PROGBITS, executable
            for j in range(0, size - size % 4, 4):
                words[addr + j] = struct.unpack_from("<I", data, offset + j)[0]
    return words


def sext(value: int, bits: int) -> int:
    return value - (1 << bits) if value >> (bits - 1) else value


def decode(word: int, pc: int) -> str:
    op, rd, f3, rs1, rs2, f7 = word & 0x7F, (word >> 7) & 31, (word >> 12) & 7, (word >> 15) & 31, (word >> 20) & 31, word >> 25
    r = REG
    imm_i = sext(word >> 20, 12)
    if op == 0x37:
        return f"lui {r[rd]}, {hex(word >> 12)}"
    if op == 0x17:
        return f"auipc {r[rd]}, {hex(word >> 12)}"
    if op == 0x6F:
        imm = sext(((word >> 31) << 20) | (((word >> 12) & 0xFF) << 12) | (((word >> 20) & 1) << 11) | (((word >> 21) & 0x3FF) << 1), 21)
        return f"jal {r[rd]}, {hex(pc + imm)}"
    if op == 0x67:
        return f"jalr {r[rd]}, {imm_i}({r[rs1]})"
    if op == 0x63:
        imm = sext(((word >> 31) << 12) | (((word >> 7) & 1) << 11) | (((word >> 25) & 0x3F) << 5) | (((word >> 8) & 0xF) << 1), 13)
        name = {0: "beq", 1: "bne", 4: "blt", 5: "bge", 6: "bltu", 7: "bgeu"}.get(f3, "b?")
        return f"{name} {r[rs1]}, {r[rs2]}, {hex(pc + imm)}"
    if op == 0x03:
        name = {0: "lb", 1: "lh", 2: "lw", 3: "ld", 4: "lbu", 5: "lhu", 6: "lwu"}.get(f3, "l?")
        return f"{name} {r[rd]}, {imm_i}({r[rs1]})"
    if op == 0x23:
        imm = sext(((word >> 25) << 5) | ((word >> 7) & 31), 12)
        name = {0: "sb", 1: "sh", 2: "sw", 3: "sd"}.get(f3, "s?")
        return f"{name} {r[rs2]}, {imm}({r[rs1]})"
    if op in (0x13, 0x1B):
        w = "w" if op == 0x1B else ""
        if f3 == 1:
            return f"slli{w} {r[rd]}, {r[rs1]}, {(word >> 20) & 0x3F}"
        if f3 == 5:
            return f"{'srai' if word >> 30 & 1 else 'srli'}{w} {r[rd]}, {r[rs1]}, {(word >> 20) & 0x3F}"
        name = {0: "addi", 2: "slti", 3: "sltiu", 4: "xori", 6: "ori", 7: "andi"}[f3]
        return f"{name}{w} {r[rd]}, {r[rs1]}, {imm_i}"
    if op in (0x33, 0x3B):
        w = "w" if op == 0x3B else ""
        if f7 == 1:
            name = ["mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu"][f3]
        else:
            name = {(0, 0): "add", (0, 0x20): "sub", (1, 0): "sll", (2, 0): "slt", (3, 0): "sltu", (4, 0): "xor",
                    (5, 0): "srl", (5, 0x20): "sra", (6, 0): "or", (7, 0): "and"}.get((f3, f7), "op?")
        return f"{name}{w} {r[rd]}, {r[rs1]}, {r[rs2]}"
    if op == 0x73:
        return "ecall" if word == 0x73 else f"system {hex(word)}"
    if op == 0x0F:
        return "fence"
    return f".word {hex(word)}"
