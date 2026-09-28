#!/usr/bin/env python3
"""Generate the two EVM control programs used to split an entry's cost.

calls-55.hex makes the statement's 55 SHA-256 precompile calls, chained, with
the same message lengths as a spend and nothing else. It returns the same
digest as the Rust hashing control. calls-0.hex runs the same prelude and
returns without any call.
"""
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Per input note: owner key, inner, commitment, 20 tree nodes, occurrence,
# nullifier key, nullifier. Then two output commitments and the statement.
SCHEDULE = ([33, 65, 49] + [65] * 20 + [37, 65, 65]) * 2 + [49, 49, 265]


def push(value: int) -> list:
    if value == 0:
        return [0x5f]
    if value < 256:
        return [0x60, value]
    return [0x61, value >> 8, value & 0xff]


def program(calls: int) -> bytes:
    code = push(265) + push(0) + push(0) + [0x37]      # CALLDATACOPY(0, 0, 265)
    code += push(32) + push(265) + push(1) + [0x37]    # CALLDATACOPY(1, 265, 32)
    for i, length in enumerate(SCHEDULE[:calls]):
        code += push(i) + push(0) + [0x53]             # MSTORE8(0, i)
        code += push(32) + push(1) + push(length) + push(0) + push(2) + [0x5a, 0xfa, 0x50]  # STATICCALL, POP
    code += push(32) + push(1) + [0xf3]                # RETURN(1, 32)
    return bytes(code)


if __name__ == "__main__":
    assert len(SCHEDULE) == 55
    for calls in (55, 0):
        (HERE / f"calls-{calls}.hex").write_text(program(calls).hex() + "\n")
    print("wrote calls-55.hex and calls-0.hex")
