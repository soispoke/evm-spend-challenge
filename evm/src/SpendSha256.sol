// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @notice Baseline EVM entry for the spend challenge: the minimal shielded
/// pool's two-input, two-output spend over a depth-20 tree, SHA-256 edition.
/// Calldata is the raw 1,680-byte input. The fallback returns the 32-byte
/// statement digest or reverts with the violated rule. Every hash is a call to
/// the SHA-256 precompile at 0x02. Checks on private data avoid short-circuit
/// evaluation so every valid input executes the same instructions.
contract SpendSha256 {
    uint256 private constant DEPTH = 20;
    uint256 private constant INPUT_BYTES = 1680;
    uint256 private constant NOTE_BYTES = 724;
    uint256 private constant NOTES_AT = 136;
    uint256 private constant OUTPUTS_AT = 1584;
    bytes32 private constant SINK0 = bytes32(uint256(1));
    bytes32 private constant SINK1 = bytes32(uint256(2));

    /// Rule codes follow the oracle's order: 0 length, 1 index range,
    /// 2 membership, 3 nonzero input, 4 conservation, 5 zero-output sink,
    /// 6 positive output not a sink, 7 authorizer, 8 recipient, 9 distinct
    /// nullifiers, 10 distinct outputs.
    error Rule(uint8 code);

    fallback(bytes calldata input) external returns (bytes memory) {
        if (input.length != INPUT_BYTES) revert Rule(0);
        (bytes32 nullifier0, uint256 in0) = spend(input, 0);
        (bytes32 nullifier1, uint256 in1) = spend(input, 1);
        (bytes32 commitment0, uint256 out0) = create(input, 0);
        (bytes32 commitment1, uint256 out1) = create(input, 1);
        checkPublic(input, in0 + in1, out0 + out1);
        if (nullifier0 == nullifier1) revert Rule(9);
        if (commitment0 == commitment1) revert Rule(10);
        // The statement's public fields end with the first 136 input bytes:
        // root, domain, public amount, fee, recipient and authorizer.
        return abi.encodePacked(
            sha256(abi.encodePacked(uint8(8), nullifier0, nullifier1, commitment0, commitment1, input[0:136]))
        );
    }

    /// Check input note `k` and return its nullifier and value.
    function spend(bytes calldata input, uint256 k) private view returns (bytes32 nullifier, uint256 value) {
        uint256 at = NOTES_AT + k * NOTE_BYTES;
        bytes32 spendKey = bytes32(input[at:at + 32]);
        value = uint128(bytes16(input[at + 64:at + 80]));
        uint32 index = uint32(bytes4(input[at + 80:at + 84]));
        if (index >= 1 << DEPTH) revert Rule(1);
        bytes32 owner = sha256(abi.encodePacked(uint8(1), spendKey));
        bytes32 inner = sha256(abi.encodePacked(uint8(5), owner, bytes32(input[at + 32:at + 64])));
        bytes32 commitment = sha256(abi.encodePacked(uint8(2), inner, uint128(value)));
        bytes32 node = climb(input, at + 84, commitment, index);
        // Dummy inputs carry zero value and need not be members.
        if (!either(node == bytes32(input[0:32]), value == 0)) revert Rule(2);
        bytes32 occurrence = sha256(abi.encodePacked(uint8(7), commitment, index));
        bytes32 nullifierKey = sha256(abi.encodePacked(uint8(6), bytes32(input[32:64]), spendKey));
        nullifier = sha256(abi.encodePacked(uint8(3), nullifierKey, occurrence));
    }

    /// Hash `node` up the path whose siblings start at calldata offset `path`.
    function climb(bytes calldata input, uint256 path, bytes32 node, uint32 index) private view returns (bytes32) {
        for (uint256 level; level < DEPTH; ++level) {
            uint256 s = path + level * 32;
            (bytes32 left, bytes32 right) = order(node, bytes32(input[s:s + 32]), (index >> level) & 1);
            node = sha256(abi.encodePacked(uint8(4), left, right));
        }
        return node;
    }

    /// Check output `k` and return its commitment and value.
    function create(bytes calldata input, uint256 k) private view returns (bytes32 commitment, uint256 value) {
        uint256 at = OUTPUTS_AT + k * 48;
        bytes32 inner = bytes32(input[at:at + 32]);
        value = uint128(bytes16(input[at + 32:at + 48]));
        if (!either(value != 0, inner == (k == 0 ? SINK0 : SINK1))) revert Rule(5);
        if (!either(value == 0, !either(inner == SINK0, inner == SINK1))) revert Rule(6);
        commitment = sha256(abi.encodePacked(uint8(2), inner, uint128(value)));
    }

    /// Value and address rules over the public fields. Sums are exact: two
    /// u128 inputs and four u128 outputs cannot overflow a uint256.
    function checkPublic(bytes calldata input, uint256 totalIn, uint256 outputs) private pure {
        uint128 publicAmount = uint128(bytes16(input[64:80]));
        uint128 fee = uint128(bytes16(input[80:96]));
        if (totalIn == 0) revert Rule(3);
        if (totalIn != outputs + publicAmount + fee) revert Rule(4);
        if (bytes20(input[116:136]) == bytes20(0)) revert Rule(7);
        if ((publicAmount == 0) != (bytes20(input[96:116]) == bytes20(0))) revert Rule(8);
    }

    /// Put `node` on the right exactly when `bit` is 1, by masking.
    function order(bytes32 node, bytes32 sibling, uint256 bit) private pure returns (bytes32 left, bytes32 right) {
        assembly {
            let swap := and(xor(node, sibling), sub(0, bit))
            left := xor(node, swap)
            right := xor(sibling, swap)
        }
    }

    /// Logical or without short-circuit evaluation.
    function either(bool a, bool b) private pure returns (bool result) {
        assembly {
            result := or(a, b)
        }
    }
}
