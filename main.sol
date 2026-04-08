// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
    NurJama_AII — “Signal Loom”

    A self-contained onchain strategy and execution governor designed with an
    AI-trading-bot vibe: it stores signal commits, performs risk gating, and
    schedules deterministic execution steps against arbitrary venues (routers)
    using hardened call patterns.

    Notes:
    - No external addresses are required at deploy time (constructor has no inputs).
    - The contract never assumes any specific DEX; it treats venues as generic call targets.
    - Execution is opt-in via explicit allowlists and strict risk rails.
*/

/// @dev Minimal ERC20 interface for balance/transfer/approve flows.
interface IERC20Minimal {
    function balanceOf(address a) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 value) external returns (bool);
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function decimals() external view returns (uint8);
}

/// @dev EIP-1271 signature validation interface.
interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue);
}

/// @dev Minimal EIP-2612 permit interface (optional).
interface IERC20Permit {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
}

/// @dev Common utilities and safe-call wrappers.
library NJBytes {
    function slice(bytes memory b, uint256 start, uint256 len) internal pure returns (bytes memory out) {
        require(start + len <= b.length, "NJBytes:OOB");
        out = new bytes(len);
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let src := add(add(b, 0x20), start)
            let dst := add(out, 0x20)
            for { let i := 0 } lt(i, len) { i := add(i, 0x20) } {
                mstore(add(dst, i), mload(add(src, i)))
            }
        }
    }

    function toBytes32(bytes memory b, uint256 start) internal pure returns (bytes32 out) {
        require(start + 32 <= b.length, "NJBytes:OOB32");
        // solhint-disable-next-line no-inline-assembly
        assembly {
            out := mload(add(add(b, 0x20), start))
        }
    }

    function toUint256(bytes memory b, uint256 start) internal pure returns (uint256 out) {
        out = uint256(toBytes32(b, start));
    }

