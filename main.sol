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

    function eq(bytes32 a, bytes32 c) internal pure returns (bool) {
        return a == c;
    }
}

library NJMath {
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    function clamp(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {
        require(lo <= hi, "NJMath:range");
        if (x < lo) return lo;
        if (x > hi) return hi;
        return x;
    }

    function satSub(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            return a > b ? a - b : 0;
        }
    }

    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b != 0, "NJMath:div0");
        unchecked {
            return a == 0 ? 0 : ((a - 1) / b) + 1;
        }
    }

    function absDiff(uint256 a, uint256 b) internal pure returns (uint256) {
        return a >= b ? a - b : b - a;
    }
}

library NJHash {
    function mix(bytes32 a, bytes32 b, bytes32 c) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b, c));
    }

    function mix4(bytes32 a, bytes32 b, bytes32 c, bytes32 d) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b, c, d));
    }

    function mixBytes(bytes32 a, bytes memory b) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b));
    }
}

library NJAddress {
    error NJA_CallFailed();
    error NJA_StaticFailed();
    error NJA_DelegateFailed();
    error NJA_ZeroAddress();
    error NJA_NonContract();

    function _isContract(address a) internal view returns (bool ok) {
        uint256 s;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            s := extcodesize(a)
        }
        ok = s != 0;
    }

    function requireContract(address a) internal view {
        if (a == address(0)) revert NJA_ZeroAddress();
        if (!_isContract(a)) revert NJA_NonContract();
    }

    function safeCall(address target, uint256 value, bytes memory data, uint256 gasStipend)
        internal
        returns (bytes memory ret)
    {
        if (target == address(0)) revert NJA_ZeroAddress();
        bool ok;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            ok := call(gasStipend, target, value, add(data, 0x20), mload(data), 0, 0)
            let size := returndatasize()
            ret := mload(0x40)
            mstore(0x40, add(ret, add(size, 0x60)))
            mstore(ret, size)
            returndatacopy(add(ret, 0x20), 0, size)
        }
        if (!ok) revert NJA_CallFailed();
    }

    function safeStaticCall(address target, bytes memory data, uint256 gasStipend)
        internal
        view
        returns (bytes memory ret)
    {
        if (target == address(0)) revert NJA_ZeroAddress();
        bool ok;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            ok := staticcall(gasStipend, target, add(data, 0x20), mload(data), 0, 0)
            let size := returndatasize()
            ret := mload(0x40)
            mstore(0x40, add(ret, add(size, 0x60)))
            mstore(ret, size)
            returndatacopy(add(ret, 0x20), 0, size)
        }
        if (!ok) revert NJA_StaticFailed();
    }
}

library NJSafeERC20 {
    using NJAddress for address;

    error NJT_ApproveFailed();
    error NJT_TransferFailed();
    error NJT_TransferFromFailed();

    function _callOptionalReturn(address token, bytes memory data) private returns (bytes memory ret) {
        ret = NJAddress.safeCall(token, 0, data, gasleft());
        if (ret.length == 0) return ret;
        // Some tokens do not return bool; if they do, require true.
        if (ret.length >= 32) {
            uint256 v = uint256(bytes32(ret[0:32]));
            require(v == 1, "NJSafeERC20:false");
        }
    }

    function safeTransfer(IERC20Minimal token, address to, uint256 value) internal {
        bytes memory ret = _callOptionalReturn(
            address(token),
            abi.encodeWithSelector(IERC20Minimal.transfer.selector, to, value)
        );
        if (ret.length >= 32 && abi.decode(ret, (bool)) == false) revert NJT_TransferFailed();
    }

    function safeTransferFrom(IERC20Minimal token, address from, address to, uint256 value) internal {
        bytes memory ret = _callOptionalReturn(
            address(token),
            abi.encodeWithSelector(IERC20Minimal.transferFrom.selector, from, to, value)
        );
        if (ret.length >= 32 && abi.decode(ret, (bool)) == false) revert NJT_TransferFromFailed();
    }

    function safeApprove(IERC20Minimal token, address spender, uint256 value) internal {
        bytes memory ret = _callOptionalReturn(
            address(token),
            abi.encodeWithSelector(IERC20Minimal.approve.selector, spender, value)
        );
        if (ret.length >= 32 && abi.decode(ret, (bool)) == false) revert NJT_ApproveFailed();
    }
}

/// @dev Compact reentrancy guard with explicit states.
abstract contract NJReentrancy {
    error NJR_Reentrancy();
    uint256 private _njLock;

    modifier nonReentrant() {
        if (_njLock == 2) revert NJR_Reentrancy();
        _njLock = 2;
        _;
        _njLock = 1;
    }

    constructor() {
        _njLock = 1;
    }
}

/// @dev Two-step ownership for safe handovers.
abstract contract NJOwnable2Step {
    error NJO_Unauthorized();
    error NJO_Zero();
    error NJO_PendingMismatch();

    event NJO_OwnerProposed(address indexed owner, address indexed proposed);
    event NJO_OwnerAccepted(address indexed oldOwner, address indexed newOwner);

    address public owner;
    address public pendingOwner;

    modifier onlyOwner() {
        if (msg.sender != owner) revert NJO_Unauthorized();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function proposeOwner(address next) external onlyOwner {
        if (next == address(0)) revert NJO_Zero();
        pendingOwner = next;
        emit NJO_OwnerProposed(owner, next);
    }

    function acceptOwner() external {
        address p = pendingOwner;
        if (p == address(0)) revert NJO_Zero();
        if (msg.sender != p) revert NJO_PendingMismatch();
        address old = owner;
        owner = p;
        pendingOwner = address(0);
        emit NJO_OwnerAccepted(old, p);
    }
}

/// @dev Role system: small, explicit, and gas-conscious.
abstract contract NJRoles is NJOwnable2Step {
    error NJR_NotRole(bytes32 role);
    error NJR_BadInput();

    event NJR_RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event NJR_RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
