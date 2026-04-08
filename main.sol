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
    event NJR_RoleAdminChanged(bytes32 indexed role, bytes32 indexed oldAdmin, bytes32 indexed newAdmin);

    mapping(bytes32 role => mapping(address account => bool)) internal _hasRole;
    mapping(bytes32 role => bytes32) internal _adminOf;

    bytes32 public constant ROLE_ADMIN = keccak256("NURJAMA_ROLE_ADMIN");
    bytes32 public constant ROLE_GUARDIAN = keccak256("NURJAMA_ROLE_GUARDIAN");
    bytes32 public constant ROLE_SIGNALER = keccak256("NURJAMA_ROLE_SIGNALER");
    bytes32 public constant ROLE_EXECUTOR = keccak256("NURJAMA_ROLE_EXECUTOR");
    bytes32 public constant ROLE_TREASURER = keccak256("NURJAMA_ROLE_TREASURER");

    modifier onlyRole(bytes32 role) {
        if (!_hasRole[role][msg.sender]) revert NJR_NotRole(role);
        _;
    }

    function hasRole(bytes32 role, address a) external view returns (bool) {
        return _hasRole[role][a];
    }

    function getRoleAdmin(bytes32 role) external view returns (bytes32) {
        bytes32 a = _adminOf[role];
        return a == bytes32(0) ? ROLE_ADMIN : a;
    }

    function _roleAdmin(bytes32 role) internal view returns (bytes32) {
        bytes32 a = _adminOf[role];
        return a == bytes32(0) ? ROLE_ADMIN : a;
    }

    function setRoleAdmin(bytes32 role, bytes32 newAdmin) external onlyOwner {
        if (role == bytes32(0) || newAdmin == bytes32(0)) revert NJR_BadInput();
        bytes32 oldAdmin = _roleAdmin(role);
        _adminOf[role] = newAdmin;
        emit NJR_RoleAdminChanged(role, oldAdmin, newAdmin);
    }

    function grantRole(bytes32 role, address a) external {
        bytes32 admin = _roleAdmin(role);
        if (!_hasRole[admin][msg.sender] && msg.sender != owner) revert NJO_Unauthorized();
        _grantRole(role, a);
    }

    function revokeRole(bytes32 role, address a) external {
        bytes32 admin = _roleAdmin(role);
        if (!_hasRole[admin][msg.sender] && msg.sender != owner) revert NJO_Unauthorized();
        _revokeRole(role, a);
    }

    function renounceRole(bytes32 role) external {
        _revokeRole(role, msg.sender);
    }

    function _grantRole(bytes32 role, address a) internal {
        if (role == bytes32(0) || a == address(0)) revert NJR_BadInput();
        if (_hasRole[role][a]) return;
        _hasRole[role][a] = true;
        emit NJR_RoleGranted(role, a, msg.sender);
    }

    function _revokeRole(bytes32 role, address a) internal {
        if (role == bytes32(0) || a == address(0)) revert NJR_BadInput();
        if (!_hasRole[role][a]) return;
        _hasRole[role][a] = false;
        emit NJR_RoleRevoked(role, a, msg.sender);
    }
}

/// @dev A small pausability module (guardian-controlled).
abstract contract NJPausable is NJRoles {
    error NJP_Paused();
    error NJP_Same();

    event NJP_PauseSet(bool paused, address indexed guardian);

    bool public paused;

    modifier whenActive() {
        if (paused) revert NJP_Paused();
        _;
    }

    function setPaused(bool on) external onlyRole(ROLE_GUARDIAN) {
        if (paused == on) revert NJP_Same();
        paused = on;
        emit NJP_PauseSet(on, msg.sender);
    }
}

/// @dev EIP-712 domain with deterministic salt.
abstract contract NJEIP712 {
    bytes32 internal immutable _DOMAIN_SEPARATOR;
    uint256 internal immutable _DOMAIN_CHAIN_ID;

    bytes32 internal constant _TYPEHASH_EIP712DOMAIN =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");

    constructor(string memory name, string memory version, bytes32 salt) {
        _DOMAIN_CHAIN_ID = block.chainid;
        _DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                _TYPEHASH_EIP712DOMAIN,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                block.chainid,
                address(this),
                salt
            )
        );
    }

    function domainSeparator() public view returns (bytes32) {
        if (block.chainid == _DOMAIN_CHAIN_ID) return _DOMAIN_SEPARATOR;
        // Recompute on forks.
        return keccak256(
            abi.encode(
                _TYPEHASH_EIP712DOMAIN,
                keccak256(bytes("NurJama_AII")),
                keccak256(bytes("1")),
                block.chainid,
                address(this),
                bytes32(uint256(0x4e55524a414d415f4149495f53414c545f5a45524f)) // "NURJAMA_AII_SALT_ZERO"
            )
        );
    }

    function _hashTypedData(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }
}

/// @dev Signature checks supporting EOAs and EIP-1271 smart accounts.
library NJSign {
    error NJS_BadSignature();
    error NJS_BadSigner();
    error NJS_Expired();

    bytes4 internal constant MAGICVALUE = 0x1626ba7e;

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert NJS_BadSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 0x20))
            v := byte(0, calldataload(add(sig.offset, 0x40)))
        }
        // EIP-2 / malleability check for s.
        if (uint256(s) > 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff) revert NJS_BadSignature();
        if (v != 27 && v != 28) revert NJS_BadSignature();
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert NJS_BadSignature();
        return signer;
    }

    function isValid(address signer, bytes32 digest, bytes calldata sig) internal view returns (bool) {
        if (signer.code.length == 0) {
            return _recover(digest, sig) == signer;
        }
        try IERC1271(signer).isValidSignature(digest, sig) returns (bytes4 magic) {
            return magic == MAGICVALUE;
        } catch {
            return false;
        }
    }
}

/// @notice NurJama_AII: onchain signal registry + risk-gated execution governor.
contract NurJama_AII is NJPausable, NJReentrancy, NJEIP712 {
    using NJMath for uint256;
    using NJSafeERC20 for IERC20Minimal;

    // ============
    // Errors
    // ============
    error NJX_Zero();
    error NJX_NotFound();
    error NJX_Already();
    error NJX_Disabled();
    error NJX_Range();
    error NJX_TooLong();
    error NJX_TooSoon();
    error NJX_TooLate();
    error NJX_BadNonce();
    error NJX_BadState();
    error NJX_BadVenue();
    error NJX_BadToken();
    error NJX_Risk();
    error NJX_Forbidden();
    error NJX_Slippage();
    error NJX_ValueMismatch();
    error NJX_SignalMismatch();
    error NJX_Untrusted();
    error NJX_Cooldown();
    error NJX_Lock();
    error NJX_InvalidBytes();

    // ============
    // Events
    // ============
    event NJX_Bootstrap(bytes32 indexed genesis, address indexed owner, uint64 at);
    event NJX_VenueSet(address indexed venue, bool allowed, bytes32 meta);
    event NJX_TokenSet(address indexed token, bool allowed, uint8 decimalsHint, bytes32 meta);
    event NJX_SignalCommitted(bytes32 indexed signalId, address indexed author, bytes32 indexed model, uint64 eta, uint64 ttl);
    event NJX_SignalRevealed(bytes32 indexed signalId, address indexed author, bytes32 indexed leaf, bytes32 paramsHash);
    event NJX_RunQueued(bytes32 indexed runId, bytes32 indexed signalId, address indexed venue, uint64 executeAfter);
    event NJX_RunExecuted(bytes32 indexed runId, bytes32 indexed signalId, uint256 spent, uint256 received);
    event NJX_RunCancelled(bytes32 indexed runId, bytes32 indexed signalId, address indexed by);
    event NJX_VaultSweep(address indexed token, address indexed to, uint256 amount);
    event NJX_RiskParamsSet(bytes32 indexed key, uint256 a, uint256 b, uint256 c);
    event NJX_ModelKeySet(bytes32 indexed model, bytes32 indexed keyHash, bool enabled);
    event NJX_OracleHint(bytes32 indexed model, bytes32 indexed hint);
    event NJX_NonceUsed(address indexed author, uint256 indexed nonce, bytes32 indexed tag);
    event NJX_ArbiterSet(address indexed oldArbiter, address indexed newArbiter);
    event NJX_ExecutionLimitSet(uint256 indexed maxCalls, uint256 indexed maxBytes);
    event NJX_CooldownSet(uint64 indexed secondsMin);
    event NJX_OperatorNonceBumped(address indexed operator, uint64 indexed bumpTo);
    event NJX_ProofOfLife(bytes32 indexed ping, uint64 indexed at);

    // ============
    // Types
    // ============
    enum SignalState {
        Nil,
        Committed,
        Revealed,
        Expired,
        Cancelled
    }

    enum RunState {
        None,
        Queued,
        Executed,
        Cancelled
    }

    struct SignalCommit {
        address author;
        bytes32 model;
        bytes32 commitHash;
        uint64 committedAt;
        uint64 eta;
        uint64 ttl;
        uint64 revealAt;
        SignalState state;
        uint64 reservedA;
        uint64 reservedB;
    }

    struct Run {
        bytes32 signalId;
        address venue;
        address inputToken;
        address outputToken;
        uint256 inputAmount;
        uint256 minOutputAmount;
        uint64 queuedAt;
        uint64 executeAfter;
        uint64 deadline;
        RunState state;
        uint256 spent;
        uint256 received;
        bytes32 opaque;
    }

    struct VenueConfig {
        bool allowed;
        uint64 addedAt;
        bytes32 meta;
    }

    struct TokenConfig {
        bool allowed;
        uint8 decimalsHint;
        uint64 addedAt;
        bytes32 meta;
    }

    struct RiskParams {
        uint256 maxInputPerRun;
        uint256 maxInputPerDay;
        uint256 maxSlippageBps;
        uint256 minDelay;
        uint256 maxDelay;
