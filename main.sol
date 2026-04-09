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
        uint256 maxTtl;
        uint256 cooldownSeconds;
        uint256 maxCalls;
        uint256 maxCalldataBytes;
        uint256 reserved0;
        uint256 reserved1;
        uint256 reserved2;
    }

    // ============
    // Storage
    // ============
    bytes32 public immutable GENESIS;
    bytes32 public immutable LOOM_ID;
    bytes32 public immutable BOOT_SALT;

    // model => keyHash => enabled
    mapping(bytes32 model => mapping(bytes32 keyHash => bool enabled)) public modelKeyEnabled;
    mapping(bytes32 model => bytes32 hint) public oracleHint;

    // signalId => commit struct
    mapping(bytes32 signalId => SignalCommit) public signals;
    // runId => run struct
    mapping(bytes32 runId => Run) public runs;

    // allowlists
    mapping(address venue => VenueConfig) public venues;
    mapping(address token => TokenConfig) public tokens;

    // nonces and operator bumps
    mapping(address author => uint256 nonce) public authorNonce;
    mapping(address operator => uint64 bump) public operatorNonceBump;

    // spending rails
    mapping(uint64 day => uint256 spent) public dailySpent;
    mapping(bytes32 signalId => bool used) public consumedSignal;

    // governance knobs
    RiskParams public risk;
    address public arbiter;

    // ============
    // Constants (distinct, non-OZ naming)
    // ============
    uint256 public constant BPS = 10_000;
    uint256 public constant NJ_VERSION_SEM = 0x0001000000000000000000000000000000000000000000000000000000000001;
    bytes32 public constant TYPEHASH_COMMIT =
        keccak256("NJCommit(bytes32 signalId,bytes32 model,bytes32 commitHash,uint64 eta,uint64 ttl,uint256 nonce,uint64 bump,bytes32 tag)");
    bytes32 public constant TYPEHASH_REVEAL =
        keccak256("NJReveal(bytes32 signalId,bytes32 leaf,bytes32 paramsHash,uint256 nonce,uint64 bump,bytes32 tag)");
    bytes32 public constant TYPEHASH_QUEUE =
        keccak256(
            "NJQueue(bytes32 runId,bytes32 signalId,address venue,address inputToken,address outputToken,uint256 inputAmount,uint256 minOutputAmount,uint64 executeAfter,uint64 deadline,uint256 nonce,uint64 bump,bytes32 tag)"
        );

    // ============
    // Constructor
    // ============
    constructor()
        NJEIP712("NurJama_AII", "1", bytes32(uint256(0x4e55524a414d415f4149495f53414c545f5a45524f)))
    {
        // Deterministic but unguessable enough for uniqueness within this codebase:
        // it mixes chain id, deployer, timestamp, and codehash of this contract at creation.
        bytes32 g = keccak256(
            abi.encodePacked(
                block.chainid,
                msg.sender,
                block.timestamp,
                block.prevrandao,
                keccak256(type(NurJama_AII).creationCode)
            )
        );
        GENESIS = g;
        LOOM_ID = keccak256(abi.encodePacked("NURJAMA_LOOM", g, address(this)));
        BOOT_SALT = keccak256(abi.encodePacked("NURJAMA_BOOT", g, uint256(0x9d3f2b6c7a81e509)));

        // Initial roles: owner is also admin/guardian/signal/executor/treasurer.
        _grantRole(ROLE_ADMIN, msg.sender);
        _grantRole(ROLE_GUARDIAN, msg.sender);
        _grantRole(ROLE_SIGNALER, msg.sender);
        _grantRole(ROLE_EXECUTOR, msg.sender);
        _grantRole(ROLE_TREASURER, msg.sender);

        // Default risk rails: conservative; changeable by owner (with events).
        risk = RiskParams({
            maxInputPerRun: 250_000 ether,
            maxInputPerDay: 1_000_000 ether,
            maxSlippageBps: 150, // 1.50%
            minDelay: 30,
            maxDelay: 3 days,
            maxTtl: 7 days,
            cooldownSeconds: 12,
            maxCalls: 5,
            maxCalldataBytes: 12_288,
            reserved0: 0,
            reserved1: 0,
            reserved2: 0
        });

        arbiter = msg.sender;
        paused = false;

        emit NJX_Bootstrap(g, msg.sender, uint64(block.timestamp));
        emit NJX_ArbiterSet(address(0), msg.sender);
        emit NJX_ExecutionLimitSet(risk.maxCalls, risk.maxCalldataBytes);
        emit NJX_CooldownSet(uint64(risk.cooldownSeconds));
        emit NJX_ProofOfLife(keccak256(abi.encodePacked(g, block.timestamp)), uint64(block.timestamp));
    }

    // ============
    // Receive
    // ============
    receive() external payable {}

    // ============
    // Admin / governance
    // ============
    function setArbiter(address next) external onlyOwner {
        if (next == address(0)) revert NJX_Zero();
        address old = arbiter;
        arbiter = next;
        emit NJX_ArbiterSet(old, next);
    }

    function setExecutionLimits(uint256 maxCalls, uint256 maxBytes) external onlyOwner {
        if (maxCalls == 0 || maxCalls > 12) revert NJX_Range();
        if (maxBytes < 512 || maxBytes > 98_304) revert NJX_Range();
        risk.maxCalls = maxCalls;
        risk.maxCalldataBytes = maxBytes;
        emit NJX_ExecutionLimitSet(maxCalls, maxBytes);
    }

    function setCooldownSeconds(uint64 secondsMin) external onlyOwner {
        if (secondsMin > 600) revert NJX_Range();
        risk.cooldownSeconds = secondsMin;
        emit NJX_CooldownSet(secondsMin);
    }

    function setRiskParams(
        uint256 maxInputPerRun,
        uint256 maxInputPerDay,
        uint256 maxSlippageBps,
        uint256 minDelay,
        uint256 maxDelay,
        uint256 maxTtl
    ) external onlyOwner {
        if (maxInputPerRun == 0 || maxInputPerDay == 0) revert NJX_Zero();
        if (maxSlippageBps > 1_500) revert NJX_Range();
        if (minDelay < 1 || maxDelay < minDelay) revert NJX_Range();
        if (maxTtl < 60 || maxTtl > 30 days) revert NJX_Range();

        risk.maxInputPerRun = maxInputPerRun;
        risk.maxInputPerDay = maxInputPerDay;
        risk.maxSlippageBps = maxSlippageBps;
        risk.minDelay = minDelay;
        risk.maxDelay = maxDelay;
        risk.maxTtl = maxTtl;

        emit NJX_RiskParamsSet(keccak256("core"), maxInputPerRun, maxInputPerDay, maxSlippageBps);
        emit NJX_RiskParamsSet(keccak256("delay"), minDelay, maxDelay, maxTtl);
    }

    function setVenue(address venue, bool allowed, bytes32 meta) external onlyOwner {
        if (venue == address(0)) revert NJX_Zero();
        venues[venue] = VenueConfig({allowed: allowed, addedAt: uint64(block.timestamp), meta: meta});
        emit NJX_VenueSet(venue, allowed, meta);
    }

    function setToken(address token, bool allowed, uint8 decimalsHint, bytes32 meta) external onlyOwner {
        if (token == address(0)) revert NJX_Zero();
        if (decimalsHint > 36) revert NJX_Range();
        tokens[token] = TokenConfig({allowed: allowed, decimalsHint: decimalsHint, addedAt: uint64(block.timestamp), meta: meta});
        emit NJX_TokenSet(token, allowed, decimalsHint, meta);
    }

    function setModelKey(bytes32 model, bytes32 keyHash, bool enabled) external onlyOwner {
        if (model == bytes32(0) || keyHash == bytes32(0)) revert NJX_Zero();
        modelKeyEnabled[model][keyHash] = enabled;
        emit NJX_ModelKeySet(model, keyHash, enabled);
    }

    function setOracleHint(bytes32 model, bytes32 hint) external onlyOwner {
        if (model == bytes32(0)) revert NJX_Zero();
        oracleHint[model] = hint;
        emit NJX_OracleHint(model, hint);
    }

    // ============
    // Vault tools
    // ============
    function sweep(address token, address to, uint256 amount) external nonReentrant onlyRole(ROLE_TREASURER) {
        if (to == address(0)) revert NJX_Zero();
        if (token == address(0)) {
            // native
            if (amount > address(this).balance) revert NJX_Range();
            (bool ok,) = to.call{value: amount}("");
            if (!ok) revert NJX_Forbidden();
            emit NJX_VaultSweep(address(0), to, amount);
            return;
        }
        IERC20Minimal(token).safeTransfer(to, amount);
        emit NJX_VaultSweep(token, to, amount);
    }

    // ============
    // Signal flow: commit → reveal
    // ============
    function computeSignalId(address author, bytes32 model, bytes32 commitHash, uint64 eta, uint64 ttl, uint256 nonce, uint64 bump, bytes32 tag)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encodePacked("NJ_SIGNAL", LOOM_ID, author, model, commitHash, eta, ttl, nonce, bump, tag, block.chainid));
    }

    function commitSignal(
        bytes32 model,
        bytes32 commitHash,
        uint64 eta,
        uint64 ttl
    ) external whenActive onlyRole(ROLE_SIGNALER) returns (bytes32 signalId) {
        if (model == bytes32(0) || commitHash == bytes32(0)) revert NJX_Zero();
        if (ttl == 0 || ttl > risk.maxTtl) revert NJX_Range();
        if (eta < uint64(block.timestamp) + uint64(risk.minDelay)) revert NJX_TooSoon();
        if (eta > uint64(block.timestamp) + uint64(risk.maxDelay)) revert NJX_TooLate();

        uint256 nonce = authorNonce[msg.sender];
        authorNonce[msg.sender] = nonce + 1;
        uint64 bump = operatorNonceBump[msg.sender];
        bytes32 tag = keccak256(abi.encodePacked("commit", msg.sender, nonce, bump, block.prevrandao, GENESIS));

        signalId = computeSignalId(msg.sender, model, commitHash, eta, ttl, nonce, bump, tag);
        SignalCommit storage s = signals[signalId];
        if (s.state != SignalState.Nil) revert NJX_Already();

        signals[signalId] = SignalCommit({
            author: msg.sender,
            model: model,
            commitHash: commitHash,
            committedAt: uint64(block.timestamp),
            eta: eta,
            ttl: ttl,
            revealAt: 0,
            state: SignalState.Committed,
            reservedA: uint64(uint256(GENESIS)),
            reservedB: uint64(uint256(LOOM_ID))
        });

        emit NJX_NonceUsed(msg.sender, nonce, tag);
        emit NJX_SignalCommitted(signalId, msg.sender, model, eta, uint64(eta + ttl));
    }

    function commitSignalBySig(
        address author,
        bytes32 model,
        bytes32 commitHash,
        uint64 eta,
        uint64 ttl,
        uint256 nonce,
        uint64 bump,
        bytes32 tag,
        bytes calldata signature
    ) external whenActive returns (bytes32 signalId) {
        if (author == address(0)) revert NJX_Zero();
        if (!_hasRole[ROLE_SIGNALER][author]) revert NJX_Forbidden();
        if (ttl == 0 || ttl > risk.maxTtl) revert NJX_Range();
        if (eta < uint64(block.timestamp) + uint64(risk.minDelay)) revert NJX_TooSoon();
        if (eta > uint64(block.timestamp) + uint64(risk.maxDelay)) revert NJX_TooLate();
        if (bump < operatorNonceBump[author]) revert NJX_BadNonce();
        if (nonce != authorNonce[author]) revert NJX_BadNonce();

        bytes32 digest = _hashTypedData(
            keccak256(abi.encode(TYPEHASH_COMMIT, bytes32(0), model, commitHash, eta, ttl, nonce, bump, tag))
        );
        if (!NJSign.isValid(author, digest, signature)) revert NJX_Forbidden();

        authorNonce[author] = nonce + 1;
        operatorNonceBump[author] = bump;

        signalId = computeSignalId(author, model, commitHash, eta, ttl, nonce, bump, tag);
        SignalCommit storage s = signals[signalId];
        if (s.state != SignalState.Nil) revert NJX_Already();

        signals[signalId] = SignalCommit({
            author: author,
            model: model,
            commitHash: commitHash,
            committedAt: uint64(block.timestamp),
            eta: eta,
            ttl: ttl,
            revealAt: 0,
            state: SignalState.Committed,
            reservedA: uint64(uint256(GENESIS)),
            reservedB: uint64(uint256(LOOM_ID))
        });

        emit NJX_NonceUsed(author, nonce, tag);
        emit NJX_OperatorNonceBumped(author, bump);
        emit NJX_SignalCommitted(signalId, author, model, eta, uint64(eta + ttl));
    }

    function revealSignal(
        bytes32 signalId,
        bytes32 leaf,
        bytes32 paramsHash
    ) external whenActive returns (bytes32 leafOut) {
        SignalCommit storage s = signals[signalId];
        if (s.state != SignalState.Committed) revert NJX_BadState();
        if (msg.sender != s.author) revert NJX_Forbidden();
        if (block.timestamp < s.eta) revert NJX_TooSoon();
        if (block.timestamp > s.eta + s.ttl) {
            s.state = SignalState.Expired;
            revert NJX_TooLate();
        }
        if (leaf == bytes32(0) || paramsHash == bytes32(0)) revert NJX_Zero();

        bytes32 check = keccak256(abi.encodePacked("reveal", LOOM_ID, signalId, leaf, paramsHash));
        if (check != s.commitHash) revert NJX_SignalMismatch();

        s.state = SignalState.Revealed;
        s.revealAt = uint64(block.timestamp);
        emit NJX_SignalRevealed(signalId, msg.sender, leaf, paramsHash);
        return leaf;
    }

    function cancelSignal(bytes32 signalId) external whenActive {
        SignalCommit storage s = signals[signalId];
        if (s.state == SignalState.Nil) revert NJX_NotFound();
        if (msg.sender != s.author && msg.sender != owner && !_hasRole[ROLE_GUARDIAN][msg.sender]) revert NJX_Forbidden();
        if (s.state == SignalState.Cancelled) revert NJX_Already();
        if (s.state == SignalState.Expired) revert NJX_Already();
        s.state = SignalState.Cancelled;
    }

    // ============
    // Execution queue
    // ============
    function computeRunId(
        bytes32 signalId,
        address venue,
        address inputToken,
        address outputToken,
        uint256 inputAmount,
        uint256 minOutputAmount,
        uint64 executeAfter,
        uint64 deadline,
        bytes32 tag
    ) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "NJ_RUN",
                LOOM_ID,
                signalId,
                venue,
                inputToken,
                outputToken,
                inputAmount,
                minOutputAmount,
                executeAfter,
                deadline,
