// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from  "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title SimpleSmartWallet
 * @notice An advanced implementation of an account abstraction compatible smart wallet
 * @dev Supports owner management, batching, spending limits, and emergency recovery
 */
contract SimpleSmartWallet is ReentrancyGuard {
    using ECDSA for bytes32;

    // Structures
    struct Transaction {
        address to;
        uint256 value;
        bytes data;
    }

    struct SpendingLimit {
        uint256 amount;
        uint256 resetTime;
        uint256 spent;
    }

    // Constants
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 private constant TX_TYPEHASH = keccak256(
        "Transaction(address to,uint256 value,bytes data,uint256 nonce,uint256 deadline)"
    );

    uint256 private constant RESET_TIMEFRAME = 1 days;
    
    // State variables
    mapping(address => bool) public owners;
    mapping(address => SpendingLimit) public spendingLimits;
    address public guardian;
    uint256 public required;
    uint256 public nonce;
    uint256 public immutable CHAIN_ID;
    bytes32 public immutable DOMAIN_SEPARATOR;
    bool public locked;

    // Events
    event OwnerAdded(address indexed owner);
    event OwnerRemoved(address indexed owner);
    event GuardianSet(address indexed oldGuardian, address indexed newGuardian);
    event TransactionExecuted(address indexed to, uint256 value, bytes data, uint256 nonce);
    event BatchExecuted(uint256 indexed batchId, uint256 nonce);
    event SpendingLimitSet(address indexed owner, uint256 amount);
    event WalletLocked(address indexed by);
    event WalletUnlocked(address indexed by);

    modifier onlyOwner() {
        require(owners[msg.sender], "Not an owner");
        _;
    }

    modifier notLocked() {
        require(!locked, "Wallet is locked");
        _;
    }

    modifier onlyGuardian() {
        require(msg.sender == guardian, "Not the guardian");
        _;
    }

    constructor(
        address[] memory _owners,
        uint256 _required,
        address _guardian
    ) {
        require(_owners.length > 0, "At least one owner required");
        require(
            _required > 0 && _required <= _owners.length,
            "Invalid required number of owners"
        );
        require(_guardian != address(0), "Invalid guardian address");

        for (uint256 i = 0; i < _owners.length; i++) {
            address owner = _owners[i];
            require(owner != address(0), "Invalid owner address");
            require(!owners[owner], "Duplicate owner");
            owners[owner] = true;
            emit OwnerAdded(owner);
        }

        required = _required;
        guardian = _guardian;
        CHAIN_ID = block.chainid;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256("SimpleSmartWallet"),
                keccak256("1"),
                CHAIN_ID,
                address(this)
            )
        );
    }

    // Owner Management Functions
    function addOwner(address newOwner, bytes[] calldata signatures) external notLocked {
        require(newOwner != address(0), "Invalid owner address");
        require(!owners[newOwner], "Already an owner");

        bytes32 hash = keccak256(abi.encodePacked("addOwner", newOwner, nonce));
        _validateSignatures(hash, signatures);

        owners[newOwner] = true;
        emit OwnerAdded(newOwner);
    }

    function removeOwner(address owner, bytes[] calldata signatures) external notLocked {
        require(owners[owner], "Not an owner");
        require(msg.sender != owner, "Cannot remove self");

        bytes32 hash = keccak256(abi.encodePacked("removeOwner", owner, nonce));
        _validateSignatures(hash, signatures);

        owners[owner] = false;
        emit OwnerRemoved(owner);
    }

    // Transaction Execution Functions
    function executeTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint256 deadline,
        bytes[] calldata signatures
    ) external nonReentrant notLocked {
        require(block.timestamp <= deadline, "Transaction expired");
        
        bytes32 txHash = generateTransactionHash(to, value, data, nonce, deadline);
        bytes32 ethSignedHash = generateSignedHash(txHash);
        _validateSignatures(ethSignedHash, signatures);

        _executeTransaction(to, value, data);
    }

    function executeBatch(
        Transaction[] calldata transactions,
        uint256 deadline,
        bytes[] calldata signatures
    ) external nonReentrant notLocked {
        require(block.timestamp <= deadline, "Batch expired");
        require(transactions.length > 0, "Empty batch");

        bytes32 batchHash = keccak256(abi.encode(transactions, nonce, deadline));
        bytes32 ethSignedHash = generateSignedHash(batchHash);
        _validateSignatures(ethSignedHash, signatures);

        uint256 batchId = uint256(batchHash);
        for (uint256 i = 0; i < transactions.length; i++) {
            Transaction memory txn = transactions[i];
            _executeTransaction(txn.to, txn.value, txn.data);
        }

        emit BatchExecuted(batchId, nonce - 1);
    }

    // Spending Limit Functions
    function setSpendingLimit(address owner, uint256 amount) external onlyOwner {
        require(owners[owner], "Not an owner");
        spendingLimits[owner] = SpendingLimit({
            amount: amount,
            resetTime: block.timestamp + RESET_TIMEFRAME,
            spent: 0
        });
        emit SpendingLimitSet(owner, amount);
    }

    function executeUnderLimit(
        address to,
        uint256 value,
        bytes calldata data
    ) external onlyOwner notLocked {
        SpendingLimit storage limit = spendingLimits[msg.sender];
        require(limit.amount > 0, "No spending limit set");

        if (block.timestamp >= limit.resetTime) {
            limit.spent = 0;
            limit.resetTime = block.timestamp + RESET_TIMEFRAME;
        }

        require(limit.spent + value <= limit.amount, "Spending limit exceeded");
        limit.spent += value;

        _executeTransaction(to, value, data);
    }

    // Guardian Functions
    function setGuardian(address newGuardian, bytes[] calldata signatures) external notLocked {
        require(newGuardian != address(0), "Invalid guardian address");
        
        bytes32 hash = keccak256(abi.encodePacked("setGuardian", newGuardian, nonce));
        _validateSignatures(hash, signatures);

        address oldGuardian = guardian;
        guardian = newGuardian;
        emit GuardianSet(oldGuardian, newGuardian);
    }

    function lockWallet() external onlyGuardian {
        locked = true;
        emit WalletLocked(msg.sender);
    }

    function unlockWallet(bytes[] calldata signatures) external {
        bytes32 hash = keccak256(abi.encodePacked("unlockWallet", nonce));
        _validateSignatures(hash, signatures);

        locked = false;
        emit WalletUnlocked(msg.sender);
    }

    // Internal Functions
    function _executeTransaction(
        address to,
        uint256 value,
        bytes memory data
    ) internal {
        nonce++;
        (bool success, ) = to.call{value: value}(data);
        require(success, "Transaction failed");
        emit TransactionExecuted(to, value, data, nonce - 1);
    }

    function _validateSignatures(bytes32 hash, bytes[] calldata signatures) internal view {
        require(signatures.length >= required, "Not enough signatures");

        bytes32 ethSignedHash = generateSignedHash(hash);
        address[] memory recoveredSigners = new address[](signatures.length);

        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = ethSignedHash.recover(signatures[i]);
            require(owners[signer], "Invalid signer");
            
            for (uint256 j = 0; j < i; j++) {
                require(signer != recoveredSigners[j], "Duplicate signature");
            }
            recoveredSigners[i] = signer;
        }
    }

    // Public Helper Functions
    function generateTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        uint256 _nonce,
        uint256 deadline
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encode(TX_TYPEHASH, to, value, keccak256(data), _nonce, deadline)
        );
    }

    function generateSignedHash(bytes32 hash) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                hash
            )
        );
    }

    // Native token reception
    receive() external payable {}
}