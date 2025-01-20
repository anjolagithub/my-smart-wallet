// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {SimpleSmartWallet} from "../src/SimpleSmartWallet.sol";
import {ERC20} from  "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor() ERC20("Mock", "MCK") {
        _mint(msg.sender, 1000000 * 10**18);
    }
}

contract SimpleSmartWalletTest is Test {
    SimpleSmartWallet public wallet;
    MockERC20 public token;
    
    address[] public owners;
    uint256[] private ownerPrivateKeys;
    address public guardian;
    uint256 public guardianPrivateKey;
    
    event OwnerAdded(address indexed owner);
    event OwnerRemoved(address indexed owner);
    event GuardianSet(address indexed oldGuardian, address indexed newGuardian);
    event TransactionExecuted(address indexed to, uint256 value, bytes data, uint256 nonce);
    event BatchExecuted(uint256 indexed batchId, uint256 nonce);
    event SpendingLimitSet(address indexed owner, uint256 amount);
    event WalletLocked(address indexed by);
    event WalletUnlocked(address indexed by);
    
    function setUp() public {
        // Generate owner addresses and private keys
        for (uint256 i = 0; i < 3; i++) {
            uint256 privateKey = uint256(keccak256(abi.encodePacked("owner", i)));
            address owner = vm.addr(privateKey);
            owners.push(owner);
            ownerPrivateKeys.push(privateKey);
        }
        
        // Generate guardian
        guardianPrivateKey = uint256(keccak256(abi.encodePacked("guardian")));
        guardian = vm.addr(guardianPrivateKey);
        
        // Deploy wallet with 2-of-3 configuration
        wallet = new SimpleSmartWallet(owners, 2, guardian);
        
        // Deploy mock token
        token = new MockERC20();
    }

    function testExecuteTransaction() public {
        // Test setup
        address to = address(0x123);
        uint256 value = 1 ether;
        bytes memory data = "";
        uint256 deadline = block.timestamp + 1 hours;
        uint256 currentNonce = wallet.nonce();

        // Create transaction hash using TX_TYPEHASH
        bytes32 txHash = wallet.generateTransactionHash(
            to,
            value,
            data,
            currentNonce,
            deadline
        );
        
        // Generate signatures from two different owners
        // Note: The contract will call generateSignedHash internally for validation
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _sign(ownerPrivateKeys[0], txHash);
        signatures[1] = _sign(ownerPrivateKeys[1], txHash);

        // Fund the wallet
        vm.deal(address(wallet), 2 ether);

        // Execute transaction and verify
        wallet.executeTransaction(to, value, data, deadline, signatures);
        
        // Verify the transfer was successful
        assertEq(address(to).balance, value);
        
        // Verify nonce increased
        assertEq(wallet.nonce(), currentNonce + 1);
    }

    function testAddOwner() public {
        address newOwner = address(0x789);
        bytes32 hash = keccak256(abi.encodePacked("addOwner", newOwner, wallet.nonce()));
        bytes32 ethSignedHash = wallet.generateSignedHash(hash);
        
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _sign(ownerPrivateKeys[0], ethSignedHash);
        signatures[1] = _sign(ownerPrivateKeys[1], ethSignedHash);
        
        vm.expectEmit(true, false, false, true);
        emit OwnerAdded(newOwner);
        wallet.addOwner(newOwner, signatures);
        assertTrue(wallet.owners(newOwner));
    }

    function testRemoveOwner() public {
        address ownerToRemove = owners[2];
        bytes32 hash = keccak256(abi.encodePacked("removeOwner", ownerToRemove, wallet.nonce()));
        bytes32 ethSignedHash = wallet.generateSignedHash(hash);
        
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _sign(ownerPrivateKeys[0], ethSignedHash);
        signatures[1] = _sign(ownerPrivateKeys[1], ethSignedHash);
        
        vm.expectEmit(true, false, false, true);
        emit OwnerRemoved(ownerToRemove);
        wallet.removeOwner(ownerToRemove, signatures);
        assertFalse(wallet.owners(ownerToRemove));
    }

    function testCannotRemoveSelf() public {
        bytes32 hash = keccak256(abi.encodePacked("removeOwner", owners[0], wallet.nonce()));
        bytes32 ethSignedHash = wallet.generateSignedHash(hash);
        
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _sign(ownerPrivateKeys[1], ethSignedHash);
        signatures[1] = _sign(ownerPrivateKeys[2], ethSignedHash);

        vm.prank(owners[0]);
        vm.expectRevert("Cannot remove self");
        wallet.removeOwner(owners[0], signatures);
    }

    function testSetGuardian() public {
        address newGuardian = address(0xABC);
        bytes32 hash = keccak256(abi.encodePacked("setGuardian", newGuardian, wallet.nonce()));
        bytes32 ethSignedHash = wallet.generateSignedHash(hash);
        
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _sign(ownerPrivateKeys[0], ethSignedHash);
        signatures[1] = _sign(ownerPrivateKeys[1], ethSignedHash);
        
        vm.expectEmit(true, true, false, true);
        emit GuardianSet(guardian, newGuardian);
        wallet.setGuardian(newGuardian, signatures);
        assertEq(wallet.guardian(), newGuardian);
    }

    function testGuardianLockUnlock() public {
        // Test locking
        vm.prank(guardian);
        vm.expectEmit(true, false, false, true);
        emit WalletLocked(guardian);
        wallet.lockWallet();
        assertTrue(wallet.locked());

        // Test unlocking
        bytes32 hash = keccak256(abi.encodePacked("unlockWallet", wallet.nonce()));
        bytes32 ethSignedHash = wallet.generateSignedHash(hash);
        
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _sign(ownerPrivateKeys[0], ethSignedHash);
        signatures[1] = _sign(ownerPrivateKeys[1], ethSignedHash);
        
        vm.expectEmit(true, false, false, true);
        emit WalletUnlocked(address(this));
        wallet.unlockWallet(signatures);
        assertFalse(wallet.locked());
    }

    function testSpendingLimitLifecycle() public {
        address spender = owners[0];
        uint256 limitAmount = 1 ether;
        
        // Set limit
        vm.startPrank(owners[1]);
        vm.expectEmit(true, false, false, true);
        emit SpendingLimitSet(spender, limitAmount);
        wallet.setSpendingLimit(spender, limitAmount);
        
        // Fund wallet
        vm.deal(address(wallet), 2 ether);
        vm.stopPrank();

        // First spend
        vm.prank(spender);
        wallet.executeUnderLimit(address(0x123), 0.3 ether, "");
        
        // Second spend
        vm.prank(spender);
        wallet.executeUnderLimit(address(0x456), 0.3 ether, "");
        
        // Time travel to test reset
        vm.warp(block.timestamp + 1 days + 1);
        
        // Spend after reset
        vm.prank(spender);
        wallet.executeUnderLimit(address(0x789), 0.5 ether, "");
    }

    function _sign(uint256 privateKey, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function testSignatureGeneration() public {
        // Create a simple message to sign
        bytes32 message = keccak256(abi.encodePacked("test message"));
        bytes32 ethSignedHash = wallet.generateSignedHash(message);
        
        // Sign with first owner
        bytes memory signature = _sign(ownerPrivateKeys[0], ethSignedHash);
        
        // Split signature back into components
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        
        // Recover signer using ECDSA
        address signer = ecrecover(ethSignedHash, v, r, s);
        
        // Verify recovered signer matches expected owner
        assertTrue(wallet.owners(signer));
        assertEq(signer, owners[0]);
    }
}