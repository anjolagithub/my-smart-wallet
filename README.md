# SimpleSmartWallet

A secure and feature-rich smart contract wallet implementation with multi-signature support, account abstraction compatibility, spending limits, and emergency recovery mechanisms.

## Features

- **Multi-signature Support**: Configurable M-of-N signature requirement for transactions
- **Account Abstraction**: EIP-712 compliant signature validation
- **Spending Limits**: Daily spending limits with automatic resets
- **Batch Transactions**: Execute multiple transactions in a single call
- **Guardian System**: Emergency locking and recovery mechanisms
- **Owner Management**: Add or remove owners with multi-sig approval

## Architecture

### Core Components

- **Transaction Execution**: Support for both single and batch transactions
- **Signature Validation**: EIP-712 compliant signature verification
- **Access Control**: Owner and guardian management
- **Spending Controls**: Configurable daily limits per owner

### Security Features

- **Reentrancy Protection**: Guards against reentrant calls
- **Signature Replay Prevention**: Nonce-based transaction uniqueness
- **Duplicate Signature Check**: Prevents same-signer attacks
- **Timelock Support**: Transaction deadline enforcement
- **Emergency Controls**: Guardian-controlled wallet locking

## Installation

```bash
forge install
```

## Usage

### Deployment

Deploy the wallet with initial owners and configuration:

```solidity
// Deploy with 2-of-3 configuration
address[] memory owners = new address[](3);
owners[0] = address(0x123...);
owners[1] = address(0x456...);
owners[2] = address(0x789...);
uint256 required = 2;
address guardian = address(0xABC...);

SimpleSmartWallet wallet = new SimpleSmartWallet(
    owners,
    required,
    guardian
);
```

### Transaction Execution

Execute a single transaction:

```solidity
// Prepare transaction
address to = address(0x123);
uint256 value = 1 ether;
bytes memory data = "";
uint256 deadline = block.timestamp + 1 hours;

// Generate transaction hash
bytes32 txHash = wallet.generateTransactionHash(
    to, 
    value, 
    data, 
    wallet.nonce(), 
    deadline
);

// Get EIP-712 compliant hash
bytes32 signHash = wallet.generateSignedHash(txHash);

// Collect signatures
bytes[] memory signatures = new bytes[](2);
signatures[0] = sign(privateKey1, signHash);
signatures[1] = sign(privateKey2, signHash);

// Execute
wallet.executeTransaction(to, value, data, deadline, signatures);
```

### Batch Transactions

Execute multiple transactions in one call:

```solidity
SimpleSmartWallet.Transaction[] memory txns = new SimpleSmartWallet.Transaction[](2);
txns[0] = SimpleSmartWallet.Transaction(to1, value1, data1);
txns[1] = SimpleSmartWallet.Transaction(to2, value2, data2);

wallet.executeBatch(txns, deadline, signatures);
```

### Spending Limits

Set and use spending limits:

```solidity
// Set limit for an owner
wallet.setSpendingLimit(owner, 1 ether);

// Execute under limit
wallet.executeUnderLimit(to, 0.5 ether, "");
```

### Guardian Functions

Emergency controls:

```solidity
// Lock wallet
wallet.lockWallet();

// Unlock with owner signatures
wallet.unlockWallet(signatures);
```

## Testing

Run the test suite:

```bash
forge test
```

Run with logs:

```bash
forge test -vv
```

## Security Considerations

1. **Signature Validation**
   - All signatures are EIP-712 compliant
   - Nonce-based replay protection
   - Duplicate signature checks

2. **Access Control**
   - Multi-signature requirements
   - Guardian system for emergency control
   - Owner removal restrictions

3. **Transaction Safety**
   - Reentrancy protection
   - Deadline-based execution
   - Spending limits

## Events

Monitor wallet activity through these events:

```solidity
event OwnerAdded(address indexed owner);
event OwnerRemoved(address indexed owner);
event GuardianSet(address indexed oldGuardian, address indexed newGuardian);
event TransactionExecuted(address indexed to, uint256 value, bytes data, uint256 nonce);
event BatchExecuted(uint256 indexed batchId, uint256 nonce);
event SpendingLimitSet(address indexed owner, uint256 amount);
event WalletLocked(address indexed by);
event WalletUnlocked(address indexed by);
```

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.