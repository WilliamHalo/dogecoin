# BIP39 Mnemonic Support for Dogecoin Core

This document describes the BIP39 mnemonic support added to Dogecoin Core, allowing users to create and restore wallets using human-readable mnemonic phrases.

## Overview

BIP39 (Bitcoin Improvement Proposal 39) defines a standard for creating deterministic cryptocurrency wallets from mnemonic phrases. This implementation allows Dogecoin Core to:

1. Generate new wallets with BIP39 mnemonics
2. Import wallets from existing BIP39 mnemonics
3. Export BIP39 mnemonics from wallets (with proper authentication)
4. Securely encrypt and store mnemonic seeds

## Features

### Core Features
- **Full BIP39 Compliance**: Supports all standard entropy sizes (128, 160, 192, 224, 256 bits)
- **Secure Storage**: Mnemonic seeds are encrypted when the wallet is encrypted
- **Memory Safety**: Seeds are securely erased from memory when the wallet is locked
- **PBKDF2-HMAC-SHA512**: Proper key derivation with 2048 iterations
- **Optional Passphrase**: Support for BIP39 passphrase protection

### Security Features
- Seeds are encrypted with AES-256-CBC when the wallet is encrypted
- Seeds are automatically decrypted when the wallet is unlocked
- Seeds are securely cleared from memory when the wallet is locked
- Access to mnemonics requires wallet passphrase (for encrypted wallets)

## Usage

### Creating a New Wallet with Mnemonic

When creating a new wallet, you can choose to generate it with a BIP39 mnemonic:

```bash
# Generate a new wallet with BIP39 mnemonic (24 words by default)
dogecoind -usehd -usemnemonic

# Or with dogecoin-qt GUI
# 1. Go to Settings > Options
# 2. Enable "Generate BIP39 mnemonic for new wallet"
```

When you first start the wallet with `-usemnemonic`, it will:
1. Generate a random 256-bit entropy (24 words)
2. Display the mnemonic phrase
3. **IMPORTANT**: Write down the mnemonic and store it securely!

### Importing a Wallet from Mnemonic

To import an existing mnemonic into Dogecoin Core:

```bash
# Using RPC command
dogecoin-cli importmnemonic "word1 word2 word3 ... word24"

# With optional passphrase
dogecoin-cli importmnemonic "word1 word2 word3 ... word24" "your_passphrase"

# Response will indicate success or failure
{
  "success": true,
  "message": "Mnemonic imported successfully. The HD master key has been updated.",
  "encrypted": false
}
```

### Exporting the Mnemonic

To view your wallet's mnemonic (requires wallet to be unlocked):

```bash
# Unlock the wallet first
dogecoin-cli walletpassphrase "your_wallet_passphrase" 60

# Export the mnemonic
dogecoin-cli dumpmnemonic

# Response:
{
  "mnemonic": "word1 word2 word3 ... word24",
  "word_count": 24,
  "warning": "NEVER share this mnemonic phrase with anyone. Anyone with access to this phrase can steal all your funds."
}

# Lock the wallet again
dogecoin-cli walletlock
```

### Checking if Wallet Has Mnemonic

```bash
dogecoin-cli hasmnemonic
```

## RPC Commands

### importmnemonic

Imports a BIP39 mnemonic phrase and sets it as the wallet's HD master key.

**Parameters:**
1. `mnemonic` (string, required): The BIP39 mnemonic phrase (12-24 words)
2. `passphrase` (string, optional): Optional passphrase for the mnemonic

**Example:**
```bash
dogecoin-cli importmnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
```

### dumpmnemonic

Returns the BIP39 mnemonic phrase for the wallet's HD master key.

**Requirements:**
- Wallet must have been created with or imported from a mnemonic
- Wallet must be unlocked if encrypted

**Security Warning:** This command exposes your wallet's seed phrase. Use with extreme caution.

## Configuration Options

Add these options to your `dogecoin.conf` or command line:

```conf
# Enable HD wallet support (required for mnemonics)
usehd=1

# Generate wallet with BIP39 mnemonic
usemnemonic=1

# Specify entropy size for new mnemonics (default: 32 bytes = 24 words)
# Valid values: 16 (12 words), 20 (15 words), 24 (18 words), 28 (21 words), 32 (24 words)
mnemonicsize=32
```

## Technical Details

### Implementation

1. **Word List**: 2048 English words from BIP39 standard
2. **Entropy Generation**: Cryptographically secure random number generator
3. **Checksum**: First ENT/32 bits of SHA256(entropy)
4. **Seed Derivation**: PBKDF2-HMAC-SHA512 with 2048 iterations
5. **Salt**: "mnemonic" + optional passphrase

### Storage

- Mnemonic seeds are stored in the wallet database (`wallet.dat`)
- Seeds are encrypted with AES-256-CBC when the wallet is encrypted
- Encryption key is derived from the wallet master key
- Encrypted seeds are stored in the HD chain object

### Key Derivation

The BIP39 seed is used to derive the master private key using BIP32 hierarchical deterministic key derivation:

```
Seed (64 bytes) -> HMAC-SHA512("Bitcoin seed", seed) -> Master Key (32 bytes) + Chain Code (32 bytes)
```

## Security Best Practices

### Mnemonic Backup

1. **Write it down**: Always write your mnemonic on paper or metal
2. **Multiple copies**: Create 2-3 copies stored in different secure locations
3. **Never digital**: Don't store mnemonics on computers, phones, or cloud storage
4. **Test recovery**: Verify you can restore from your backup before depositing funds

### Passphrase Usage

- Optional but highly recommended for additional security
- Acts as a "25th word" - without it, the wallet cannot be recovered
- Different passphrases generate completely different wallets
- Passphrase is case-sensitive

### Encrypted Wallets

- Always encrypt your wallet with a strong passphrase
- The wallet passphrase is different from the BIP39 passphrase
- Wallet passphrase encrypts all keys including the mnemonic seed

## Migration from Legacy Wallets

Existing wallets can be migrated to use BIP39:

1. Create a backup of your existing wallet
2. Create a new wallet with `-usehd -usemnemonic`
3. Transfer funds from old wallet to new wallet
4. Store the new mnemonic securely

**Note**: You cannot convert an existing HD wallet to use BIP39 without creating a new wallet.

## Compatibility

This implementation is compatible with:
- Other BIP39-compliant wallets (Trezor, Ledger, etc.)
- BIP32/BIP44 hierarchical deterministic wallets
- Any wallet supporting 12/15/18/21/24 word mnemonics

## Testing

Unit tests are available in `src/wallet/test/bip39_tests.cpp`:

```bash
# Build and run tests
make check
```

Tests cover:
- Word list validation
- Mnemonic generation
- Mnemonic validation
- Seed derivation
- PBKDF2 implementation
- Passphrase handling

## Known Limitations

1. Currently only supports English word list
2. Wallet must be unlocked to export mnemonic
3. Cannot recover lost mnemonics - backup is essential

## References

- [BIP39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP32 Specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [Trezor BIP39 Implementation](https://github.com/trezor/python-mnemonic)

## Support

For issues or questions regarding BIP39 support in Dogecoin Core:
1. Check the [FAQ](FAQ.md)
2. Visit [Dogecoin GitHub Discussions](https://github.com/dogecoin/dogecoin/discussions)
3. Report bugs via [GitHub Issues](https://github.com/dogecoin/dogecoin/issues)

---

**Warning**: Your mnemonic phrase is the master key to all your funds. Treat it with the same level of security as your private keys. Never share it with anyone, and store it in a secure, offline location.
