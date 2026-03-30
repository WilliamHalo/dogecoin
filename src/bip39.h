// Copyright (c) 2024 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BIP39_H
#define BITCOIN_BIP39_H

#include <string>
#include <vector>
#include "support/allocators/secure.h"

/**
 * BIP39 Mnemonic code for generating deterministic keys
 * https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 */

static const int BIP39_SEED_LEN = 64;

/**
 * Convert mnemonic phrase to seed using PBKDF2-HMAC-SHA512
 * @param mnemonic Space-separated list of BIP39 words
 * @param passphrase Optional passphrase (can be empty)
 * @return 64-byte seed vector (using secure_allocator)
 */
std::vector<unsigned char, secure_allocator<unsigned char>> MnemonicToSeed(const std::string& mnemonic, const std::string& passphrase);

/**
 * Validate that the given mnemonic phrase is valid according to BIP39
 * @param mnemonic Space-separated list of words to validate
 * @return true if valid, false otherwise
 */
bool ValidateMnemonic(const std::string& mnemonic);

/**
 * Generate a new mnemonic phrase from entropy
 * @param entropy Byte vector of entropy (16, 20, 24, 28, or 32 bytes)
 * @return Space-separated mnemonic phrase
 */
std::string GenerateMnemonic(const std::vector<unsigned char>& entropy);

/**
 * Generate a new mnemonic phrase with random entropy
 * @param strength Number of bits of entropy (128, 160, 192, 224, or 256)
 * @return Space-separated mnemonic phrase
 */
std::string GenerateNewMnemonic(int strength = 256);

/**
 * Get the word at a specific index from the BIP39 word list (0-2047)
 * @param index Word index
 * @return The English word at that index
 */
const char* GetWord(int index);

/**
 * Find the index of a word in the BIP39 word list
 * @param word The word to find
 * @return Index (0-2047) or -1 if not found
 */
int GetWordIndex(const char* word);

/** Number of words in BIP39 word list */
static const int BIP39_WORD_COUNT = 2048;

#endif // BITCOIN_BIP39_H
