// Copyright (c) 2024 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_BIP39_H
#define BITCOIN_WALLET_BIP39_H

#include <string>
#include <vector>
#include <stdint.h>

/**
 * BIP39 Mnemonic Code for generating deterministic keys
 * Implements BIP39 specification for mnemonic phrases
 */

class BIP39 {
public:
    /**
     * Generate a new mnemonic phrase
     * @param entropy_bytes Number of entropy bytes (16, 20, 24, 28, 32)
     * @return Mnemonic phrase as space-separated words
     */
    static std::string GenerateMnemonic(int entropy_bytes = 32);
    
    /**
     * Validate a mnemonic phrase
     * @param mnemonic The mnemonic phrase to validate
     * @return true if valid, false otherwise
     */
    static bool ValidateMnemonic(const std::string& mnemonic);
    
    /**
     * Convert mnemonic phrase to seed
     * @param mnemonic The mnemonic phrase
     * @param passphrase Optional passphrase (default: empty)
     * @return 64-byte seed
     */
    static std::vector<unsigned char> MnemonicToSeed(const std::string& mnemonic, 
                                                      const std::string& passphrase = "");
    
    /**
     * Get word list
     * @return Array of 2048 BIP39 words
     */
    static const char** GetWordList();
    
    /**
     * Get number of words in the list
     * @return 2048
     */
    static int GetWordCount();
    
private:
    /**
     * Convert bytes to mnemonic
     * @param data Byte array
     * @param len Length of data
     * @return Mnemonic phrase
     */
    static std::string BytesToMnemonic(const uint8_t* data, int len);
    
    /**
     * Get word index from word
     * @param word The word to look up
     * @return Index (0-2047) or -1 if not found
     */
    static int GetWordIndex(const char* word);
};

#endif // BITCOIN_WALLET_BIP39_H
