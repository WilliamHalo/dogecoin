// Copyright (c) 2023 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_BIP39_H
#define BITCOIN_WALLET_BIP39_H

#include "serialize.h"
#include "support/allocators/secure.h"
#include "support/cleanse.h"
#include "uint256.h"

#include <string>
#include <vector>

/**
 * BIP39 Mnemonic Implementation
 *
 * BIP39 defines a standard for creating mnemonic phrases from entropy,
 * and converting those phrases into a binary seed for BIP32 wallet generation.
 */

/** Secure vector for storing sensitive mnemonic data */
typedef std::vector<unsigned char, secure_allocator<unsigned char>> SecureVector;

/**
 * Mnemonic word list languages
 */
enum class Language : uint8_t {
    ENGLISH = 0,
    // Additional languages can be added here
    COUNT
};

/**
 * BIP39 helper class for mnemonic operations
 */
class BIP39
{
public:
    /** Get the English word list */
    static const char* const* GetWordList(Language language = Language::ENGLISH);

    /** Get the word list size (should be 2048 for BIP39) */
    static size_t GetWordListSize(Language language = Language::ENGLISH);

    /**
     * Generate entropy bytes of the specified size
     * Sizes valid for BIP39: 16, 20, 24, 28, 32 bytes
     * Corresponding to: 128, 160, 192, 224, 256 bits
     */
    static SecureVector GenerateEntropy(size_t size = 32);

    /**
     * Convert entropy to a mnemonic phrase
     * @param entropy The entropy bytes
     * @param language The language to use for the word list
     * @return The mnemonic phrase (space-separated words)
     */
    static std::string EntropyToMnemonic(const SecureVector& entropy, Language language = Language::ENGLISH);

    /**
     * Convert a mnemonic phrase back to entropy
     * @param mnemonic The mnemonic phrase (space-separated words)
     * @param language The language to use for the word list
     * @return The original entropy bytes, or empty vector if invalid
     */
    static SecureVector MnemonicToEntropy(const std::string& mnemonic, Language language = Language::ENGLISH);

    /**
     * Check if a mnemonic phrase is valid
     * @param mnemonic The mnemonic phrase to check
     * @param language The language to use for the word list (or nullptr to check all)
     * @return true if valid, false otherwise
     */
    static bool CheckMnemonic(const std::string& mnemonic, Language* language = nullptr);

    /**
     * Convert mnemonic phrase to seed using PBKDF2-HMAC-SHA512
     * @param mnemonic The mnemonic phrase
     * @param passphrase Optional passphrase (default: empty string)
     * @return The 64-byte seed
     */
    static SecureVector MnemonicToSeed(const std::string& mnemonic, const std::string& passphrase = "");

    /**
     * Generate a new mnemonic phrase
     * @param strength The entropy strength in bits (128, 160, 192, 224, or 256)
     * @param language The language to use
     * @return A new mnemonic phrase
     */
    static std::string GenerateMnemonic(size_t strength = 256, Language language = Language::ENGLISH);

private:
    /**
     * Compute checksum for entropy
     * @param entropy The entropy bytes
     * @return The checksum bits (first N bits of SHA256 hash)
     */
    static uint8_t ComputeChecksum(const SecureVector& entropy);

    /**
     * Get the number of checksum bits for given entropy length
     */
    static size_t GetChecksumBits(size_t entropyLen);

    BIP39(); // Disallow instantiation
};

/**
 * BIP39 seed with secure storage
 * This class holds the BIP39 mnemonic and derived seed
 */
class CMnemonicSeed
{
public:
    std::string strMnemonic;           //!< The mnemonic phrase
    SecureVector vchSeed;              //!< The 64-byte seed derived from mnemonic
    std::string strPassphrase;         //!< Optional passphrase (empty if none)
    Language language;                 //!< Language of the mnemonic

    CMnemonicSeed() : language(Language::ENGLISH) {}

    /**
     * Initialize from a mnemonic phrase and optional passphrase
     * @param mnemonic The mnemonic phrase
     * @param passphrase Optional passphrase
     * @param lang The language of the mnemonic
     * @return true if successful
     */
    bool Init(const std::string& mnemonic, const std::string& passphrase = "", Language lang = Language::ENGLISH);

    /**
     * Initialize from entropy (generates new mnemonic)
     * @param entropy The entropy bytes
     * @param passphrase Optional passphrase
     * @param lang The language to use
     * @return true if successful
     */
    bool InitFromEntropy(const SecureVector& entropy, const std::string& passphrase = "", Language lang = Language::ENGLISH);

    /** Check if this seed is valid (has been initialized) */
    bool IsValid() const { return vchSeed.size() == 64; }

    /** Get the seed data for BIP32 derivation */
    const unsigned char* GetSeedData() const { return vchSeed.data(); }
    size_t GetSeedSize() const { return vchSeed.size(); }

    /** Clear all sensitive data */
    void Clear();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        // Note: Mnemonic is serialized for backup/export purposes only
        // In encrypted wallets, vchSeed should be encrypted, and strMnemonic empty
        READWRITE(strMnemonic);
        READWRITE(strPassphrase);
        READWRITE(*(unsigned char*)&language);

        // vchSeed is handled separately for encryption
        if (ser_action.ForRead()) {
            // Try to read the seed
            std::vector<unsigned char> vchSeedIn;
            READWRITE(vchSeedIn);
            vchSeed.assign(vchSeedIn.begin(), vchSeedIn.end());
            memory_cleanse(vchSeedIn.data(), vchSeedIn.size());
        } else {
            std::vector<unsigned char> vchSeedOut(vchSeed.begin(), vchSeed.end());
            READWRITE(vchSeedOut);
            memory_cleanse(vchSeedOut.data(), vchSeedOut.size());
        }
    }
};

#endif // BITCOIN_WALLET_BIP39_H
