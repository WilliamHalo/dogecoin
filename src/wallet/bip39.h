// Copyright (c) 2023 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_BIP39_H
#define BITCOIN_WALLET_BIP39_H

#include <string>
#include <vector>
#include "support/allocators/secure.h"

/**
 * BIP39 Mnemonic code for generating deterministic keys.
 * Reference: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 */

namespace BIP39 {

// Supported languages for mnemonic phrase
enum Language {
    ENGLISH = 0,
    CHINESE_SIMPLIFIED,
    CHINESE_TRADITIONAL,
    JAPANESE,
    SPANISH,
    FRENCH,
    ITALIAN,
    KOREAN
};

/**
 * Convert language string to enum
 * @param strLanguage Language code (e.g., "en", "zh_CN")
 * @return Language enum value
 */
Language GetLanguageFromCode(const std::string& strLanguage);

/**
 * Get language code string from enum
 * @param lang Language enum
 * @return Language code string
 */
std::string GetLanguageCode(Language lang);

/**
 * Generate a random mnemonic phrase
 * @param strPhrase Output mnemonic phrase (words separated by space)
 * @param nBits Number of entropy bits (128, 160, 192, 224, or 256)
 * @param lang Language for word list
 * @return true if successful
 */
bool GenerateMnemonic(SecureString& strPhrase, int nBits = 256, Language lang = ENGLISH);

/**
 * Convert mnemonic phrase to seed using PBKDF2
 * @param strPhrase Mnemonic phrase
 * @param strPassphrase Optional passphrase (default empty)
 * @param vchSeedOut Output seed (64 bytes)
 * @return true if successful
 */
bool MnemonicToSeed(const SecureString& strPhrase, const SecureString& strPassphrase, std::vector<unsigned char>& vchSeedOut);

/**
 * Convert mnemonic phrase to seed (convenience function without passphrase)
 * @param strPhrase Mnemonic phrase
 * @param vchSeedOut Output seed (64 bytes)
 * @return true if successful
 */
bool MnemonicToSeed(const SecureString& strPhrase, std::vector<unsigned char>& vchSeedOut);

/**
 * Validate if a mnemonic phrase is valid
 * @param strPhrase Mnemonic phrase to validate
 * @param lang Optional language hint (if UNKNOWN, try all languages)
 * @return true if valid
 */
bool IsValidMnemonic(const SecureString& strPhrase, Language lang = ENGLISH);

/**
 * Get word list for a specific language
 * @param lang Language enum
 * @return Pointer to word list array (2048 words)
 */
const char* const* GetWordList(Language lang);

/**
 * Get the number of words in the word list
 * @return Always 2048 for BIP39
 */
int GetWordListSize();

} // namespace BIP39

#endif // BITCOIN_WALLET_BIP39_H
