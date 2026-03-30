// Copyright (c) 2023 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/bip39.h"
#include "wallet/bip39_english.h"
#include "crypto/hmac_sha512.h"
#include "crypto/sha256.h"
#include "random.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cstring>
#include <sstream>
#include <stdexcept>

namespace BIP39 {

// BIP39 word separator (space for English, ideographic space for Japanese)
static const std::string WORD_SEPARATOR = " ";

Language GetLanguageFromCode(const std::string& strLanguage)
{
    if (strLanguage == "en" || strLanguage == "english") return ENGLISH;
    if (strLanguage == "zh_CN" || strLanguage == "chinese_simplified") return CHINESE_SIMPLIFIED;
    if (strLanguage == "zh_TW" || strLanguage == "chinese_traditional") return CHINESE_TRADITIONAL;
    if (strLanguage == "ja" || strLanguage == "japanese") return JAPANESE;
    if (strLanguage == "es" || strLanguage == "spanish") return SPANISH;
    if (strLanguage == "fr" || strLanguage == "french") return FRENCH;
    if (strLanguage == "it" || strLanguage == "italian") return ITALIAN;
    if (strLanguage == "ko" || strLanguage == "korean") return KOREAN;
    return ENGLISH; // Default to English
}

std::string GetLanguageCode(Language lang)
{
    switch (lang) {
        case ENGLISH: return "en";
        case CHINESE_SIMPLIFIED: return "zh_CN";
        case CHINESE_TRADITIONAL: return "zh_TW";
        case JAPANESE: return "ja";
        case SPANISH: return "es";
        case FRENCH: return "fr";
        case ITALIAN: return "it";
        case KOREAN: return "ko";
        default: return "en";
    }
}

const char* const* GetWordList(Language lang)
{
    switch (lang) {
        case ENGLISH:
        default:
            return BIP39_WORDLIST_ENGLISH;
    }
}

int GetWordListSize()
{
    return BIP39_WORDLIST_SIZE;
}

// Get index of word in wordlist, returns -1 if not found
static int GetWordIndex(const char* const* wordlist, const std::string& word)
{
    for (int i = 0; i < BIP39_WORDLIST_SIZE; i++) {
        if (word == wordlist[i]) {
            return i;
        }
    }
    return -1;
}

// Convert bytes to binary string
static std::string BytesToBinary(const std::vector<unsigned char>& data)
{
    std::string binary;
    for (size_t i = 0; i < data.size(); i++) {
        for (int j = 7; j >= 0; j--) {
            binary += ((data[i] >> j) & 1) ? '1' : '0';
        }
    }
    return binary;
}

// Split string by delimiter
static std::vector<std::string> SplitWords(const std::string& str, char delimiter)
{
    std::vector<std::string> words;
    std::stringstream ss(str);
    std::string word;
    while (std::getline(ss, word, delimiter)) {
        if (!word.empty()) {
            words.push_back(word);
        }
    }
    return words;
}

// Join words with delimiter
static std::string JoinWords(const std::vector<std::string>& words, const std::string& delimiter)
{
    std::string result;
    for (size_t i = 0; i < words.size(); i++) {
        if (i > 0) result += delimiter;
        result += words[i];
    }
    return result;
}

bool GenerateMnemonic(SecureString& strPhrase, int nBits, Language lang)
{
    // Valid entropy lengths: 128, 160, 192, 224, 256 bits
    if (nBits != 128 && nBits != 160 && nBits != 192 && nBits != 224 && nBits != 256) {
        return false;
    }

    int nEntropyBytes = nBits / 8;
    int nChecksumBits = nBits / 32;
    int nTotalBits = nBits + nChecksumBits;
    int nWordCount = nTotalBits / 11;

    // Generate random entropy
    std::vector<unsigned char> vchEntropy(nEntropyBytes);
    if (RAND_bytes(vchEntropy.data(), nEntropyBytes) != 1) {
        return false;
    }

    // Calculate checksum (first nChecksumBits bits of SHA256 hash)
    std::vector<unsigned char> vchHash(32);
    CSHA256().Write(vchEntropy.data(), vchEntropy.size()).Finalize(vchHash.data());

    // Append checksum bits to entropy
    std::string strBinary = BytesToBinary(vchEntropy);
    for (int i = 0; i < nChecksumBits; i++) {
        strBinary += ((vchHash[0] >> (7 - i)) & 1) ? '1' : '0';
    }

    // Get word list
    const char* const* wordlist = GetWordList(lang);

    // Convert binary to words
    std::vector<std::string> words;
    for (int i = 0; i < nWordCount; i++) {
        std::string strChunk = strBinary.substr(i * 11, 11);
        int nIndex = std::stoi(strChunk, nullptr, 2);
        words.push_back(wordlist[nIndex]);
    }

    // Join words
    std::string strResult = JoinWords(words, WORD_SEPARATOR);
    strPhrase = SecureString(strResult.begin(), strResult.end());

    return true;
}

bool MnemonicToSeed(const SecureString& strPhrase, const SecureString& strPassphrase, std::vector<unsigned char>& vchSeedOut)
{
    // Use PBKDF2-HMAC-SHA512 to derive seed
    std::string strSalt = std::string("mnemonic") + std::string(strPassphrase.begin(), strPassphrase.end());

    vchSeedOut.resize(64); // BIP39 specifies 512-bit (64 bytes) seed

    // PKCS5_PBKDF2_HMAC implementation
    if (!PKCS5_PBKDF2_HMAC(
            strPhrase.c_str(),
            strPhrase.size(),
            reinterpret_cast<const unsigned char*>(strSalt.data()),
            strSalt.size(),
            2048,  // BIP39 specifies 2048 iterations
            EVP_sha512(),
            64,
            vchSeedOut.data())) {
        return false;
    }

    return true;
}

bool MnemonicToSeed(const SecureString& strPhrase, std::vector<unsigned char>& vchSeedOut)
{
    SecureString emptyPassphrase;
    return MnemonicToSeed(strPhrase, emptyPassphrase, vchSeedOut);
}

bool IsValidMnemonic(const SecureString& strPhrase, Language lang)
{
    std::string strPhraseStd(strPhrase.begin(), strPhrase.end());
    std::vector<std::string> words = SplitWords(strPhraseStd, ' ');

    // Valid word counts: 12, 15, 18, 21, 24
    if (words.size() != 12 && words.size() != 15 && words.size() != 18 &&
        words.size() != 21 && words.size() != 24) {
        return false;
    }

    const char* const* wordlist = GetWordList(lang);

    // Build binary string from word indices
    std::string strBinary;
    for (const std::string& word : words) {
        int nIndex = GetWordIndex(wordlist, word);
        if (nIndex < 0) {
            return false; // Invalid word
        }
        // Convert index to 11-bit binary
        for (int i = 10; i >= 0; i--) {
            strBinary += ((nIndex >> i) & 1) ? '1' : '0';
        }
    }

    // Split into entropy and checksum
    int nChecksumBits = words.size() / 3;
    int nEntropyBits = strBinary.size() - nChecksumBits;
    std::string strEntropyBits = strBinary.substr(0, nEntropyBits);
    std::string strChecksumBits = strBinary.substr(nEntropyBits);

    // Convert entropy bits back to bytes
    int nEntropyBytes = nEntropyBits / 8;
    std::vector<unsigned char> vchEntropy(nEntropyBytes);
    for (int i = 0; i < nEntropyBytes; i++) {
        std::string byteStr = strEntropyBits.substr(i * 8, 8);
        vchEntropy[i] = static_cast<unsigned char>(std::stoi(byteStr, nullptr, 2));
    }

    // Calculate checksum
    std::vector<unsigned char> vchHash(32);
    CSHA256().Write(vchEntropy.data(), vchEntropy.size()).Finalize(vchHash.data());

    // Verify checksum
    std::string strExpectedChecksum;
    for (int i = 0; i < nChecksumBits; i++) {
        strExpectedChecksum += ((vchHash[0] >> (7 - i)) & 1) ? '1' : '0';
    }

    return strChecksumBits == strExpectedChecksum;
}

} // namespace BIP39
