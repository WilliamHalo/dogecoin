// Copyright (c) 2014-2016 The Bitcoin Core developers
// Copyright (c) 2024 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bip39.h"
#include "bip39_words.h"
#include "crypto/hmac_sha512.h"
#include "crypto/sha256.h"
#include "random.h"
#include "utilstrencodings.h"

#include <boost/algorithm/string.hpp>

static const char* BIP39_SEED_KEY = "mnemonic";

std::string CBIP39Mnemonic::GetMnemonic() const
{
    std::string strMnemonic;
    for (size_t i = 0; i < vMnemonicWords.size(); i++) {
        if (i > 0) strMnemonic += " ";
        strMnemonic += vMnemonicWords[i];
    }
    return strMnemonic;
}

bool CBIP39Mnemonic::SetEntropy(const SecureVector& entropy)
{
    if (entropy.size() != BIP39_ENTROPY_LEN_128 &&
        entropy.size() != BIP39_ENTROPY_LEN_160 &&
        entropy.size() != BIP39_ENTROPY_LEN_192 &&
        entropy.size() != BIP39_ENTROPY_LEN_224 &&
        entropy.size() != BIP39_ENTROPY_LEN_256) {
        return false;
    }

    vchEntropy = entropy;

    CSHA256 hasher;
    unsigned char hash[32];
    hasher.Write(entropy.data(), entropy.size()).Finalize(hash);

    int nChecksumBits = entropy.size() * 8 / 32;
    int nWords = (entropy.size() * 8 + nChecksumBits) / 11;

    vMnemonicWords.clear();
    int nBit = 0;
    for (int i = 0; i < nWords; i++) {
        int nIndex = 0;
        for (int j = 0; j < 11; j++) {
            int nBytePos = nBit / 8;
            int nBitPos = 7 - (nBit % 8);
            unsigned char bit;
            if (nBytePos < (int)entropy.size()) {
                bit = (entropy[nBytePos] >> nBitPos) & 1;
            } else {
                int nChecksumBit = nBit - entropy.size() * 8;
                bit = (hash[nChecksumBit / 8] >> (7 - (nChecksumBit % 8))) & 1;
            }
            nIndex = (nIndex << 1) | bit;
            nBit++;
        }
        vMnemonicWords.push_back(GetWord(nIndex));
    }

    vchSeed.clear();
    BIP39GenerateSeed(vchEntropy, strPassphrase, vchSeed);

    fValid = true;
    return true;
}

bool CBIP39Mnemonic::SetMnemonic(const std::string& mnemonic, const SecureString& passphrase)
{
    std::vector<std::string> words;
    boost::split(words, mnemonic, boost::is_any_of(" "), boost::token_compress_on);
    return SetMnemonic(words, passphrase);
}

bool CBIP39Mnemonic::SetMnemonic(const std::vector<std::string>& words, const SecureString& passphrase)
{
    if (words.empty() || words.size() > BIP39_PASSPHRASE_MAX_WORDS) {
        return false;
    }

    int nWords = words.size();
    int nEntropyBits = nWords * 11;
    int nChecksumBits = nEntropyBits / 33;
    int nEntropyLen = (nEntropyBits - nChecksumBits) / 8;

    if (!GetEntropyLen(nWords)) {
        return false;
    }

    for (const auto& word : words) {
        if (!IsValidWord(word)) {
            return false;
        }
    }

    strPassphrase = passphrase;
    vMnemonicWords = words;

    std::vector<unsigned char> entropyBits((nEntropyBits + 7) / 8, 0);
    int nBit = 0;
    for (int i = 0; i < nWords; i++) {
        int nIndex = GetWordIndex(words[i]);
        for (int j = 10; j >= 0; j--) {
            int nBytePos = nBit / 8;
            int nBitPos = 7 - (nBit % 8);
            if ((nIndex >> j) & 1) {
                entropyBits[nBytePos] |= (1 << nBitPos);
            }
            nBit++;
        }
    }

    vchEntropy.assign(entropyBits.begin(), entropyBits.begin() + nEntropyLen);

    CSHA256 hasher;
    unsigned char hash[32];
    hasher.Write(vchEntropy.data(), vchEntropy.size()).Finalize(hash);

    int nChecksumBitsToVerify = vchEntropy.size() * 8 / 32;
    for (int i = 0; i < nChecksumBitsToVerify; i++) {
        int nBitPos = vchEntropy.size() * 8 + i;
        int nBytePos = nBitPos / 8;
        int nBitInByte = 7 - (nBitPos % 8);
        int nChecksumByte = i / 8;
        int nChecksumBitInByte = 7 - (i % 8);

        bool bitFromMnemonic = (entropyBits[nBytePos] >> nBitInByte) & 1;
        bool bitFromHash = (hash[nChecksumByte] >> nChecksumBitInByte) & 1;

        if (bitFromMnemonic != bitFromHash) {
            fValid = false;
            return false;
        }
    }

    vchSeed.clear();
    BIP39GenerateSeed(vchEntropy, strPassphrase, vchSeed);

    fValid = true;
    return true;
}

bool CBIP39Mnemonic::GenerateEntropy(int nEntropyLen, SecureVector& entropy)
{
    if (nEntropyLen != BIP39_ENTROPY_LEN_128 &&
        nEntropyLen != BIP39_ENTROPY_LEN_160 &&
        nEntropyLen != BIP39_ENTROPY_LEN_192 &&
        nEntropyLen != BIP39_ENTROPY_LEN_224 &&
        nEntropyLen != BIP39_ENTROPY_LEN_256) {
        return false;
    }

    entropy.resize(nEntropyLen);
    GetStrongRandBytes(entropy.data(), nEntropyLen);
    return true;
}

int CBIP39Mnemonic::GetEntropyLen(int nWords)
{
    switch (nWords) {
    case 12: return BIP39_ENTROPY_LEN_128;
    case 15: return BIP39_ENTROPY_LEN_160;
    case 18: return BIP39_ENTROPY_LEN_192;
    case 21: return BIP39_ENTROPY_LEN_224;
    case 24: return BIP39_ENTROPY_LEN_256;
    default: return 0;
    }
}

bool CBIP39Mnemonic::IsValidWord(const std::string& word)
{
    return GetWordIndex(word) >= 0;
}

int CBIP39Mnemonic::GetWordIndex(const std::string& word)
{
    for (int i = 0; i < BIP39_WORD_COUNT; i++) {
        if (word == BIP39_WORDS_EN[i]) {
            return i;
        }
    }
    return -1;
}

std::string CBIP39Mnemonic::GetWord(int nIndex)
{
    if (nIndex < 0 || nIndex >= BIP39_WORD_COUNT) {
        return "";
    }
    return BIP39_WORDS_EN[nIndex];
}

void BIP39GenerateSeed(const SecureVector& vchEntropy, const SecureString& passphrase, SecureVector& vchSeed)
{
    std::vector<unsigned char> vchMnemonic;
    for (const auto& word : vchEntropy) {
        vchMnemonic.push_back(word);
    }

    std::string mnemonicStr(vchMnemonic.begin(), vchMnemonic.end());
    std::string salt = std::string(BIP39_SEED_KEY) + std::string(passphrase.begin(), passphrase.end());

    vchSeed.resize(64);
    CHMAC_SHA512(reinterpret_cast<const unsigned char*>(salt.data()), salt.size())
        .Write(reinterpret_cast<const unsigned char*>(mnemonicStr.data()), mnemonicStr.size())
        .Finalize(vchSeed.data());
}
