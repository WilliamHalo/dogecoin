// Copyright (c) 2014-2016 The Bitcoin Core developers
// Copyright (c) 2024 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_BIP39_H
#define BITCOIN_WALLET_BIP39_H

#include "support/allocators/secure.h"
#include <string>
#include <vector>

static const int BIP39_ENTROPY_LEN_128 = 16;
static const int BIP39_ENTROPY_LEN_160 = 20;
static const int BIP39_ENTROPY_LEN_192 = 24;
static const int BIP39_ENTROPY_LEN_224 = 28;
static const int BIP39_ENTROPY_LEN_256 = 32;

static const int BIP39_PASSPHRASE_MAX_WORDS = 24;

typedef std::vector<unsigned char, secure_allocator<unsigned char> > SecureVector;

class CBIP39Mnemonic
{
private:
    SecureVector vchEntropy;
    SecureVector vchSeed;
    std::vector<std::string> vMnemonicWords;
    SecureString strPassphrase;

    bool fValid;

public:
    CBIP39Mnemonic() : fValid(false) {}

    bool IsValid() const { return fValid; }

    const SecureVector& GetEntropy() const { return vchEntropy; }
    const SecureVector& GetSeed() const { return vchSeed; }
    const std::vector<std::string>& GetWords() const { return vMnemonicWords; }

    std::string GetMnemonic() const;

    bool SetEntropy(const SecureVector& entropy);
    bool SetMnemonic(const std::string& mnemonic, const SecureString& passphrase = SecureString(""));
    bool SetMnemonic(const std::vector<std::string>& words, const SecureString& passphrase = SecureString(""));

    static bool GenerateEntropy(int nEntropyLen, SecureVector& entropy);
    static int GetEntropyLen(int nWords);
    static bool IsValidWord(const std::string& word);
    static int GetWordIndex(const std::string& word);
    static std::string GetWord(int nIndex);
};

void BIP39GenerateSeed(const std::string& strMnemonic, const SecureString& strPassphrase, SecureVector& vchSeed);

#endif // BITCOIN_WALLET_BIP39_H
