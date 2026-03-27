// Copyright (c) 2023 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BIP39_H
#define BITCOIN_BIP39_H

#include <string>
#include <vector>
#include <utility>

class uint256;

static const int BIP39_WORDLIST_ENTROPY_BITS = 128;
static const int BIP39_WORDLIST_CHECKSUM_BITS = 4;
static const int BIP39_WORDLIST_TOTAL_BITS = BIP39_WORDLIST_ENTROPY_BITS + BIP39_WORDLIST_CHECKSUM_BITS;
static const int BIP39_WORDLIST_WORD_COUNT = BIP39_WORDLIST_TOTAL_BITS / 11;
static const int BIP39_SEED_SIZE = 64;

class CBIP39
{
public:
    static bool IsValidMnemonic(const std::vector<std::string>& words);
    static bool IsValidMnemonic(const std::string& mnemonic);
    static bool MnemonicToSeed(const std::vector<std::string>& words, const std::string& passphrase, std::vector<unsigned char>& seed);
    static bool MnemonicToSeed(const std::string& mnemonic, const std::string& passphrase, std::vector<unsigned char>& seed);
    static std::vector<std::string> GetWordList();
};

bool BIP39IsValidWord(const std::string& word);
std::string BIP39GetWordListLanguage();

#endif // BITCOIN_BIP39_H