// Copyright (c) 2023 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bip39.h"

#include "crypto/hmac_sha512.h"
#include "crypto/pbkdf2.h"
#include "hash.h"
#include "uint256.h"
#include "utilstrencodings.h"

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <fstream>
#include <sstream>

static std::vector<std::string> wordlist;

static void LoadWordList()
{
    if (!wordlist.empty())
        return;

    std::string lang = BIP39GetWordListLanguage();
    boost::filesystem::path path = boost::filesystem::path("share/bip39") / (lang + ".txt");
    
    std::ifstream file(path.string());
    if (!file.is_open()) {
        path = boost::filesystem::path("bip39") / (lang + ".txt");
        file.open(path.string());
    }
    
    if (!file.is_open()) {
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        boost::algorithm::trim(line);
        if (!line.empty() && line[0] != '#') {
            wordlist.push_back(line);
        }
    }
    file.close();
}

std::string BIP39GetWordListLanguage()
{
    return "english";
}

std::vector<std::string> CBIP39::GetWordList()
{
    LoadWordList();
    return wordlist;
}

bool BIP39IsValidWord(const std::string& word)
{
    LoadWordList();
    for (const auto& w : wordlist) {
        if (w == word)
            return true;
    }
    return false;
}

bool CBIP39::IsValidMnemonic(const std::vector<std::string>& words)
{
    if (words.size() != BIP39_WORDLIST_WORD_COUNT)
        return false;

    LoadWordList();
    
    std::vector<int> indices;
    for (size_t i = 0; i < words.size(); i++) {
        bool found = false;
        for (int j = 0; j < (int)wordlist.size(); j++) {
            if (words[i] == wordlist[j]) {
                indices.push_back(j);
                found = true;
                break;
            }
        }
        if (!found)
            return false;
    }

    std::vector<unsigned char> entropy(BIP39_WORDLIST_ENTROPY_BITS / 8);
    for (int i = 0; i < BIP39_WORDLIST_ENTROPY_BITS / 8; i++) {
        int wordIndex = indices[i * 11 / 8];
        int bitPosition = (i * 11) % 8;
        unsigned char byte = 0;
        
        if (bitPosition <= 4) {
            byte = (wordIndex >> (11 - 8 - bitPosition)) & 0xFF;
        } else {
            byte = ((wordIndex << (bitPosition - 4)) & 0xFF) | ((indices[(i * 11 / 8) + 1] >> (19 - bitPosition)) & 0xFF);
        }
        entropy[i] = byte;
    }

    CHashWriter hasher(SER_GETHASH, 0);
    hasher << entropy;
    uint256 hash = hasher.GetHash();
    
    int checkSumBits = BIP39_WORDLIST_CHECKSUM_BITS;
    int checkSum = 0;
    for (int i = 0; i < checkSumBits; i++) {
        int wordIndex = indices[BIP39_WORDLIST_ENTROPY_BITS / 8 + (i / 8)];
        int bitPos = 7 - (i % 8);
        if (wordIndex & (1 << bitPos))
            checkSum |= (1 << i);
    }
    
    int expectedCheckSum = (hash.begin()[0] >> 4) & 0xF;
    
    return checkSum == expectedCheckSum;
}

bool CBIP39::IsValidMnemonic(const std::string& mnemonic)
{
    std::vector<std::string> words;
    boost::algorithm::split(words, mnemonic, boost::algorithm::is_any_of(" \t\n"), boost::algorithm::token_compress_on);
    return IsValidMnemonic(words);
}

bool CBIP39::MnemonicToSeed(const std::vector<std::string>& words, const std::string& passphrase, std::vector<unsigned char>& seed)
{
    if (!IsValidMnemonic(words))
        return false;

    std::string mnemonic;
    for (size_t i = 0; i < words.size(); i++) {
        if (i > 0) mnemonic += " ";
        mnemonic += words[i];
    }

    std::string salt = std::string("mnemonic") + passphrase;
    std::vector<unsigned char> saltVec(salt.begin(), salt.end());

    seed.resize(BIP39_SEED_SIZE);
    PKCS5_PBKDF2_HMAC_SHA512(
        (const unsigned char*)mnemonic.c_str(),
        mnemonic.size(),
        saltVec.data(),
        saltVec.size(),
        2048,
        BIP39_SEED_SIZE,
        seed.data()
    );

    return true;
}

bool CBIP39::MnemonicToSeed(const std::string& mnemonic, const std::string& passphrase, std::vector<unsigned char>& seed)
{
    std::vector<std::string> words;
    boost::algorithm::split(words, mnemonic, boost::algorithm::is_any_of(" \t\n"), boost::algorithm::token_compress_on);
    return MnemonicToSeed(words, passphrase, seed);
}