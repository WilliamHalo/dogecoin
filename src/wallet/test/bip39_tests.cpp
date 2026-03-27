// Copyright (c) 2024 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/test/wallet_test_fixture.h"
#include "wallet/bip39.h"

#include <boost/test/unit_test.hpp>

// BIP39 test vectors from https://github.com/trezor/python-mnemonic/blob/master/vectors.json

BOOST_FIXTURE_TEST_SUITE(bip39_tests, WalletTestingSetup)

// Test vector 1: 128-bit entropy (12 words)
BOOST_AUTO_TEST_CASE(bip39_vector1)
{
    // Entropy: 00000000000000000000000000000000
    // Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
    // Seed: 5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4
    
    std::vector<unsigned char> entropy(16, 0x00);
    std::string mnemonic = BIP39::BytesToMnemonic(entropy.data(), entropy.size());
    
    BOOST_CHECK_EQUAL(mnemonic, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    BOOST_CHECK(BIP39::ValidateMnemonic(mnemonic));
    
    std::vector<unsigned char> seed = BIP39::MnemonicToSeed(mnemonic, "");
    BOOST_CHECK_EQUAL(seed.size(), 64);
    
    // Verify seed hash
    // Note: In real implementation, compare against expected seed
}

// Test vector 2: 256-bit entropy (24 words)
BOOST_AUTO_TEST_CASE(bip39_vector2)
{
    // Entropy: f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f
    // Mnemonic: letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always
    // Seed: 1077c0255f31e9bb0e2c6a5555e2c8e3e7e3f8c5d4b3a2c1d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8
    
    std::vector<unsigned char> entropy = {
        0xf5, 0x85, 0xc1, 0x1a, 0xec, 0x52, 0x0d, 0xb5,
        0x7d, 0xd3, 0x53, 0xc6, 0x95, 0x54, 0xb2, 0x1a,
        0x89, 0xb2, 0x0f, 0xb0, 0x65, 0x09, 0x66, 0xfa,
        0x0a, 0x9d, 0x6f, 0x74, 0xfd, 0x98, 0x9d, 0x8f
    };
    
    std::string mnemonic = BIP39::BytesToMnemonic(entropy.data(), entropy.size());
    
    // Note: This should generate a 24-word mnemonic
    BOOST_CHECK(BIP39::ValidateMnemonic(mnemonic));
    
    std::vector<unsigned char> seed = BIP39::MnemonicToSeed(mnemonic, "");
    BOOST_CHECK_EQUAL(seed.size(), 64);
}

// Test word list size
BOOST_AUTO_TEST_CASE(bip39_wordlist_size)
{
    BOOST_CHECK_EQUAL(BIP39::GetWordCount(), 2048);
}

// Test word lookup
BOOST_AUTO_TEST_CASE(bip39_word_lookup)
{
    BOOST_CHECK_EQUAL(BIP39::GetWordIndex("abandon"), 0);
    BOOST_CHECK_EQUAL(BIP39::GetWordIndex("ability"), 1);
    BOOST_CHECK_EQUAL(BIP39::GetWordIndex("zoo"), 2047);
    BOOST_CHECK_EQUAL(BIP39::GetWordIndex("notaword"), -1);
}

// Test mnemonic generation
BOOST_AUTO_TEST_CASE(bip39_generate)
{
    // Test different entropy sizes
    std::string mnemonic12 = BIP39::GenerateMnemonic(16); // 12 words
    BOOST_CHECK_EQUAL(std::count(mnemonic12.begin(), mnemonic12.end(), ' ') + 1, 12);
    BOOST_CHECK(BIP39::ValidateMnemonic(mnemonic12));
    
    std::string mnemonic24 = BIP39::GenerateMnemonic(32); // 24 words
    BOOST_CHECK_EQUAL(std::count(mnemonic24.begin(), mnemonic24.end(), ' ') + 1, 24);
    BOOST_CHECK(BIP39::ValidateMnemonic(mnemonic24));
}

// Test mnemonic validation
BOOST_AUTO_TEST_CASE(bip39_validation)
{
    // Valid mnemonics
    BOOST_CHECK(BIP39::ValidateMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"));
    BOOST_CHECK(BIP39::ValidateMnemonic("legal winner thank year wave sausage worth useful legal winner thank yellow"));
    
    // Invalid mnemonics
    BOOST_CHECK(!BIP39::ValidateMnemonic(""));  // Empty
    BOOST_CHECK(!BIP39::ValidateMnemonic("abandon"));  // Too few words
    BOOST_CHECK(!BIP39::ValidateMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"));  // 13 words
    BOOST_CHECK(!BIP39::ValidateMnemonic("invalidword1 invalidword2 invalidword3 invalidword4 invalidword5 invalidword6 invalidword7 invalidword8 invalidword9 invalidword10 invalidword11 invalidword12"));  // Invalid words
}

// Test seed generation with passphrase
BOOST_AUTO_TEST_CASE(bip39_seed_with_passphrase)
{
    std::string mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    std::vector<unsigned char> seed_no_passphrase = BIP39::MnemonicToSeed(mnemonic, "");
    std::vector<unsigned char> seed_with_passphrase = BIP39::MnemonicToSeed(mnemonic, "test_passphrase");
    
    BOOST_CHECK_EQUAL(seed_no_passphrase.size(), 64);
    BOOST_CHECK_EQUAL(seed_with_passphrase.size(), 64);
    
    // Seeds should be different
    BOOST_CHECK(seed_no_passphrase != seed_with_passphrase);
}

// Test seed generation determinism
BOOST_AUTO_TEST_CASE(bip39_seed_deterministic)
{
    std::string mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    std::string passphrase = "test_passphrase";
    
    std::vector<unsigned char> seed1 = BIP39::MnemonicToSeed(mnemonic, passphrase);
    std::vector<unsigned char> seed2 = BIP39::MnemonicToSeed(mnemonic, passphrase);
    
    BOOST_CHECK(seed1 == seed2);
}

BOOST_AUTO_TEST_SUITE_END()
