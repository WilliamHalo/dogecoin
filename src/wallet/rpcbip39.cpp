// Copyright (c) 2024 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "chain.h"
#include "init.h"
#include "validation.h"
#include "wallet/bip39.h"
#include "wallet/wallet.h"
#include "rpc/server.h"
#include "utilstrencodings.h"

#include <univalue.h>

extern CWallet* pwalletMain;
extern void EnsureWalletIsUnlocked();
extern bool EnsureWalletIsAvailable(bool avoidException);
extern uint32_t getHeightParamFromRequest(const JSONRPCRequest& request, size_t pos);
extern void attemptRescanFromHeight(uint32_t nHeight);

UniValue createmnemonic(const JSONRPCRequest& request)
{
    if (!EnsureWalletIsAvailable(request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() > 2)
        throw std::runtime_error(
            "createmnemonic ( \"passphrase\" words )\n"
            "\nGenerate a new BIP39 mnemonic seed and import it into the wallet.\n"
            "This will create a new HD wallet from the mnemonic.\n"
            "\nArguments:\n"
            "1. \"passphrase\"    (string, optional) Optional passphrase for the mnemonic (default: \"\")\n"
            "2. words            (numeric, optional) Number of words in mnemonic. One of 12, 15, 18, 21, 24 (default: 12)\n"
            "\nResult:\n"
            "\"mnemonic\"        (string) The generated mnemonic phrase\n"
            "\nExamples:\n"
            + HelpExampleCli("createmnemonic", "")
            + HelpExampleCli("createmnemonic", "\"my secret passphrase\" 24")
            + HelpExampleRpc("createmnemonic", "\"my secret passphrase\", 24")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    int nWords = 12;
    if (request.params.size() > 1) {
        nWords = request.params[1].get_int();
        if (nWords != 12 && nWords != 15 && nWords != 18 && nWords != 21 && nWords != 24) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid number of words. Must be 12, 15, 18, 21, or 24.");
        }
    }

    SecureString strPassphrase;
    if (request.params.size() > 0) {
        strPassphrase = SecureString(request.params[0].get_str().begin(), request.params[0].get_str().end());
    }

    int nEntropyLen = CBIP39Mnemonic::GetEntropyLen(nWords);
    SecureVector vchEntropy;
    if (!CBIP39Mnemonic::GenerateEntropy(nEntropyLen, vchEntropy)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to generate entropy for mnemonic");
    }

    CBIP39Mnemonic mnemonic;
    if (!mnemonic.SetEntropy(vchEntropy)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to create mnemonic from entropy");
    }

    if (!strPassphrase.empty()) {
        SecureVector vchSeed;
        BIP39GenerateSeed(mnemonic.GetEntropy(), strPassphrase, vchSeed);
    }

    std::string strMnemonic = mnemonic.GetMnemonic();

    if (!pwalletMain->ImportMnemonic(strMnemonic, strPassphrase, false)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to import mnemonic into wallet");
    }

    return strMnemonic;
}

UniValue importmnemonic(const JSONRPCRequest& request)
{
    if (!EnsureWalletIsAvailable(request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 3)
        throw std::runtime_error(
            "importmnemonic \"mnemonic\" ( \"passphrase\" rescan )\n"
            "\nImport a BIP39 mnemonic seed into the wallet.\n"
            "This will restore all addresses derived from the mnemonic.\n"
            "\nArguments:\n"
            "1. \"mnemonic\"      (string, required) The mnemonic phrase (words separated by spaces)\n"
            "2. \"passphrase\"    (string, optional) The passphrase used when creating the mnemonic (default: \"\")\n"
            "3. rescan           (boolean, optional, default=true) Rescan the wallet for transactions\n"
            "\nResult:\n"
            "true|false          (boolean) Whether the import was successful\n"
            "\nExamples:\n"
            + HelpExampleCli("importmnemonic", "\"abandon ability able about above absent absorb abstract absurd abuse access accident\"")
            + HelpExampleCli("importmnemonic", "\"abandon ability able\" \"my passphrase\" false")
            + HelpExampleRpc("importmnemonic", "\"abandon ability able\", \"my passphrase\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    std::string strMnemonic = request.params[0].get_str();
    
    SecureString strPassphrase;
    if (request.params.size() > 1) {
        strPassphrase = SecureString(request.params[1].get_str().begin(), request.params[1].get_str().end());
    }

    bool fRescan = true;
    if (request.params.size() > 2) {
        fRescan = request.params[2].get_bool();
    }

    if (fRescan && fPruneMode) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Rescan is disabled in pruned mode");
    }

    if (!pwalletMain->ImportMnemonic(strMnemonic, strPassphrase, fRescan)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to import mnemonic");
    }

    return NullUniValue;
}

UniValue exportmnemonic(const JSONRPCRequest& request)
{
    if (!EnsureWalletIsAvailable(request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "exportmnemonic\n"
            "\nExport the BIP39 mnemonic seed from the wallet.\n"
            "The wallet must be unlocked if encrypted.\n"
            "\nResult:\n"
            "\"mnemonic\"        (string) The mnemonic phrase\n"
            "\nExamples:\n"
            + HelpExampleCli("exportmnemonic", "")
            + HelpExampleRpc("exportmnemonic", "")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    if (!pwalletMain->HasMnemonicSeed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not have a mnemonic seed");
    }

    std::string strMnemonic = pwalletMain->ExportMnemonic();
    if (strMnemonic.empty()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to export mnemonic. Wallet may need to be unlocked.");
    }

    return strMnemonic;
}


