// Copyright (c) 2023 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_PBKDF2_H
#define BITCOIN_CRYPTO_PBKDF2_H

#include <cstdint>
#include <cstddef>

void PKCS5_PBKDF2_HMAC_SHA512(
    const uint8_t* passwd,
    size_t passwdlen,
    const uint8_t* salt,
    size_t saltlen,
    uint32_t iterations,
    size_t dkLen,
    uint8_t* dkOut);

#endif // BITCOIN_CRYPTO_PBKDF2_H