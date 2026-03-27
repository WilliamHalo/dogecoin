// Copyright (c) 2023 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/pbkdf2.h"
#include "crypto/hmac_sha512.h"

#include <string.h>

static void FillBuffer(uint8_t* buffer, size_t size, uint8_t value)
{
    for (size_t i = 0; i < size; i++)
        buffer[i] = value;
}

static void IntToBigEndian(uint32_t val, uint8_t* out)
{
    out[0] = (uint8_t)((val >> 24) & 0xFF);
    out[1] = (uint8_t)((val >> 16) & 0xFF);
    out[2] = (uint8_t)((val >> 8) & 0xFF);
    out[3] = (uint8_t)(val & 0xFF);
}

void PKCS5_PBKDF2_HMAC_SHA512(
    const uint8_t* passwd,
    size_t passwdlen,
    const uint8_t* salt,
    size_t saltlen,
    uint32_t iterations,
    size_t dkLen,
    uint8_t* dkOut)
{
    size_t hLen = 64;
    size_t l, r, T_size;
    uint32_t i;
    uint8_t* T;
    uint8_t* salt_and_iter;
    uint8_t U[hLen];
    uint8_t work[hLen];
    
    if (passwd == NULL || dkOut == NULL || dkLen == 0 || iterations == 0)
        return;

    l = 1 + ((dkLen - 1) / hLen);
    r = dkLen - ((l - 1) * hLen);

    if ((l - 1) * hLen + r != dkLen)
        return;

    T = (uint8_t*)malloc(l * hLen);
    if (!T)
        return;

    FillBuffer(T, l * hLen, 0);

    salt_and_iter = (uint8_t*)malloc(saltlen + 4);
    if (!salt_and_iter) {
        free(T);
        return;
    }

    for (i = 1; i <= l; i++) {
        memcpy(salt_and_iter, salt, saltlen);
        IntToBigEndian(i, salt_and_iter + saltlen);

        CHMAC_SHA512(passwd, passwdlen).Write(salt_and_iter, saltlen + 4).Finalize(U);

        memcpy(work, U, hLen);

        for (uint32_t j = 1; j < iterations; j++) {
            CHMAC_SHA512(passwd, passwdlen).Write(U, hLen).Finalize(U);
            for (size_t k = 0; k < hLen; k++)
                work[k] ^= U[k];
        }

        T_size = (i == l) ? r : hLen;
        memcpy(T + ((i - 1) * hLen), work, T_size);
    }

    memcpy(dkOut, T, dkLen);

    memset(work, 0, hLen);
    memset(U, 0, hLen);
    free(salt_and_iter);
    free(T);
}