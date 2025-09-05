// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "hkdf.h"

int hkdf(uint8_t *secret, size_t secret_len, uint8_t* info, size_t info_len, uint8_t *out_key, size_t out_key_len)
{
    if (!secret || !out_key || !out_key_len || !secret_len ) {
        fprintf(stderr, "Invalid input parameters for HKDF.\n");
        return EXIT_FAILURE;
    }

    // create KDF context
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) {
        fprintf(stderr, "Failed to fetch HKDF\n");
        return 1;
    }

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) {
        fprintf(stderr, "Failed to create HKDF context\n");
        return 1;
    }

    uint8_t salt[32] = {0,};
    OSSL_PARAM kdf_params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_octet_string("salt", (void *)salt, sizeof(salt)),
        OSSL_PARAM_construct_octet_string("key", (void *)secret, secret_len),
        OSSL_PARAM_construct_octet_string("info", info, info_len),
        OSSL_PARAM_construct_end()
    };

    if (EVP_KDF_derive(kctx, out_key, out_key_len, kdf_params) <= 0) {
        fprintf(stderr, "HKDF derive failed\n");
        EVP_KDF_CTX_free(kctx);
        return EXIT_FAILURE;
    }

    EVP_KDF_CTX_free(kctx);

    return EXIT_SUCCESS;
}

