// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "nxp_prod_ka_pub.h"
#include "ecdh.h"

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

int ecdh(char *oem_private_key_pem, uint8_t *nxp_prod_ka_pub, size_t nxp_prod_ka_pub_len, uint8_t **shared_secret, size_t *shared_secret_len) {
    if(!oem_private_key_pem || !nxp_prod_ka_pub || !shared_secret || !shared_secret_len || nxp_prod_ka_pub_len != PROD_KA_PUB_LEN+1) {
        fprintf(stderr, "Invalid input parameters.\n");
        return EXIT_FAILURE;
    }

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // get the oem private key from PEM file
    FILE *fp = fopen(oem_private_key_pem, "r");
    if (!fp) {
        fprintf(stderr, "failed to open PEM file: %s\n", oem_private_key_pem);
        return EXIT_FAILURE;
    }

    EVP_PKEY *p_oem_private_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!p_oem_private_key) handle_openssl_error();

    EVP_PKEY *p_nxp_prod_ka_pub = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!ctx) handle_openssl_error();

    if (EVP_PKEY_fromdata_init(ctx) <= 0) handle_openssl_error();

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("group", "prime256v1", 0),
        OSSL_PARAM_octet_string("pub", nxp_prod_ka_pub, nxp_prod_ka_pub_len),
        OSSL_PARAM_END
    };

    if (EVP_PKEY_fromdata(ctx, &p_nxp_prod_ka_pub, EVP_PKEY_PUBLIC_KEY, params) <= 0)
        handle_openssl_error();

    EVP_PKEY_CTX_free(ctx);

    // derive the shared secret
    EVP_PKEY_CTX *derive_ctx = EVP_PKEY_CTX_new(p_oem_private_key, NULL);
    if (!derive_ctx) handle_openssl_error();

    if (EVP_PKEY_derive_init(derive_ctx) <= 0) handle_openssl_error();
    if (EVP_PKEY_derive_set_peer(derive_ctx, p_nxp_prod_ka_pub) <= 0) handle_openssl_error();

    if (EVP_PKEY_derive(derive_ctx, NULL, shared_secret_len) <= 0) handle_openssl_error();

    *shared_secret = malloc(*shared_secret_len);
    if (EVP_PKEY_derive(derive_ctx, *shared_secret, shared_secret_len) <= 0) handle_openssl_error();

    EVP_PKEY_free(p_oem_private_key);
    EVP_PKEY_free(p_nxp_prod_ka_pub);
    EVP_PKEY_CTX_free(derive_ctx);

    EVP_cleanup();
    ERR_free_strings();

    return EXIT_SUCCESS;
}