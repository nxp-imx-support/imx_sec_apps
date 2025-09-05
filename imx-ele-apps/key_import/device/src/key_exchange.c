// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <sys/types.h>
#include "key_exchange.h"
#include "hsm_key_exchange.h"
#include "hsm_key_management.h"
#include "hsm_utils.h"
#include "main.h"
#include "debug.h"
#include "file_op.h"
#include "hsm_api.h"

int get_oem_import_puk(char *filename, uint8_t **puk, size_t *puk_len)
{
    if (!filename || !puk || !puk_len) {
        return -1; // Invalid parameters
    }

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Unable to open PEM file");
        return 1;
    }

    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) {
        fprintf(stderr, "Error reading public key from PEM\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec_key) {
        fprintf(stderr, "Not an EC key\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    const EC_POINT *point = EC_KEY_get0_public_key(ec_key);

    *puk_len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    *puk = malloc(*puk_len);
    if (!*puk) {
        fprintf(stderr, "Memory allocation failed\n");
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        return 1;
    }

    EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, *puk, *puk_len, NULL);

    EC_KEY_free(ec_key);
    EVP_PKEY_free(pkey);
    return 0;
}

hsm_err_t key_exchange(uint8_t *payload, size_t payload_len, uint8_t *oem_puk, size_t puk_len)
{
    if (!payload || payload_len == 0 || !oem_puk || puk_len == 0) {
        return HSM_INVALID_PARAM;
    }

    hsm_err_t hsmret = HSM_GENERAL_ERROR;
    hsm_hdl_t hsm_session_hdl;
    hsm_hdl_t key_store_hdl;
    hsm_hdl_t key_mgmt_hdl;

    open_session_args_t open_session_args = {0};
    open_svc_key_store_args_t open_svc_args = {0};
    open_svc_key_management_args_t open_svc_key_mgmt_args = {0};

    op_key_exchange_args_t key_exchange_args = {0};

    open_session_args.mu_type = HSM1;
    hsmret = hsm_open_session(&open_session_args,
                                &hsm_session_hdl);
    
    if (hsmret != HSM_NO_ERROR) {
            fprintf(stderr,"hsm_open_session failed err:0x%x\n", hsmret);
            goto out;
    } else {
        printf("hsm_open_session success\n");
    }

    open_svc_args.authentication_nonce = 0x534D57;
    open_svc_args.key_store_identifier = 0x454C4500;
    open_svc_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
    hsmret = hsm_open_key_store_service(hsm_session_hdl, &open_svc_args, &key_store_hdl);
    if (hsmret == HSM_KEY_STORE_CONFLICT){
        open_svc_args.flags = HSM_SVC_KEY_STORE_FLAGS_LOAD;
        printf("Key store already created, trying to load it...\n");
        hsmret = hsm_open_key_store_service(hsm_session_hdl, &open_svc_args, &key_store_hdl);
    }

    if(hsmret != HSM_NO_ERROR) {
        fprintf(stderr, "hsm_open_key_store_service failed err:0x%x\n", hsmret);
        goto key_store_fail;
    } else {
        printf("hsm_open_key_store_service success\n");
    }

    hsmret = hsm_open_key_management_service(key_store_hdl, &open_svc_key_mgmt_args, &key_mgmt_hdl);
    if (hsmret != HSM_NO_ERROR) {
        fprintf(stderr, "hsm_open_key_management_service failed err:0x%x\n", hsmret);
        goto key_mgmt_fail;
    } else {
        printf("hsm_open_key_management_service success\n");
    }

    key_exchange_args.in_content = payload;
    key_exchange_args.in_content_sz = payload_len;
    key_exchange_args.in_pub_buffer = oem_puk;
    key_exchange_args.in_pub_buffer_sz = puk_len;
    key_exchange_args.user_fixed_info = NULL;
    key_exchange_args.user_fixed_info_sz = 0;
    key_exchange_args.flags = HSM_OP_KEY_EXCHANGE_FLAGS_STRICT_OPERATION;

    hsmret = hsm_key_exchange(key_mgmt_hdl, &key_exchange_args);
    if(hsmret == HSM_ID_CONFLICT){
        printf("Key already derived\n");
        hsmret = HSM_NO_ERROR;
    }else if (hsmret == HSM_NO_ERROR) {
        printf("hsm_key_exchange success\n");
    } else {
        fprintf(stderr, "hsm_key_exchange failed err:0x%x\n", hsmret);
    }

    hsm_close_key_management_service(key_mgmt_hdl);
key_mgmt_fail:
    hsm_close_key_store_service(key_store_hdl);
key_store_fail:
    hsm_close_session(hsm_session_hdl);
out:
    return hsmret;
}

int do_key_exchange(int argc, char* argv[])
{
    if (argc != 3) {
        printUsage();
        return HSM_INVALID_PARAM;
    }

    char *signed_msg_file = argv[1];
    uint8_t *signed_payload = NULL;
    size_t signed_payload_len = 0;

    char *oem_public_key_pem = argv[2];
    uint8_t *puk = NULL;
    size_t puk_len = 0;

    int ret = 0;

    // get the signed payload from the signed file
    ret = read_from_file(signed_msg_file, &signed_payload, &signed_payload_len);
    if (ret != 0) {
        fprintf(stderr, "Failed to read signed message from file %s: %d\n", signed_msg_file, ret);
        goto out;
    }
    hex_dump("Signed Message", signed_payload, signed_payload_len);

    // get the raw public key from the PEM file, with 0x04 prefix
    ret = get_oem_import_puk(oem_public_key_pem, &puk, &puk_len);
    if (ret != 0) {
        fprintf(stderr, "Failed to get OEM import PUK from file %s: %d\n", oem_public_key_pem, ret);
        goto out;
    }
    hex_dump("OEM Import PUK", puk, puk_len);

    // do key exchange with signed payload and oem raw public key without 0x04 prefix
    ret = key_exchange(signed_payload, signed_payload_len, &puk[1], puk_len-1);
    if(ret == HSM_NO_ERROR) {
        printf("Key exchange successful\n");
    }else{
        fprintf(stderr, "Key exchange failed: %d\n", ret);
        goto out;
    }

out:
    my_free(signed_payload);
    my_free(puk);
    return ret;
}