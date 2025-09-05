// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */
#include "cipher.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "hsm_api.h"

hsm_cipher_algo_t get_algo(const char * mode)
{
    if (strcmp(mode, "ECB") == 0) {
        return ALGO_CIPHER_ECB_NO_PAD;
    } else if (strcmp(mode, "CBC") == 0) {
        return ALGO_CIPHER_CBC_NO_PAD;
    } else if (strcmp(mode, "CTR") == 0) {
        return ALGO_CIPHER_CTR;
    } else if (strcmp(mode, "CFB") == 0) {
        return ALGO_CIPHER_CFB;
    } else if (strcmp(mode, "OFB") == 0) {
        return ALGO_CIPHER_OFB;
    } else {
        printf("Unsupported mode: %s\n", mode);
    }
    return ALGO_INVALID; // Invalid value to indicate error
}

int pkcs7_padding(uint8_t **input, size_t *input_len, size_t block_size)
{
    if (!input || !*input || !input_len || *input_len == 0 || block_size == 0) {
        return -1; // Invalid parameters
    }

    size_t pad_len = block_size - (*input_len % block_size);
    size_t new_len = *input_len + pad_len;

    uint8_t *padded_input = (uint8_t *)realloc(*input, new_len);
    if (!padded_input) {
        return -1; // Memory allocation failed
    }

    // Add padding bytes
    for (size_t i = *input_len; i < new_len; i++) {
        padded_input[i] = (uint8_t)pad_len;
    }

    *input = padded_input;
    *input_len = new_len;
    return 0; // Success
}

// for 6.6.36, only one go cipher is supported
// for 6.12.20, both one go cipher and streaming cipher are supported
#define USE_ONE_GO_CIPHER   1

uint8_t iv_data[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

static hsm_err_t do_hsm_cipher(hsm_hdl_t key_store_hdl, bool encrypt, hsm_cipher_algo_t algo,
                                uint8_t * input, size_t input_len, uint8_t * output, 
                                size_t output_len, uint32_t key_id)
{
    hsm_err_t hsmret = HSM_GENERAL_ERROR;
#if USE_ONE_GO_CIPHER
#else
    hsm_hdl_t cipher_hdl = 0;
#endif

#if USE_ONE_GO_CIPHER
    op_cipher_one_go_args_t cipher_args = {0};
#else
    op_cipher_args_t cipher_args = {0};

    open_svc_cipher_args_t open_cipher_args = {0};
    hsmret = hsm_open_cipher_service(key_store_hdl, &open_cipher_args, &cipher_hdl);
    if (hsmret != HSM_NO_ERROR) {
        fprintf(stderr, "hsm_open_key_management_service failed hsmret:0x%x\n", hsmret);
        return hsmret;
    }
#endif

    memset(&cipher_args, 0, sizeof(cipher_args));
    if(encrypt) cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
    else    cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;

    cipher_args.cipher_algo = algo;
	cipher_args.key_identifier = key_id;
	cipher_args.iv = iv_data;
	cipher_args.iv_size = sizeof(iv_data);
    cipher_args.input = input;
    cipher_args.input_size = input_len;
    cipher_args.output = output;
    cipher_args.output_size = output_len;

#if USE_ONE_GO_CIPHER
    hsmret = hsm_do_cipher(key_store_hdl, &cipher_args);
#else
    hsmret = hsm_cipher(cipher_hdl, &cipher_args);
#endif
    if (hsmret != HSM_NO_ERROR) {
        printf("hsm cipher failed, ret: 0x%x\n", hsmret);
        goto cipher_fail;
    }

cipher_fail:
#if USE_ONE_GO_CIPHER
#else
    hsm_close_cipher_service(cipher_hdl);
#endif
    return hsmret;
}

hsm_err_t cipher_with_ele_cipher(bool encrypt, hsm_cipher_algo_t algo,
                                uint8_t * input, size_t input_len, 
                                uint8_t * output, size_t output_len,
                                uint32_t key_id)
{
	hsm_err_t hsmret = HSM_GENERAL_ERROR;
    hsm_hdl_t hsm_session_hdl;
    hsm_hdl_t key_store_hdl;

	open_session_args_t open_session_args = {0};
    open_svc_key_store_args_t open_svc_args = {0};

    open_session_args.mu_type = HSM1;
    hsmret = hsm_open_session(&open_session_args,
                                &hsm_session_hdl);
    
    if (hsmret != HSM_NO_ERROR) {
            fprintf(stderr,"hsm_open_session failed hsmret:0x%x\n", hsmret);
            goto out;
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
        fprintf(stderr, "hsm_open_key_store_service failed hsmret:0x%x\n", hsmret);
        goto key_store_fail;
    }

    hsmret = do_hsm_cipher(key_store_hdl, encrypt, algo, input, input_len,
                            output, output_len, key_id);

    hsm_close_key_store_service(key_store_hdl);
key_store_fail:
    hsm_close_session(hsm_session_hdl);
out:
	return hsmret;
}