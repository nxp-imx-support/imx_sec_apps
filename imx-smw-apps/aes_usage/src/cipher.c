// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */
#include "cipher.h"
#include <smw_keymgr.h>
#include <smw_status.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "smw/names.h"
#include "smw_crypto.h"

smw_cipher_mode_t get_algo(const char * mode)
{
    if (strcmp(mode, "ECB") == 0) {
        return SMW_CIPHER_MODE_NAME_ECB;
    } else if (strcmp(mode, "CBC") == 0) {
        return SMW_CIPHER_MODE_NAME_CBC;
    } else if (strcmp(mode, "CTR") == 0) {
        return SMW_CIPHER_MODE_NAME_CTR;
    } else if (strcmp(mode, "CFB") == 0) {
        return SMW_CIPHER_MODE_NAME_CFB;
    } else {
        printf("Unsupported mode: %s\n", mode);
    }
    return SMW_CIPHER_MODE_NAME_NONE; // Invalid value to indicate error
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

enum smw_status_code encrypt_with_smw_cipher(bool encrypt, smw_cipher_mode_t algo,
                            uint8_t * input, size_t input_len, 
                            uint8_t * output, size_t output_len,
                            psa_key_id_t key_id) {
	uint8_t iv_data[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	struct smw_key_descriptor key_descriptor = {
		.type_name = SMW_KEY_TYPE_NAME_AES,
		.id = key_id,
		.security_size = 256,
		.buffer = NULL
	};
	struct smw_key_descriptor *key_descriptor_ptr = &key_descriptor;
	struct smw_cipher_init_args smw_init_args = {
		.version = 0,
		.subsystem_name = SMW_SUBSYSTEM_NAME_ELE,
		.keys_desc = &key_descriptor_ptr,
		.mode_name = algo,
		.iv = iv_data,
		.iv_length = sizeof(iv_data),
		.op_type_name = SMW_CIPHER_OP_TYPE_NAME_NONE,
		.nb_keys = 1
	 };

	struct smw_cipher_data_args smw_data_args = { 
		.version = 0,
		.input = input,
		.input_length = input_len,
		.output = output,
		.output_length = output_len
	 };

     if(encrypt) smw_init_args.op_type_name = SMW_CIPHER_OP_TYPE_NAME_ENCRYPT;
     else smw_init_args.op_type_name = SMW_CIPHER_OP_TYPE_NAME_DECRYPT;

	struct smw_cipher_args smw_args = {
		.init = smw_init_args,
		.data = smw_data_args
	};


	return smw_cipher(&smw_args);
}