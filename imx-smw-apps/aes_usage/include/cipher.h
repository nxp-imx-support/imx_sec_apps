// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */
#ifndef __CIPHER_H__
#define __CIPHER_H__

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <psa/crypto_types.h>
#include <smw/names.h>

smw_cipher_mode_t get_algo(const char * mode);
int pkcs7_padding(uint8_t **input, size_t *input_len, size_t block_size);
enum smw_status_code encrypt_with_smw_cipher(bool encrypt, smw_cipher_mode_t algo,
                            uint8_t * input, size_t input_len, 
                            uint8_t * output, size_t output_len,
                            psa_key_id_t key_id);

#endif