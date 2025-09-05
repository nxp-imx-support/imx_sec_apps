// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */
#ifndef __CIPHER_H__
#define __CIPHER_H__

#include <stdint.h>
#include "hsm_utils.h"
#include <stdio.h>
#include <sys/types.h>
#include "hsm_common_def.h"

#define ALGO_INVALID 0xFFFFFFFF

hsm_cipher_algo_t get_algo(const char * mode);

int pkcs7_padding(uint8_t **input, size_t *input_len, size_t block_size);

hsm_err_t cipher_with_ele_cipher(bool encrypt, hsm_cipher_algo_t algo,
                                uint8_t * input, size_t input_len, 
                                uint8_t * output, size_t output_len,
                                uint32_t key_id);

#endif