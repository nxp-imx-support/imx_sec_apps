// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef _KEY_IMPORT_H_
#define _KEY_IMPORT_H_

#include <stdio.h>
#include <stdint.h>
#include "hsm_key_generate.h"

#define HSM_KEY_TYPE_UNKNOWN        0x00
typedef struct ele_tlv_blob {
    uint8_t *data;      // Pointer to the data
    size_t data_len;    // Length of the data
} ele_tlv_blob_t;

typedef enum {
	IMPORT_AGLO_RFC_3394      = 0x1,
	IMPORT_ALGO_AES_CBC      = 0x2,
	IMPORT_ALGO_NONE         = 0x3,
} ele_importkey_wrap_algo_t;

typedef struct {
    op_generate_key_args_t key_import_args;
    uint8_t *oem_key;
    size_t oem_key_len;
} import_key_prop_t;

#define HSM_ELE_IMPORT_KEY   0xC0020000
#define HSM_ELE_IMPORT_SIGN_ALGO_CMAC 0x1

#define	HSM_ELE_IMPORT_KEY_VOLATILE         (HSM_ELE_IMPORT_KEY | HSM_VOLATILE_STORAGE)
#define	HSM_ELE_IMPORT_KEY_PERSISTENT       (HSM_ELE_IMPORT_KEY | HSM_PERSISTENT_STORAGE)
#define	HSM_ELE_IMPORT_KEY_PERS_PERM        (HSM_ELE_IMPORT_KEY | HSM_PERMANENT_STORAGE)

#define CHECK_CALL(fn, ...) do { \
    int _ret = fn(__VA_ARGS__); \
    if (_ret != 0) { \
        fprintf(stderr, #fn " failed at line %d with code %d\n", __LINE__, _ret); \
        return _ret; \
    } \
} while (0)

int tlv_blob_init(ele_tlv_blob_t *blob);
void tlv_blob_free(ele_tlv_blob_t *blob);
int tlv_blob_append(ele_tlv_blob_t *blob, uint8_t tag, uint32_t length, void *data);
int get_oem_key(const char *oem_key_file_name, import_key_prop_t *import_key_prop);
void print_key_prop(import_key_prop_t *import_key_prop);
int iso7816_4_padding(uint8_t **data, size_t *data_len, size_t block_size);
int aes_cbc_encrypt(const unsigned char *plaintext, int plaintext_len,
                    const unsigned char *key, unsigned char *ciphertext, int * ciphertext_len, uint8_t *iv);
int aes_warp(const unsigned char *key, const unsigned char *plaintext, size_t plaintext_len, unsigned char *ciphertext, int *outlen);
int aes_cmac(const unsigned char *key, const unsigned char *message, size_t message_len, unsigned char *mac, size_t *mac_len);
int assemble_tlv_blob(ele_tlv_blob_t *blob, op_generate_key_args_t *key_import_args, uint8_t *oem_key_warp, size_t oem_key_warp_len, 
                    ele_importkey_wrap_algo_t wrap_algo, uint8_t *iv);

#endif