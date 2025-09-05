// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef _KEY_IMPORT_H_
#define _KEY_IMPORT_H_

#include <stdio.h>
#include <stdint.h>
#include "hsm_utils.h"

typedef struct ele_tlv_blob {
    uint8_t *data;      // Pointer to the data
    size_t data_len;    // Length of the data
} ele_tlv_blob_t;

#define HSM_ELE_IMPORT_KEY   0xC0020000
#define HSM_ELE_IMPORT_SIGN_ALGO_CMAC 0x1

#define	HSM_ELE_IMPORT_KEY_VOLATILE         (HSM_ELE_IMPORT_KEY | HSM_VOLATILE_STORAGE)
#define	HSM_ELE_IMPORT_KEY_PERSISTENT       (HSM_ELE_IMPORT_KEY | HSM_PERSISTENT_STORAGE)
#define	HSM_ELE_IMPORT_KEY_PERS_PERM        (HSM_ELE_IMPORT_KEY | HSM_PERMANENT_STORAGE)

hsm_err_t import_key(ele_tlv_blob_t *blob, uint32_t *import_key_id);
int do_import_key(int argc, char* argv[]);

#endif