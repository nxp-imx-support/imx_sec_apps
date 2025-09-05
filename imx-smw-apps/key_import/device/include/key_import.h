// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef _KEY_IMPORT_H_
#define _KEY_IMPORT_H_

#include <stdio.h>
#include <stdint.h>
#include "smw_status.h"
#include "smw_keymgr.h"

typedef struct ele_tlv_blob {
    uint8_t *data;      // Pointer to the data
    size_t data_len;    // Length of the data
} ele_tlv_blob_t;

enum smw_status_code import_key(ele_tlv_blob_t *blob, struct smw_key_descriptor *key, uint32_t *import_key_id);
int init_key_from_tlv_blob(ele_tlv_blob_t *blob, struct smw_key_descriptor *key);
int do_import_key(int argc, char* argv[]);

#endif