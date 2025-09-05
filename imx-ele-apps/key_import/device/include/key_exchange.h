// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef _KEY_EXCHANGE_H_
#define _KEY_EXCHANGE_H_

#include <stdint.h>
#include <stdio.h>
#include "hsm_utils.h"
#define OEM_IMPORT_MK_SK_ID 0x1

int get_oem_import_puk(char *filename, uint8_t **puk, size_t *puk_len);
hsm_err_t key_exchange(uint8_t *payload, size_t payload_len, uint8_t *oem_puk, size_t puk_len);
int do_key_exchange(int argc, char* argv[]);

#endif