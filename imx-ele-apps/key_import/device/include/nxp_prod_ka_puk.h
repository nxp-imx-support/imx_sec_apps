// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef _NXP_PROD_KA_PUK_H_
#define _NXP_PROD_KA_PUK_H_

#include <stdint.h>
#include <stdio.h>
#include "hsm_utils.h"

#define PROD_KA_PUK_LEN 64 // For ECC key type, public key is exported in a non-compressed form {x, y}, in big-endian order.
#define ECC_PUB_KEY_FORMAT_RAW 0x04
#define NXP_PROD_KA_PUK_ID 0x70000000

hsm_err_t nxp_prod_ka_puk_export(uint8_t *prod_ka_puk, size_t puk_len);
int export_nxp(int argc, char* argv[]);

#endif