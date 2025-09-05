// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef _NXP_PROD_KA_PUB_H_
#define _NXP_PROD_KA_PUB_H_

#include "smw_status.h"
#include <stdint.h>
#include <stdio.h>

#define PROD_KA_PUB_LEN 64 // For ECC key type, public key is exported in a non-compressed form {x, y}, in big-endian order.
#define ECC_PUB_KEY_FORMAT_RAW 0x04
#define NXP_PROD_KA_PUK_ID 0x70000000

enum smw_status_code nxp_prod_ka_pub_export(uint8_t *prod_ka_pub, size_t pub_len);
int export_nxp(int argc, char* argv[]);

#endif