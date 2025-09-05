// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef _ECDH_H_
#define _ECDH_H_
#include <stdio.h>
#include <stdint.h>

int ecdh(char *oem_private_key_pem, uint8_t *nxp_prod_ka_pub, size_t nxp_prod_ka_pub_len, uint8_t **shared_secret, size_t *shared_secret_len);

#endif