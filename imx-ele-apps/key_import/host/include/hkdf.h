// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef _HKDF_H_
#define _HKDF_H_
#include <stdio.h>
#include <stdint.h>

int hkdf(uint8_t *secret, size_t secret_len, uint8_t* info, size_t info_len, uint8_t *out_key, size_t out_key_len);

#endif