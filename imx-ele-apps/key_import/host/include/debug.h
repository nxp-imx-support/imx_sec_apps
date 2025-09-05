// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef _DEBUG_H_
#define _DEBUG_H_
#include <stdint.h>
#include <stdio.h>

void hex_dump(const char *title, const uint8_t *data, size_t len);

#endif // _DEBUG_H_