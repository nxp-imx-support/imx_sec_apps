// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef _FILE_OP_H_
#define _FILE_OP_H_

#include <stdint.h>
#include <stdio.h>

int write2file(const char *filename, const uint8_t *data, size_t data_len);
int read_from_file(const char *filename, uint8_t **data, size_t *data_len);
#endif