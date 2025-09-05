// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */
#include "debug.h"

void hex_dump(const char *title, const uint8_t *data, size_t len) {
    printf("%s: %ld bytes\n", title, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n\n");
}