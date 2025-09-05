// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "file_op.h"
#include <stdlib.h>


int write2file(const char *filename, const uint8_t *data, size_t data_len)
{
    if (!filename || !data || data_len == 0) {
        return -1; // Invalid parameters
    }

    FILE *fp = fopen(filename, "w");
    if (!fp) {
        perror("Unable to open file for writing");
        return 1;
    }
    size_t written = fwrite(data, 1, data_len, fp);
    fclose(fp);
    if (written != data_len) {
        fprintf(stderr, "Error writing to file: expected %zu bytes, wrote %zu bytes\n", data_len, written);
        return 1;
    }
    return 0; // Success
}

int read_from_file(const char *filename, uint8_t **data, size_t *data_len)
{
    if (!filename || !data || !data_len) {
        return -1; // Invalid parameters
    }

    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("Unable to open file for reading");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    *data_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    *data = malloc(*data_len);
    if (!*data) {
        fclose(fp);
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    size_t read = fread(*data, 1, *data_len, fp);
    fclose(fp);
    if (read != *data_len) {
        fprintf(stderr, "Error reading from file: expected %zu bytes, read %zu bytes\n", *data_len, read);
        free(*data);
        return 1;
    }
    
    return 0; // Success
}