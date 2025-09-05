// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cipher.h"
#include "file_op.h"
#include "debug.h"

void printUsage()
{
    printf("Usage: ./ele_aes_usage <operation> <mode> <input file> <output file> <key_id>\n");
    printf("    <operation>: encrypt, decrypt\n");
    printf("    <mode>: ECB, CBC, CTR, CFB, OFB\n");
    printf("    <input file>: input file name\n");
    printf("    <output file>: output file name\n");
    printf("    <key_id>: key identifier in HSM\n");
}

int main(int argc, char* argv[])
{
    bool encrypt = false;
    hsm_cipher_algo_t algo = ALGO_INVALID;
    uint8_t * input = NULL;
    size_t input_len = 0;
    uint8_t * output = NULL;
    size_t output_len = 0;
    uint32_t key_id = 0;
    int ret = 0;
    
    printf("Hello, World! %s:%s %s\n", __DATE__, __TIME__, GITVERSION);

    if(argc < 6) {
        printUsage();
        return -1;
    }

    if(strcmp(argv[1], "encrypt") == 0) {
        encrypt = true;
    } else if(strcmp(argv[1], "decrypt") == 0) {
        encrypt = false;
    } else {
        printUsage();
        return -1;
    }

    algo = get_algo(argv[2]);
    if (algo == ALGO_INVALID) {
        printUsage();
        return -1;
    }

    ret = read_from_file(argv[3], &input, &input_len);
    if (ret) {
        fprintf(stderr, "Failed to read input file %s\n", argv[3]);
        goto out;
    }

    if(algo == ALGO_CIPHER_ECB_NO_PAD || algo == ALGO_CIPHER_CBC_NO_PAD) {
        // apply PKCS7 padding for ECB and CBC mode
        ret = pkcs7_padding(&input, &input_len, 16);
        if ( ret) {
            fprintf(stderr, "PKCS7 padding failed\n");
            goto out;
        }
    }
    if(encrypt)
        printf("message preview:\n%.*s\n", (int)input_len, input);
    else
        hex_dump("input data", input, input_len);

    output_len = input_len;
    output = (uint8_t *)malloc(output_len);
    if (!output) {
        fprintf(stderr, "Memory allocation failed\n");
        goto out;
    }
    memset(output, 0, output_len);

    key_id = strtoul(argv[5], NULL, 0);
    if (key_id == 0) {
        fprintf(stderr, "Invalid key_id %s\n", argv[5]);
        goto out;
    }

    ret = cipher_with_ele_cipher(encrypt, algo, input, input_len, output, output_len, key_id);
    if (ret != HSM_NO_ERROR) {
        fprintf(stderr, "cipher_with_ele_cipher failed ret:0x%x\n", ret);
        goto out;
    }

    if(encrypt)
        hex_dump("encrypt result", output, output_len);
    else
        printf("decrypt preview:\n%.*s\n", (int)output_len, output);

    ret = write2file(argv[4], output, output_len);
    if (ret) {
        fprintf(stderr, "Failed to write output file %s\n", argv[4]);
        goto out;
    }

out:
    if(input)
        free(input);
    if(output)
        free(output);
    return ret;
}