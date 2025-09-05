// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "main.h"
#include "nxp_prod_ka_puk.h"
#include "key_exchange.h"
#include "key_import.h"

/*
On device side, do the following:
1. Get the NXP_PROD_KA_PUB raw public key.
2. Do key exchange with the signed message.
3. Import the OEM key with the warpped TLV blob.
 */

void my_free(void *ptr)
{
    if (ptr) {
        free(ptr);
        ptr = NULL;
    }
}

void printUsage()
{
    printf("Usage: ./ele_key_import <options>\n");
    printf("Options:\n");
    printf("  export_nxp <nxp_prod_ka_puk>\n");
    printf("        <nxp_prod_ka_puk>   The raw binary file which stores the NXP_PROD_KA_PUK, including 0x4 header\n");
    printf("  key_exchange <signed_message> <oem_import_puk>\n");
    printf("        <signed_message>    The signed message for key exchange, get from SPSDK\n");
    printf("        <oem_import_puk>    The OEM_IMPORT_PUK pem file for key exchange\n");
    printf("  do_import <tlv_blob>\n");
    printf("        <tlv_blob>          The TLV blob for key import\n");
}

int main(int argc, char* argv[])
{
    printf("Hello, World! %s:%s %s\n", __DATE__, __TIME__, GITVERSION);

    if(argc < 2) {
        printUsage();
        return -1;
    }

    int ret = 0;

    if (strcmp(argv[1], "export_nxp") == 0) {
        ret = export_nxp(argc-1, &argv[1]);
    } else if (strcmp(argv[1], "key_exchange") == 0) {
        ret = do_key_exchange(argc-1, &argv[1]);
    } else if (strcmp(argv[1], "do_import") == 0) {
        ret = do_import_key(argc-1, &argv[1]);
    } else {
        printf("Unknown command: %s\n", argv[1]);
        printUsage();
        return -1;
    }

    return ret;
}