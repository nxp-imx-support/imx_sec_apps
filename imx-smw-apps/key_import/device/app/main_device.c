// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "get_smw_info.h"
#include "nxp_prod_ka_pub.h"
#include "key_import.h"
#include "smw_status.h"
#include "key_exchange.h"
#include "smw_osal.h"
#include "main.h"

/*
On device side, do the following:
1. Get the unsigned payload from the OEM public key PEM file. (Necessary for CST but not needed if using SPSDK for signed message)
2. Get the NXP_PROD_KA_PUB raw public key.
3. Do key exchange with the signed payload.
4. Import the OEM key with the warpped TLV blob.
 */

void my_free(void *ptr)
{
    if (ptr) {
        free(ptr);
        ptr = NULL;
    }
}

// If the OEM MK can be persist, we can do key exchange once for all
// If not, we need to do key exchange every time with key import
void printUsage()
{
    printf("Usage: ./smw_key_import <options>\n");
    printf("Options:\n");
    printf("  export_nxp <nxp_prod_ka_puk>\n");
    printf("        <nxp_prod_ka_puk>   The raw binary file which stores the NXP_PROD_KA_PUK, including 0x4 header\n");
    printf("  get_payload <oem_import_puk> <unsigned_payload>\n");
    printf("        <oem_import_puk>    The pem file for OEM_IMPORT_PUK\n");
    printf("        <unsigned_payload>  The output file for unsigned payload\n");

    if(oem_mk_persist_is_supported() == FEATURE_SUPPORTED){
        printf("  key_exchange <signed_message> <oem_import_puk>\n");
        printf("        <signed_message>    The signed message for key exchange\n");
        printf("  do_import <tlv_blob>\n");
        printf("        <tlv_blob>          The TLV blob for key import\n");
    }else if(oem_mk_persist_is_supported() == FEATURE_NOT_SUPPORTED){
        printf("  do_import <signed_message> <oem_import_puk> <tlv_blob>\n");
        printf("        <signed_message>    The signed message for key exchange\n");
        printf("        <tlv_blob>          The TLV blob for key import\n");
    }

}

int main(int argc, char *argv[]) {
    if(key_import_is_supported()!=FEATURE_SUPPORTED){
        fprintf(stderr, "key import feature is not supported\n");
        return SMW_STATUS_VERSION_NOT_SUPPORTED;
    }

    if (argc < 2) {
        printUsage();
        return SMW_STATUS_INVALID_PARAM;
    }

    printf("%s %s:%s %s\n",argv[0], __DATE__, __TIME__, GITVERSION);

    int ret = 0;

    ret = smw_osal_lib_init();
    if (ret != SMW_STATUS_OK) {
        printf("SMW library initialization failed %d\n", ret);
        return ret;
    }

    if(strcmp(argv[1], "export_nxp") == 0) {
        return export_nxp(argc-1, &argv[1]);
    }else if(strcmp(argv[1], "get_payload") == 0) {
        return get_raw_payload(argc-1, &argv[1]);
    }else if(strcmp(argv[1], "key_exchange") == 0) {
        if(oem_mk_persist_is_supported()!=FEATURE_SUPPORTED){
            fprintf(stderr, "cannot do key_exchange standalone\n");
            return SMW_STATUS_VERSION_NOT_SUPPORTED;
        }
        return do_key_exchange(argc-1, &argv[1]);
    }else if(strcmp(argv[1], "do_import") == 0) {
        return do_import_key(argc-1, &argv[1]);
    }else{
        printUsage();
        return SMW_STATUS_INVALID_PARAM;
    }

    return 0;
}