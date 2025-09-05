// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */
#include "nxp_prod_ka_pub.h"
#include "smw/names.h"
#include "smw_status.h"
#include "stdio.h"
#include "smw_keymgr.h"
#include "main.h"
#include "debug.h"
#include "file_op.h"

enum smw_status_code nxp_prod_ka_pub_export(uint8_t *prod_ka_pub, size_t pub_len)
{
    enum smw_status_code res = SMW_STATUS_OPERATION_FAILURE;

    if (prod_ka_pub == NULL || pub_len != PROD_KA_PUB_LEN) {
        return SMW_STATUS_INVALID_PARAM;
    }
    struct smw_export_key_args export_key_args = {0};
    struct smw_keypair_gen keypair_gen = {
        .public_data = prod_ka_pub,
        .public_length = pub_len,
        .private_data = NULL,
        .private_length = 0,
    };
    struct smw_keypair_buffer keypair_buffer = {
        .format_name = SMW_KEY_FORMAT_NAME_HEX,
        .gen = keypair_gen,
    };
    struct smw_key_descriptor key_descriptor = {
        .id = NXP_PROD_KA_PUK_ID,
        .security_size = 256,
        .type_name = SMW_KEY_TYPE_NAME_SECP_R1,
        .buffer = &keypair_buffer,
    };

    export_key_args.key_descriptor = &key_descriptor;
    res = smw_export_key(&export_key_args);
    if (res != SMW_STATUS_OK) {
        printf("SMW export key failed %d\n", res);
        return res;
    }

    return SMW_STATUS_OK;
}

int export_nxp(int argc, char* argv[])
{
    if (argc != 2) {
        printUsage();
        return SMW_STATUS_INVALID_PARAM;
    }

    char *nxp_prod_ka_puk_file = argv[1];
    int ret = 0;
    uint8_t prod_ka_pub[PROD_KA_PUB_LEN + 1] = {0};

    // export NXP_PROD_KA_PUB raw public key
    ret = nxp_prod_ka_pub_export(&prod_ka_pub[1], PROD_KA_PUB_LEN);
    if (ret != SMW_STATUS_OK) {
        fprintf(stderr, "Export NXP_PROD_KA_PUB failed %d\n", ret);
        goto out;
    }
    printf("Export NXP_PROD_KA_PUB success\n");
    // add 0x04 prefix to the public key, as it's used for OpenSSL ECDH
    prod_ka_pub[0] = ECC_PUB_KEY_FORMAT_RAW;
    hex_dump("Exported Key", &prod_ka_pub[1], PROD_KA_PUB_LEN);

    ret = write2file(nxp_prod_ka_puk_file, prod_ka_pub, sizeof(prod_ka_pub));
    if (ret != 0) {
        fprintf(stderr, "Failed to write NXP_PROD_KA_PUK to file %s: %d\n", nxp_prod_ka_puk_file, ret);
        goto out;
    }
    printf("NXP_PROD_KA_PUK written to %s successfully.\n", nxp_prod_ka_puk_file);

out:
    return ret;
}