// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */
#include "nxp_prod_ka_puk.h"
#include "common/key_store.h"
#include "hsm_handle.h"
#include "hsm_key_recovery.h"
#include "hsm_key_store.h"
#include "stdio.h"
#include "main.h"
#include "debug.h"
#include "file_op.h"
#include <stdint.h>
#include "hsm_api.h"

hsm_err_t nxp_prod_ka_puk_export(uint8_t *prod_ka_puk, size_t puk_len)
{
    if(!prod_ka_puk){
        return HSM_INVALID_PARAM;
    }

    hsm_err_t hsmret = HSM_GENERAL_ERROR;
    hsm_hdl_t hsm_session_hdl;
    hsm_hdl_t key_store_hdl;
    open_session_args_t open_session_args = {0};
    open_svc_key_store_args_t open_svc_args = {0};
    op_pub_key_recovery_args_t op_pub_key_recovery_args = {0};

    open_session_args.mu_type = HSM1;
    hsmret = hsm_open_session(&open_session_args,
                                &hsm_session_hdl);
    
    if (hsmret != HSM_NO_ERROR) {
            fprintf(stderr,"hsm_open_session failed err:0x%x\n", hsmret);
            goto out;
    } else {
        printf("hsm_open_session success\n");
    }

    open_svc_args.authentication_nonce = 0x534D57;
    open_svc_args.key_store_identifier = 0x454C4500;
    open_svc_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
    hsmret = hsm_open_key_store_service(hsm_session_hdl, &open_svc_args, &key_store_hdl);
    if (hsmret == HSM_KEY_STORE_CONFLICT){
        open_svc_args.flags = HSM_SVC_KEY_STORE_FLAGS_LOAD;
        printf("Key store already created, trying to load it...\n");
        hsmret = hsm_open_key_store_service(hsm_session_hdl, &open_svc_args, &key_store_hdl);
    }

    if(hsmret != HSM_NO_ERROR) {
        fprintf(stderr, "hsm_open_key_store_service failed err:0x%x\n", hsmret);
        goto key_store_fail;
    } else {
        printf("hsm_open_key_store_service success\n");
    }

    op_pub_key_recovery_args.key_identifier = NXP_PROD_KA_PUK_ID;
    op_pub_key_recovery_args.out_key_size = puk_len;
    op_pub_key_recovery_args.out_key = prod_ka_puk;
    hsmret = hsm_pub_key_recovery(key_store_hdl, &op_pub_key_recovery_args);
    if (hsmret != HSM_NO_ERROR) {
        fprintf(stderr, "hsm_pub_key_recovery failed err:0x%x\n", hsmret);
    } else {
        printf("hsm_pub_key_recovery success\n");
    }

    hsm_close_key_store_service(key_store_hdl);
key_store_fail:
    hsm_close_session(hsm_session_hdl);
out:
    return hsmret;
}

int export_nxp(int argc, char* argv[])
{
    if (argc < 2) {
        printUsage();
        return -1;
    }

    char *nxp_prod_ka_puk_file = argv[1];
    uint8_t prod_ka_puk[PROD_KA_PUK_LEN + 1] = {0};

    hsm_err_t ret = HSM_GENERAL_ERROR;
    // export NXP_PROD_KA_PUK raw public key
    ret = nxp_prod_ka_puk_export(&prod_ka_puk[1], PROD_KA_PUK_LEN);
    if (ret != HSM_NO_ERROR) {
        fprintf(stderr, "Export NXP_PROD_KA_PUK failed %d\n", ret);
        goto out;
    }
    printf("Export NXP_PROD_KA_PUK success\n");
    // add 0x04 prefix to the public key, as it's used for OpenSSL ECDH
    prod_ka_puk[0] = ECC_PUB_KEY_FORMAT_RAW;
    hex_dump("Exported Key", &prod_ka_puk[1], PROD_KA_PUK_LEN);

    ret = write2file(nxp_prod_ka_puk_file, prod_ka_puk, sizeof(prod_ka_puk));
    if (ret != 0) {
        fprintf(stderr, "Failed to write NXP_PROD_KA_PUK to file %s: %d\n", nxp_prod_ka_puk_file, ret);
        goto out;
    }
    printf("NXP_PROD_KA_PUK written to %s successfully.\n", nxp_prod_ka_puk_file);

out:
    return ret;
}