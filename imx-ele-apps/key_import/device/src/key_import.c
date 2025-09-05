// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdint.h>
#include "key_import.h"
#include "hsm_importkey.h"
#include "hsm_utils.h"
#include "file_op.h"
#include "debug.h"
#include "main.h"
#include "hsm_api.h"

// Use ELE API to import the key
hsm_err_t import_key(ele_tlv_blob_t *blob, uint32_t *import_key_id)
{
    if (!blob || !blob->data || blob->data_len == 0 || !import_key_id) {
        fprintf(stderr, "Invalid TLV blob for import key.\n");
        return HSM_INVALID_PARAM;
    }

    hsm_err_t hsmret = HSM_GENERAL_ERROR;
    hsm_hdl_t hsm_session_hdl;
    hsm_hdl_t key_store_hdl;
    hsm_hdl_t key_mgmt_hdl;

    open_session_args_t open_session_args = {0};
    open_svc_key_store_args_t open_svc_args = {0};
    open_svc_key_management_args_t open_svc_key_mgmt_args = {0};

    op_import_key_args_t import_key_args = {0};

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

    hsmret = hsm_open_key_management_service(key_store_hdl, &open_svc_key_mgmt_args, &key_mgmt_hdl);
    if (hsmret != HSM_NO_ERROR) {
        fprintf(stderr, "hsm_open_key_management_service failed err:0x%x\n", hsmret);
        goto key_mgmt_fail;
    } else {
        printf("hsm_open_key_management_service success\n");
    }

    import_key_args.flags = HSM_OP_IMPORT_KEY_INPUT_ELE_TLV | HSM_OP_IMPORT_KEY_FLAGS_STRICT_OPERATION;
    import_key_args.input_lsb_addr = blob->data;
    import_key_args.input_size = blob->data_len;
    import_key_args.key_group = 0;

    hsmret = hsm_import_key(key_mgmt_hdl, &import_key_args);
    if (hsmret != HSM_NO_ERROR) {
        fprintf(stderr, "hsm_import_key failed err:0x%x\n", hsmret);
    } else {
        printf("hsm_import_key success\n");
        *import_key_id = import_key_args.key_identifier;
    }

    hsm_close_key_management_service(key_mgmt_hdl);
key_mgmt_fail:
    hsm_close_key_store_service(key_store_hdl);
key_store_fail:
    hsm_close_session(hsm_session_hdl);
out:
    return hsmret;
}

int do_import_key(int argc, char* argv[])
{
    if(argc != 2) {
        printUsage();
        return HSM_INVALID_PARAM;
    }

    char *tlv_blob_file = argv[1];
    int ret = HSM_NO_ERROR;
    ele_tlv_blob_t blob = {0};
    uint32_t import_key_id = 0;

    ret = read_from_file(tlv_blob_file, &blob.data, &blob.data_len);
    if (ret != 0) {
        fprintf(stderr, "Failed to read TLV blob from file %s: %d\n", tlv_blob_file, ret);
        goto out;
    }
    hex_dump("TLV Blob", blob.data, blob.data_len);

    ret = import_key(&blob, &import_key_id);
    if (ret != HSM_NO_ERROR) {
        fprintf(stderr, "Key import failed: %d\n", ret);
        goto out;
    }

    printf("Key imported successfully with ID: 0x%X\n", import_key_id);

out:
    my_free(blob.data);
    return ret;
}