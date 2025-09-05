// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <stdint.h>
#include <string.h>
#include "key_import.h"
#include "key_exchange.h"
#include "hsm_key.h"
#include "smw/attr.h"
#include "smw/names.h"
#include "smw_status.h"
#include "file_op.h"
#include "debug.h"
#include "main.h"
#include "get_smw_info.h"

static uint32_t arry2number(uint8_t *arry, uint8_t size)
{
    if(size < 1 || size > 4 || !arry) {
        fprintf(stderr, "Invalid input for arry2number: %d\n", size);
        return 0; // Invalid size
    }
    uint32_t number = 0;
    for (int i = 0; i < size; i++) {
        number = (number << 8) | arry[i];
    }
    return number;
}

int init_key_from_tlv_blob(ele_tlv_blob_t *blob, struct smw_key_descriptor *key)
{
    if (!blob || !blob->data || blob->data_len == 0 || !key) {
        fprintf(stderr, "Invalid TLV blob or key descriptor.\n");
        return SMW_STATUS_INVALID_PARAM; // Invalid parameters
    }

    memset(key, 0, sizeof(struct smw_key_descriptor));

    uint32_t key_type = arry2number(&blob->data[43], 2);
    uint32_t key_size_bit = arry2number(&blob->data[47], 4);

    struct smw_key_attributes *attributes = &(key->attributes);

    printf("Key Type: 0x%X, Key Size: %d bits\n", key_type, key_size_bit);
    // Transform the key properties as needed
    key->security_size = key_size_bit;

    //key prop for ECC key
    if(key_type == HSM_KEY_TYPE_ECC_NIST) {
        key->type_name = SMW_KEY_TYPE_NAME_SECP_R1;
        if(key_size_bit == 256) {
            attributes->permitted_algo = SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_ECDSA(SMW_ATTR_CURVE_SECP_R1, SMW_ATTR_HASH_SHA256);
        } else if(key_size_bit == 384) {
            attributes->permitted_algo = SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_ECDSA(SMW_ATTR_CURVE_SECP_R1, SMW_ATTR_HASH_SHA384);
        } else if(key_size_bit == 521) {
            attributes->permitted_algo = SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_ECDSA(SMW_ATTR_CURVE_SECP_R1, SMW_ATTR_HASH_SHA512);
        } else {
            fprintf(stderr, "Unsupported ECC key size: %d bits\n", key_size_bit);
            return -1;
        }
        attributes->usage_flags = SMW_ATTR_USAGE_SIGN_HASH | SMW_ATTR_USAGE_VERIFY_HASH;
    //key prop for AES key
    } else if(key_type == HSM_KEY_TYPE_AES) {
        key->type_name = SMW_KEY_TYPE_NAME_AES;
        attributes->permitted_algo = SMW_ATTR_ALGO_SYMMETRIC_ENCRYPTION(SMW_ATTR_ALGO_AES, SMW_ATTR_MODE_CTR);
        attributes->usage_flags = SMW_ATTR_USAGE_ENCRYPT | SMW_ATTR_USAGE_DECRYPT;
    } else if(key_type == HSM_KEY_TYPE_RSA){
        key->type_name = SMW_KEY_TYPE_NAME_RSA;
        attributes->permitted_algo = SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_RSA(SMW_ATTR_MODE_PKCS1_1_5, SMW_ATTR_HASH_ANY, 0);
        attributes->usage_flags = SMW_ATTR_USAGE_SIGN_HASH | SMW_ATTR_USAGE_VERIFY_HASH;
    }else{
        fprintf(stderr, "Unsupported key type: 0x%X\n", key_type);
        return -1; // Unsupported key type
    }

    attributes->attributes = SMW_ATTR_SET_LC_OPEN(attributes->attributes);
    attributes->attributes = SMW_ATTR_SET_LC_CLOSED(attributes->attributes);
    attributes->attributes = SMW_ATTR_SET_PERSISTENT(attributes->attributes);

    return 0; // Success
}

// Use SMW API to import the key
// Note: some SMW param value is different with the TLV blob value
//      e.g. key_usage, key_lifecycle, key_lifetime, permitted_algo
enum smw_status_code import_key(ele_tlv_blob_t *blob, struct smw_key_descriptor *key, uint32_t *import_key_id)
{
    if (!blob || !blob->data || blob->data_len == 0 || !key || !import_key_id) {
        fprintf(stderr, "Invalid TLV blob for import key.\n");
        return SMW_STATUS_INVALID_PARAM;
    }

    enum smw_status_code status = SMW_STATUS_OK;
    struct smw_import_key_args args = { 0 };
    struct smw_keypair_buffer buffer = { 0 };

    memset(&args, 0, sizeof(args));
    memset(&buffer, 0, sizeof(buffer));

    buffer.gen.private_length = blob->data_len;
    buffer.gen.private_data = blob->data;

    args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
    args.key_descriptor = key;

    key->buffer = &buffer; //might be a problem, as buffer is a local variable

    status = smw_import_key(&args);

    *import_key_id = key->id;
    key->buffer = NULL;

    return status;
}

int do_import_key(int argc, char* argv[])
{
    char *tlv_blob_file = NULL;
    int ret = SMW_STATUS_OPERATION_FAILURE;
    ele_tlv_blob_t blob = {0};
    struct smw_key_descriptor key = {0};
    uint32_t import_key_id = 0;

    if(oem_mk_persist_is_supported()!=FEATURE_SUPPORTED){
        if(argc != 4) {
            printUsage();
            return SMW_STATUS_INVALID_PARAM;
        }

        ret = do_key_exchange(3,argv);
        if (ret) {
            fprintf(stderr, "Key exchange failed: %d\n", ret);
            return ret;
        }

        tlv_blob_file=argv[3];
    }else{
        tlv_blob_file=argv[1];
    }



    ret = read_from_file(tlv_blob_file, &blob.data, &blob.data_len);
    if (ret != 0) {
        fprintf(stderr, "Failed to read TLV blob from file %s: %d\n", tlv_blob_file, ret);
        goto out;
    }
    hex_dump("TLV Blob", blob.data, blob.data_len);

    ret = init_key_from_tlv_blob(&blob, &key);
    if (ret) {
        fprintf(stderr, "Failed to initialize key from TLV blob: %d\n", ret);
        goto out;
    }

    // Use SMW API to import the key
    ret = import_key(&blob, &key, &import_key_id);
    if (ret != SMW_STATUS_OK) {
        fprintf(stderr, "Key import failed: %d\n", ret);
        goto out;
    }

    printf("Key imported successfully with ID: %u\n", import_key_id);

out:
    my_free(blob.data);
    return ret;
}