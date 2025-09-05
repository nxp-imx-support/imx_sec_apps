// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <sys/types.h>
#include "key_exchange.h"
#include "nxp_prod_ka_pub.h"
#include "smw_status.h"
#include "smw/attr.h"
#include "smw_keymgr.h"
#include "main.h"
#include "debug.h"
#include "file_op.h"

int get_oem_import_puk(char *filename, uint8_t **puk, size_t *puk_len)
{
    if (!filename || !puk || !puk_len) {
        return -1; // Invalid parameters
    }

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Unable to open PEM file");
        return 1;
    }

    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) {
        fprintf(stderr, "Error reading public key from PEM\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec_key) {
        fprintf(stderr, "Not an EC key\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    const EC_POINT *point = EC_KEY_get0_public_key(ec_key);

    *puk_len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    *puk = malloc(*puk_len);
    if (!*puk) {
        fprintf(stderr, "Memory allocation failed\n");
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        return 1;
    }

    EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, *puk, *puk_len, NULL);

    EC_KEY_free(ec_key);
    EVP_PKEY_free(pkey);
    return 0;
}

enum smw_status_code get_oem_master_key_message(uint8_t* oem_import_puk, size_t puk_len, uint8_t **payload, size_t *payload_len)
{
    if ( !oem_import_puk || puk_len == 0 || !payload || !payload_len) {
        return SMW_STATUS_INVALID_PARAM;
    }

    enum smw_status_code status = SMW_STATUS_OK;
    struct smw_derive_key_args args = { 0 };
    struct smw_kdf_oem_master_key_args oem_mk_args = { 0 };
    struct smw_key_descriptor key_base = { 0 };
    struct smw_derived_key_descriptor key_derived = { 0 };

    args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
    args.key_descriptor_base = &key_base;
    args.kdf_name = SMW_KDF_NAME_OEM_MASTER_KEY;
    args.kdf_arguments = &oem_mk_args;
    args.store_derived_key = false; /* Not store it for prepare operation */
    args.key_descriptor_derived = &key_derived;

    oem_mk_args.op = SMW_OEM_MK_OP_NAME_PREPARE;
    oem_mk_args.peer_public_buffer = oem_import_puk;
    oem_mk_args.peer_public_buffer_length = puk_len;
    oem_mk_args.payload = NULL;
    oem_mk_args.payload_length = 0;

    key_base.id = NXP_PROD_KA_PUK_ID;

    key_derived.type_name = SMW_KEY_TYPE_NAME_DERIVE;
    key_derived.security_size = 256;
    key_derived.id = OEM_IMPORT_MK_SK_ID;
    key_derived.attributes.permitted_algo = SMW_ATTR_ALGO_KEY_DERIVATION_HKDF(SHA256);
    key_derived.attributes.usage_flags = SMW_ATTR_USAGE_DERIVE;
    key_derived.attributes.attributes = SMW_ATTR_PERSISTENCE_PERSISTENT;
    //key_derived.attributes.storage_id = 1; // key group of OEM Master Key

    status = smw_derive_key(&args);
    if (status != SMW_STATUS_OK ||
        !oem_mk_args.payload_length) {
        fprintf(stderr, "Unable to get OEM Master key payload size\n");
        return status;
    }

    printf("OEM Master Key payload length: %u\n", oem_mk_args.payload_length);
    *payload_len = oem_mk_args.payload_length;
    *payload = malloc(oem_mk_args.payload_length);
    if (!*payload)
        return SMW_STATUS_SUBSYSTEM_OUT_OF_MEMORY;
    oem_mk_args.payload = *payload;

    return smw_derive_key(&args);
}

enum smw_status_code key_exchange(uint8_t *payload, size_t payload_len, uint8_t *oem_puk, size_t puk_len)
{
    if (!payload || payload_len == 0 || !oem_puk || puk_len == 0) {
        return SMW_STATUS_INVALID_PARAM;
    }

    struct smw_derive_key_args args = { 0 };
    struct smw_kdf_oem_master_key_args oem_mk_args = { 0 };
    struct smw_key_descriptor key_base = { 0 };
    struct smw_derived_key_descriptor key_derived = { 0 };

    args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
    args.key_descriptor_base = &key_base;
    args.kdf_name = SMW_KDF_NAME_OEM_MASTER_KEY;
    args.kdf_arguments = &oem_mk_args;
    args.store_derived_key = false;
    args.key_descriptor_derived = &key_derived;

    oem_mk_args.op = SMW_OEM_MK_OP_NAME_DERIVE;
    oem_mk_args.peer_public_buffer = oem_puk;
    oem_mk_args.peer_public_buffer_length = puk_len;
    oem_mk_args.payload = payload;
    oem_mk_args.payload_length = payload_len;
    oem_mk_args.info = NULL; // Optional context information
    oem_mk_args.info_len = 0;
    oem_mk_args.use_peer_key_digest_kdf = false; // Not used in this case
    oem_mk_args.use_oem_srkh_kdf = false; // Not used in this case

    key_base.id = NXP_PROD_KA_PUK_ID;

    key_derived.type_name = SMW_KEY_TYPE_NAME_DERIVE;
    key_derived.security_size = 256;
    key_derived.id = OEM_IMPORT_MK_SK_ID;
    key_derived.attributes.permitted_algo = SMW_ATTR_ALGO_KEY_DERIVATION_HKDF(SHA256);
    key_derived.attributes.usage_flags = SMW_ATTR_USAGE_DERIVE;
    key_derived.attributes.attributes = SMW_ATTR_PERSISTENCE_PERSISTENT;

    return smw_derive_key(&args);
}

int get_raw_payload(int argc, char* argv[])
{
    if (argc != 3) {
        printUsage();
        return SMW_STATUS_INVALID_PARAM;
    }
    char *oem_public_key_pem = argv[1];
    char *unsigned_msg_file = argv[2];
    uint8_t *puk = NULL;
    size_t puk_len = 0;
    uint8_t *payload = NULL;
    size_t payload_len = 0;

    int ret = 0;

    // get the raw public key from the PEM file, with 0x04 prefix
    ret = get_oem_import_puk(oem_public_key_pem, &puk, &puk_len);
    if (ret != 0) {
        fprintf(stderr, "Failed to get OEM import PUK from file %s: %d\n", oem_public_key_pem, ret);
        goto out;
    }
    hex_dump("OEM Import PUK", puk, puk_len);

    // use raw public key without tag 0x04, to generate the unsigned payload
    ret = get_oem_master_key_message(&puk[1], puk_len-1, &payload, &payload_len);
    if (ret != SMW_STATUS_OK) {
        fprintf(stderr, "Failed to get OEM Master key message: %d\n", ret);
        free(puk);
        return ret;
    }
    hex_dump("OEM Master Key Payload", payload, payload_len);

    // write the ussigned payload to file
    ret = write2file(unsigned_msg_file, payload, payload_len);
    if (ret != 0) {
        fprintf(stderr, "Failed to write OEM Master key payload to file %s: %d\n", unsigned_msg_file, ret);
        goto out;
    }
    printf("OEM Master key payload written to %s successfully.\n", unsigned_msg_file);
    printf("please sign the payload and do key exchange with it\n");

out:
    my_free(puk);
    my_free(payload);
    return SMW_STATUS_OK;
}

int do_key_exchange(int argc, char* argv[])
{
    if (argc != 3) {
        printUsage();
        return SMW_STATUS_INVALID_PARAM;
    }

    char *signed_msg_file = argv[1];
    uint8_t *signed_payload = NULL;
    size_t signed_payload_len = 0;

    char *oem_public_key_pem = argv[2];
    uint8_t *puk = NULL;
    size_t puk_len = 0;

    int ret = 0;

    // get the signed payload from the signed file
    ret = read_from_file(signed_msg_file, &signed_payload, &signed_payload_len);
    if (ret != 0) {
        fprintf(stderr, "Failed to read signed message from file %s: %d\n", signed_msg_file, ret);
        goto out;
    }
    hex_dump("Signed Message", signed_payload, signed_payload_len);

        // get the raw public key from the PEM file, with 0x04 prefix
    ret = get_oem_import_puk(oem_public_key_pem, &puk, &puk_len);
    if (ret != 0) {
        fprintf(stderr, "Failed to get OEM import PUK from file %s: %d\n", oem_public_key_pem, ret);
        goto out;
    }
    hex_dump("OEM Import PUK", puk, puk_len);

    // do key exchange with signed payload and oem raw public key without 0x04 prefix
    ret = key_exchange(signed_payload, signed_payload_len, &puk[1], puk_len-1);
    if(ret == SMW_STATUS_OBJ_DB_CREATE || ret == SMW_STATUS_INVALID_PARAM){
        printf("Key already derived\n");
        ret=0;
    }else if(ret == SMW_STATUS_OK) {
        printf("Key exchange successful\n");
    }else{
        fprintf(stderr, "Key exchange failed: %d\n", ret);
        goto out;
    }

out:
    my_free(signed_payload);
    my_free(puk);
    return ret;
}