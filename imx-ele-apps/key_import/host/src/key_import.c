// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <stdint.h>
#include <string.h>
#include "key_import.h"
#include "key_exchange.h"
#include "hsm_key.h"
#include "file_op.h"
#include "debug.h"

static hsm_key_type_t switch_rsa_ecc(const char *filename) {
    hsm_key_type_t key_type=HSM_KEY_TYPE_UNKNOWN;
    if(!filename) return HSM_KEY_TYPE_UNKNOWN;

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Failed to open file");
        return HSM_KEY_TYPE_UNKNOWN;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (!pkey) {
        rewind(fp);
        pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    }

    fclose(fp);

    if (!pkey) {
        perror("Not a valid PEM key file.\n");
        return HSM_KEY_TYPE_UNKNOWN;
    }

    int type = EVP_PKEY_base_id(pkey);
    switch (type) {
        case EVP_PKEY_RSA:
            key_type = HSM_KEY_TYPE_RSA;
            break;
        case EVP_PKEY_EC:
            key_type = HSM_KEY_TYPE_ECC_NIST;
            break;
        default:
            key_type=HSM_KEY_TYPE_UNKNOWN;
            printf("Other key type detected: %d\n", type);
            break;
    }

    EVP_PKEY_free(pkey);
    return key_type;
}

static hsm_key_type_t detect_key_type(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) return HSM_KEY_TYPE_UNKNOWN;

    char buffer[256] = {0};
    size_t data_len = fread(buffer, 1, sizeof(buffer) - 1, fp);
    (void)data_len;
    fclose(fp);

    if (strstr(buffer, "BEGIN RSA PRIVATE KEY")) return HSM_KEY_TYPE_RSA;
    if (strstr(buffer, "BEGIN EC PRIVATE KEY")) return HSM_KEY_TYPE_ECC_NIST;
    if (strstr(buffer, "BEGIN PRIVATE KEY")) return switch_rsa_ecc(filename);

    fp = fopen(filename, "rb");
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fclose(fp);

    if (size == 16 || size == 24 || size == 32) {
        return HSM_KEY_TYPE_AES;
    }

    return HSM_KEY_TYPE_UNKNOWN;
}

static int read_ecc_key_from_pem(const char *filename, import_key_prop_t *import_key_prop) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Unable to open PEM file");
        return 1;
    }

    EC_KEY *ec_key = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!ec_key) {
        fprintf(stderr, "Failed to read EC private key\n");
        return 1;
    }

    const BIGNUM *priv_bn = EC_KEY_get0_private_key(ec_key);
    if (!priv_bn) {
        fprintf(stderr, "No private key found\n");
        EC_KEY_free(ec_key);
        return 1;
    }

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    int degree = EC_GROUP_get_degree(group);
    import_key_prop->oem_key_len = (degree + 7) / 8; // Convert bits to bytes， P521 key is 66 bytes
    import_key_prop->oem_key = malloc(import_key_prop->oem_key_len);
    if (!import_key_prop->oem_key) {
        fprintf(stderr, "Memory allocation failed\n");
        EC_KEY_free(ec_key);
        return 1;
    }
    import_key_prop->key_import_args.bit_key_sz = degree;

    if(degree == 256) {
        import_key_prop->key_import_args.permitted_algo = PERMITTED_ALGO_ECDSA_SHA256;
    } else if(degree == 384) {
        import_key_prop->key_import_args.permitted_algo = PERMITTED_ALGO_ECDSA_SHA384;
    } else if(degree == 521) {
        import_key_prop->key_import_args.permitted_algo = PERMITTED_ALGO_ECDSA_SHA512;
    } else {
        fprintf(stderr, "Unsupported ECC key size: %d bits\n", degree);
        EC_KEY_free(ec_key);
        free(import_key_prop->oem_key);
        return 1; // Unsupported key size
    }

    int len = BN_bn2binpad(priv_bn, import_key_prop->oem_key, import_key_prop->oem_key_len);

    if (len <= 0) {
        fprintf(stderr, "Failed to convert BIGNUM to binary\n");
        return 1;
    }

    int nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key));
    const char *curve_name = OBJ_nid2sn(nid);
    printf("Curve type: %s\n", curve_name);

    EC_KEY_free(ec_key);
    return 0;
}

// For RSA asymmetric private keys, 
// it must be the concatenation of the modulus followed by the private exponent, in big-endian order. 
// It’s inspired by the syntax described by RFC 8017, without ASN.1 encode bytes.
static int read_rsa_key_from_pem(const char * filename, import_key_prop_t *import_key_prop){
    if(!filename || !import_key_prop) return -1;

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Failed to open PEM file");
        return 1;
    }

    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!rsa) {
        fprintf(stderr, "Failed to read RSA private key.\n");
        return 1;
    }

    const BIGNUM * bn_n = RSA_get0_n(rsa);
    const BIGNUM * bn_d = RSA_get0_d(rsa);

    import_key_prop->oem_key_len = BN_num_bytes(bn_n) + BN_num_bytes(bn_d);
    import_key_prop->oem_key = malloc(import_key_prop->oem_key_len);
    import_key_prop->key_import_args.bit_key_sz = RSA_bits(rsa);
    if (!import_key_prop->oem_key) {
        fprintf(stderr, "Memory allocation failed.\n");
        return -1;
    }

    BN_bn2bin(bn_n, import_key_prop->oem_key);
    BN_bn2bin(bn_d, &import_key_prop->oem_key[import_key_prop->oem_key_len/2]);

    RSA_free(rsa);

    return 0;
}

int get_oem_key(const char *oem_key_file_name, import_key_prop_t *import_key_prop)
{
    if (!oem_key_file_name || !import_key_prop) {
        fprintf(stderr, "Invalid input parameters.\n");
        return -1; // Error
    }

    int ret = 0;
    memset(&import_key_prop->key_import_args, 0, sizeof(import_key_prop->key_import_args));
    hsm_key_type_t key_type = detect_key_type(oem_key_file_name);

    import_key_prop->key_import_args.key_type = key_type;
    if(key_type == HSM_KEY_TYPE_ECC_NIST) {
        ret = read_ecc_key_from_pem(oem_key_file_name, import_key_prop);
        if (ret != 0) {
            fprintf(stderr, "Failed to read ECC key from file: %s\n", oem_key_file_name);
            return ret; // Error reading file
        }
        import_key_prop->key_import_args.key_usage = HSM_KEY_USAGE_SIGN_HASH | HSM_KEY_USAGE_VERIFY_HASH;
    }else if(key_type == HSM_KEY_TYPE_AES) {
        ret = read_from_file(oem_key_file_name, &import_key_prop->oem_key, &import_key_prop->oem_key_len);
        if (ret != 0) {
            fprintf(stderr, "Failed to read OEM key from file: %s\n", oem_key_file_name);
            return ret; // Error reading file
        }
        import_key_prop->key_import_args.bit_key_sz = import_key_prop->oem_key_len * 8; // Convert bytes to bits
        import_key_prop->key_import_args.permitted_algo = PERMITTED_ALGO_ALL_CIPHER;
        import_key_prop->key_import_args.key_usage = HSM_KEY_USAGE_ENCRYPT | HSM_KEY_USAGE_DECRYPT;
    }else if(key_type == HSM_KEY_TYPE_RSA){
        ret = read_rsa_key_from_pem(oem_key_file_name, import_key_prop);
        if (ret != 0) {
            fprintf(stderr, "Failed to read RSA key from file: %s\n", oem_key_file_name);
            return ret;
        }
        import_key_prop->key_import_args.key_usage = HSM_KEY_USAGE_SIGN_HASH | HSM_KEY_USAGE_VERIFY_HASH;
        import_key_prop->key_import_args.permitted_algo = PERMITTED_ALGO_RSA_PKCS1_V15_SHA_ANY;
    }else{
        fprintf(stderr, "Unsupported key type in file: %s\n", oem_key_file_name);
        return -1; // Unsupported key type
    }

    import_key_prop->key_import_args.key_lifetime = HSM_ELE_IMPORT_KEY_PERSISTENT;
    import_key_prop->key_import_args.key_lifecycle = HSM_KEY_LIFECYCLE_OPEN | HSM_KEY_LIFECYCLE_CLOSED;

    return ret;
}

void print_key_prop(import_key_prop_t *import_key_prop)
{
    if (!import_key_prop) return;
    hex_dump("OEM Key", (*import_key_prop).oem_key, (*import_key_prop).oem_key_len);
    printf("Key Type: 0x%X\n\n", (*import_key_prop).key_import_args.key_type);
}

int iso7816_4_padding(uint8_t **data, size_t *data_len, size_t block_size) {
    if (!data || !data_len || block_size == 0) return -1;

    //if the data length is already aligned, return success;
    if(*data_len % block_size == 0) return 0;

    size_t pad_len = block_size - (*data_len % block_size);
    size_t padded_len = *data_len + pad_len;

    uint8_t *new_ptr = realloc(*data, padded_len);
    if (!new_ptr) return -2;

    new_ptr[*data_len] = 0x80;
    memset(new_ptr + *data_len + 1, 0x00, pad_len - 1);

    *data = new_ptr;
    *data_len = padded_len;
    return 0;
}

int aes_cbc_encrypt(const unsigned char *plaintext, int plaintext_len,
                    const unsigned char *key, unsigned char *ciphertext, int * ciphertext_len, uint8_t *iv) {
    int len;

    if(!plaintext || !key || plaintext_len % 16 != 0 || !ciphertext || !iv) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1; // Error creating context
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) return -1;

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) return -1;
    *ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return -1;
    *ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

int aes_warp(const unsigned char *key, const unsigned char *plaintext, size_t plaintext_len, unsigned char *ciphertext, int *outlen)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1; // Error creating context
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_wrap(), NULL, key, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1; // Error initializing encryption
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, outlen, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1; // Error during encryption
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0; // Success
}

int aes_cmac(const unsigned char *key, const unsigned char *message, size_t message_len, unsigned char *mac, size_t *mac_len)
{
    EVP_MAC *mac_algo = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (!mac_algo) {
        return -1; // Error fetching MAC algorithm
    }

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac_algo);
    if (!ctx) {
        EVP_MAC_free(mac_algo);
        return -1; // Error creating MAC context
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("cipher", "AES-256-CBC", 0),
        OSSL_PARAM_construct_end()
    };

    if (EVP_MAC_init(ctx, key, 32, params) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac_algo);
        return -1; // Error initializing MAC
    }

    if (EVP_MAC_update(ctx, message, message_len) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac_algo);
        return -1; // Error updating MAC
    }

    if (EVP_MAC_final(ctx, mac, mac_len, EVP_MAX_MD_SIZE) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac_algo);
        return -1; // Error finalizing MAC
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac_algo);
    return 0; // Success
}

int tlv_blob_init(ele_tlv_blob_t *blob)
{
    if (!blob) {
        return -1; // Error: null pointer
    }

    blob->data = NULL;
    blob->data_len = 0;
    return 0; // Success
}

void tlv_blob_free(ele_tlv_blob_t *blob)
{
    if (blob && blob->data) {
        free(blob->data);
        blob->data = NULL;
        blob->data_len = 0;
    }
}

/*
Length (length octet(s)):
DER involves the use definite form.
One or more octets can be used to encode this value:
    If value is less than or equal to 127 (0x7F) only one byte is used.
    Else, the first octet represent the number of octets used to encode the value
        (bit 8 must be set, bit 7 to 1 represent the number of octets used to encoded the length).
*/
static size_t encode_der_length(uint32_t length, uint8_t *out_buf) {
    if (length <= 127) {
        out_buf[0] = (uint8_t)length;
        return 1;
    } else {
        size_t num_bytes = 0;
        uint32_t temp = length;

        while (temp > 0) {
            temp >>= 8;
            num_bytes++;
        }

        out_buf[0] = 0x80 | num_bytes;
        for (int i = 0; i < num_bytes; i++) {
            out_buf[i + 1] = (length >> (8 * (num_bytes - 1 - i))) & 0xFF;
        }

        return num_bytes + 1;
    }
}

int tlv_blob_append(ele_tlv_blob_t *blob, uint8_t tag, uint32_t length, void *data)
{
    if (!blob || !data || length == 0) {
        return -1; // Error: invalid parameters
    }

    uint8_t temp[10] = {0,};
    size_t length_len = encode_der_length(length, temp);

    // tag, length, data
    // length might be variable
    size_t new_data_len = blob->data_len + 1 + length_len + length;
    uint8_t *new_data = realloc(blob->data, new_data_len);
    if (!new_data) {
        return -1; // Memory allocation error
    }

    blob->data = new_data;
    blob->data[blob->data_len] = tag; // Set tag
    memcpy(blob->data + blob->data_len + 1, temp, length_len);
    memcpy(blob->data + blob->data_len + 1 + length_len, data, length); // Copy data

    blob->data_len = new_data_len;
    return 0; // Success
}

static uint8_t num[4] = {0, 0, 0, 0};
static uint8_t *number2arry(uint32_t number, uint8_t size)
{
    if(size < 1 || size > 4) {
        fprintf(stderr, "Invalid size for number2arry: %d\n", size);
        return NULL; // Invalid size
    }
    num[0] = (number >> 24) & 0xFF;
    num[1] = (number >> 16) & 0xFF;
    num[2] = (number >> 8) & 0xFF;
    num[3] = number & 0xFF;

    return &num[4 - size]; // Return pointer to the start of the array
}

int assemble_tlv_blob(ele_tlv_blob_t *blob, op_generate_key_args_t *key_import_args, uint8_t *oem_key_warp, size_t oem_key_warp_len,
                    ele_importkey_wrap_algo_t wrap_algo, uint8_t *iv)
{
    if (!blob || !key_import_args || !oem_key_warp || oem_key_warp_len == 0) {
        return -1; // Error: null pointer
    }

    CHECK_CALL(tlv_blob_append, blob, 0x40, 21, "edgelockenclaveimport");
    CHECK_CALL(tlv_blob_append, blob, 0x41, 4, number2arry(0,4));
    CHECK_CALL(tlv_blob_append, blob, 0x42, 4, number2arry(key_import_args->permitted_algo,4));
    CHECK_CALL(tlv_blob_append, blob, 0x43, 4, number2arry(key_import_args->key_usage,4));
    CHECK_CALL(tlv_blob_append, blob, 0x44, 2, number2arry(key_import_args->key_type,2));
    CHECK_CALL(tlv_blob_append, blob, 0x45, 4, number2arry(key_import_args->bit_key_sz,4));
    CHECK_CALL(tlv_blob_append, blob, 0x46, 4, number2arry(key_import_args->key_lifetime,4));
    CHECK_CALL(tlv_blob_append, blob, 0x47, 4, number2arry(key_import_args->key_lifecycle,4));

    CHECK_CALL(tlv_blob_append, blob, 0x50, 4, number2arry(OEM_IMPORT_MK_SK_ID,4));
    CHECK_CALL(tlv_blob_append, blob, 0x51, 4, number2arry(wrap_algo,4));
    if(wrap_algo == IMPORT_ALGO_AES_CBC) {
        CHECK_CALL(tlv_blob_append, blob, 0x52, 16, iv);
    }else if(wrap_algo == IMPORT_ALGO_NONE) {
        return -1;
    }
    CHECK_CALL(tlv_blob_append, blob, 0x54, 4, number2arry(HSM_ELE_IMPORT_SIGN_ALGO_CMAC,4));
    CHECK_CALL(tlv_blob_append, blob, 0x55, oem_key_warp_len, oem_key_warp);

    return 0; // Success
}