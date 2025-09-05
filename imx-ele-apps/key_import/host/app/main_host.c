// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "nxp_prod_ka_pub.h"
#include "file_op.h"
#include "debug.h"
#include "ecdh.h"
#include "hkdf.h"
#include "key_import.h"

/*
On host side, do the following:
1. Sign the raw payload and send it to the device. Done by CST or SPSDK.
2. Do ECDH with the NXP_PROD_KA_PUB raw public key, and get the shared secret.
3. Derive the OEM_Import_MK_SK, OEM_Import_Wrap_SK and CMAC_SK from the shared secret.
4. Get the OEM key from the key file, which will be imported to the ELE.
5. Do AES_Warp on the OEM key with the OEM_Import_Wrap_SK.
6. Create a TLV blob with the wrapped OEM key.
7. Calculate the CMAC of the TLV blob with the OEM_Import_CMAC_SK.
8. Append the CMAC to the TLV blob.
9. Send the TLV blob to the device.
 */

static void my_free(void *ptr)
{
    if (ptr) {
        free(ptr);
        ptr = NULL;
    }
}

void print_usage(const char *progname)
{
    printf("Usage: %s <nxp_prod_ka_puk> <oem_p256_private_key> <oem_key> <tlv_blob>\n", progname);
    printf("Params:\n");
    printf("  nxp_prod_ka_puk          The raw binary file which stores the NXP_PROD_KA_PUK, including 0x4 header\n");
    printf("  oem_p256_private_key     The P256 private pem file which is used for ECDH\n");
    printf("  oem_key                  The OEM key to be imported to the ELE\n");
    printf("  tlv_blob                 The output TLV blob file containing OEM key\n");
    printf("  [oem_key type note:]\n");
    printf("          Current supported keys:\n");
    printf("            AES 128/192/256 key in raw binary file\n");
    printf("            SECP R1 NIST 256/384 key in pem format file\n");
}

int main(int argc, char *argv[])
{
    printf("Hello, World! %s:%s %s\n", __DATE__, __TIME__, GITVERSION);
    if (argc < 5) {
        print_usage(argv[0]);
        return -1;
    }

    char *nxp_prod_ka_puk_file = argv[1];
    char *oem_p256_private_key_file = argv[2];
    char *oem_key_file = argv[3];
    char *tlv_blob_file = argv[4];

    uint8_t* nxp_prod_ka_puk = NULL;
    size_t nxp_prod_ka_puk_len = 0;
    uint8_t *shared_secret = NULL;
    size_t shared_secret_len = 0;
    uint8_t oem_import_mk_sk[32] = {0};
    uint8_t oem_import_warp_sk[32] = {0};
    uint8_t oem_import_warp_sk_info[] = "oemelefwkeyimportwrap256";
    uint8_t oem_import_cmac_sk[32] = {0};
    uint8_t oem_import_cmac_sk_info[] = "oemelefwkeyimportcmac256";

    ele_importkey_wrap_algo_t wrap_algo = IMPORT_ALGO_NONE;
    uint8_t aes_cbc_iv[16] = {0}; // IV is all zero for AES-CBC key wrap
    int oem_key_warp_len = 0;
    uint8_t *oem_key_warp = NULL;
    size_t oem_key_cmac_len = 16; // CMAC output length is fixed at 16 bytes
    uint8_t oem_key_cmac[16] = {0};
    ele_tlv_blob_t blob={.data = NULL, .data_len = 0};
    uint8_t *tmp_tlv_blob_for_cmac = NULL;

    import_key_prop_t import_key_prop = {0};

    int ret = 0;

    ret = read_from_file(nxp_prod_ka_puk_file, &nxp_prod_ka_puk, &nxp_prod_ka_puk_len);
    if (ret || nxp_prod_ka_puk_len != (PROD_KA_PUB_LEN + 1)) {
        fprintf(stderr, "Failed to read NXP_PROD_KA_PUK from file %s: %d\n", nxp_prod_ka_puk_file, ret);
        goto out;
    }
    hex_dump("NXP_PROD_KA_PUK", nxp_prod_ka_puk, nxp_prod_ka_puk_len);

    ret = ecdh(oem_p256_private_key_file, nxp_prod_ka_puk, nxp_prod_ka_puk_len, &shared_secret, &shared_secret_len);
    if(ret) {
        fprintf(stderr, "ECDH failed: %d\n", ret);
        goto out;
    }
    hex_dump("shared secret", shared_secret, shared_secret_len);

    // derive the OEM Import MK SK from shared secret
    ret = hkdf(shared_secret, shared_secret_len, 
        NULL, 0, 
        oem_import_mk_sk, sizeof(oem_import_mk_sk));
    if(ret) {
        fprintf(stderr, "HKDF oem_import_mk_sk failed: %d\n", ret);
        goto out;
    }
    hex_dump("OEM Import MK SK", oem_import_mk_sk, sizeof(oem_import_mk_sk));

    // derive the OEM Import Wrap SK and CMAC SK from OEM Import MK SK
    ret = hkdf(oem_import_mk_sk, sizeof(oem_import_mk_sk), 
        oem_import_warp_sk_info, sizeof(oem_import_warp_sk_info)-1, 
        oem_import_warp_sk, sizeof(oem_import_warp_sk));
    if(ret) {
        fprintf(stderr, "HKDF oem_import_warp_sk failed: %d\n", ret);
        goto out;
    }
    hex_dump("oem_import_warp_sk", oem_import_warp_sk, sizeof(oem_import_warp_sk));

    ret = hkdf(oem_import_mk_sk, sizeof(oem_import_mk_sk), 
        oem_import_cmac_sk_info, sizeof(oem_import_cmac_sk_info)-1, 
        oem_import_cmac_sk, sizeof(oem_import_cmac_sk));
    if(ret) {
        fprintf(stderr, "HKDF oem_import_cmac_sk failed: %d\n", ret);
        goto out;
    }
    hex_dump("oem_import_cmac_sk", oem_import_cmac_sk, sizeof(oem_import_cmac_sk));

    // get the OEM key from the file, which will be imported to the ELE
    ret = get_oem_key(oem_key_file,  &import_key_prop);
    if (ret != 0) {
        fprintf(stderr, "Failed to get OEM key from file %s: %d\n", oem_key_file, ret);
        goto out;
    }
    print_key_prop(&import_key_prop);

    // if the OEM key length is not 8 bytes aligned
    // must use AES-CBC with ISO7816-4 padding
    if(import_key_prop.oem_key_len % 8 != 0) {
        printf("The OEM key length is not 8 bytes aligned, do ISO7816-4 padding\n");
        wrap_algo = IMPORT_ALGO_AES_CBC;
        ret = iso7816_4_padding(&import_key_prop.oem_key,&import_key_prop.oem_key_len,16);
        if(ret){
            fprintf(stderr, "iso7816_4_padding failed\n");
            goto out;
        }

        oem_key_warp_len = import_key_prop.oem_key_len;
        oem_key_warp = malloc(oem_key_warp_len);
        ret = aes_cbc_encrypt(import_key_prop.oem_key, import_key_prop.oem_key_len, oem_import_warp_sk, oem_key_warp, &oem_key_warp_len, aes_cbc_iv);
        if(ret) {
            fprintf(stderr, "AES-CBC encryption failed: %d\n", ret);
            goto out;
        }
    }else {
        wrap_algo = IMPORT_AGLO_RFC_3394;
        oem_key_warp_len = import_key_prop.oem_key_len + 8;  // 8 bytes for IV
        oem_key_warp = malloc(oem_key_warp_len);
        if (!oem_key_warp) {
            fprintf(stderr, "Failed to allocate memory for oem_key_warp.\n");
            ret = -1;
            goto out;
        }

        // use AES-WRAP to wrap the OEM key with oem_import_warp_sk
        ret = aes_warp(oem_import_warp_sk, import_key_prop.oem_key, import_key_prop.oem_key_len, oem_key_warp, &oem_key_warp_len);
        if (ret != 0) {
            fprintf(stderr, "AES-WRAP failed: %d\n", ret);
            goto out;
        }
    }
    hex_dump("OEM Key Wrapped", oem_key_warp, oem_key_warp_len);

    // Initialize the TLV blob
    ret = tlv_blob_init(&blob);
    if (ret != 0) {
        fprintf(stderr, "Failed to initialize TLV blob: %d\n", ret);
        goto out;
    }

    // Assemble the TLV blob with the key attribute, wrapped OEM key
    ret = assemble_tlv_blob(&blob, &import_key_prop.key_import_args, oem_key_warp, oem_key_warp_len, wrap_algo, aes_cbc_iv);
    if (ret != 0) {
        fprintf(stderr, "Failed to assemble TLV blob: %d\n", ret);
        goto out;
    }
    hex_dump("TLV blob", blob.data, blob.data_len);

    // Prepare for CMAC calculation. It contains the CMAC tag and length
    tmp_tlv_blob_for_cmac = malloc(blob.data_len + 2);
    if (!tmp_tlv_blob_for_cmac) {
        fprintf(stderr, "Failed to allocate memory for tmp_tlv_blob_for_cmac.\n");
        ret = -1;
        goto out;
    }

    memcpy(tmp_tlv_blob_for_cmac, blob.data, blob.data_len);
    tmp_tlv_blob_for_cmac[blob.data_len] = 0x5E; // Tag for CMAC
    tmp_tlv_blob_for_cmac[blob.data_len + 1] = 16; // Length for CMAC

    // Calculate the CMAC of the TLV blob
    ret = aes_cmac(oem_import_cmac_sk, tmp_tlv_blob_for_cmac, blob.data_len + 2, oem_key_cmac, &oem_key_cmac_len);
    if (ret != 0) {
        fprintf(stderr, "AES-CMAC on TLV blob failed: %d\n", ret);
        goto out;
    }
    hex_dump("TLV blob CMAC", oem_key_cmac, oem_key_cmac_len);

    // Append CMAC to the TLV blob
    if (tlv_blob_append(&blob, 0x5E, oem_key_cmac_len, oem_key_cmac) != 0) {
        fprintf(stderr, "Failed to append CMAC to TLV blob.\n");
        ret = -1;
        goto out;
    }
    hex_dump("TLV blob with CMAC", blob.data, blob.data_len);

    ret = write2file(tlv_blob_file, blob.data, blob.data_len);
    if (ret) {
        fprintf(stderr, "Failed to write tlv blob to file %s: %d\n", tlv_blob_file, ret);
        goto out;
    }

out:
    my_free(nxp_prod_ka_puk);
    my_free(shared_secret);
    my_free(oem_key_warp);
    my_free(tmp_tlv_blob_for_cmac);
    my_free(import_key_prop.oem_key);
    tlv_blob_free(&blob);
    return ret;
}