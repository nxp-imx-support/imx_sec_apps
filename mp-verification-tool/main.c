/*
 * Copyright 2021 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
/*
 * Know Answers
 * ------------------------------------------------------------------
 * Public Key: 040139C932F04525D083E15E3236DD1DCA625B2D0B14C13BA7FAA9
 * C50C16619CE0F4C207AA609E4AAE586DF7FEE72F829F3B59CBF49F8F34C34ECA39
 * EBD58E73CE
 * ------------------------------------------------------------------
 * msg: 7A5D4dA3
 * -------------------------------------------------------------------
 * C: E85E34E4BF56CAA32DA858C0279C50A7E64E1136A23E51BF7C04CDA56389EE56
 * -------------------------------------------------------------------
 * d: 4A3C7A3725E1F7DDE41396393C88136B019633ED7BB33B689B78B25E06D42538
 * -------------------------------------------------------------------
 *
 */
/*
 * OpenSSL naming for NIST complaint curves
 */
#define P192 "prime192v1"
#define P256 "prime256v1"
#define P384 "secp384r1"
#define P521 "secp521r1"

#define SUCCESS  1

uint8_t mpmr[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

/* Parameters */
char *msg_str;
char *pkey_str;
char *c_str;
char *d_str;

/* Global Variables */
uint8_t *bmsg;
int msg_len;
int bmsg_len;

/*
 * The MFG Private key are defaulted to P-256.
 * However, the hardware supports all the other curves.
 * Update this if support for other curves is required.
 */
char *curve = P256;
const int digest_len = 32;

/* ---------------------------------------------------------- *
 * Print Usage
 * ---------------------------------------------------------- */
void print_usage(){
    char *usage = "Usage: verify -m mesg -k pkey-c c_param -d "
                  "d_param -r mes-rep\n"
                  "Description:"
                  "\t-m message\n"
                  "\t\t-k public_key\n"
                  "\t\t-c first_part_digital_signature\n"
                  "\t\t-d second_part_digital_signature\n";
    printf("%s", usage);
}

/* ---------------------------------------------------------- *
 * Process command line arguments
 * ---------------------------------------------------------- */
void getArgs(int argc, char *argv[]){
    int opt;
    while ((opt = getopt(argc, argv,"m:k:c:d:r:")) != -1) {
        switch (opt) {
             case 'm' :
                msg_len = strlen(optarg);
                msg_str = malloc(msg_len);
                strcpy(msg_str, optarg);
                break;
             case 'k' :
                pkey_str = malloc(strlen(optarg));
                strcpy(pkey_str, optarg);
                break;
             case 'c' :
                c_str = malloc(strlen(optarg));
                strcpy(c_str, optarg);
                break;
             case 'd' :
                d_str = malloc(strlen(optarg));
                strcpy(d_str, optarg);
                break;
             default: print_usage();
                 exit(EXIT_FAILURE);
        }
    }

    if (msg_str == NULL || pkey_str == NULL || c_str == NULL
            || d_str == NULL){
        print_usage();
        exit(EXIT_FAILURE);
    }
}

/* ---------------------------------------------------------- *
 * Hexstring to Byte array
 * ---------------------------------------------------------- */
void hexstr2btyearray(){
    int i = 0;
    bmsg_len = msg_len/2;
    bmsg = malloc(bmsg_len);

    for (i = 0; i < bmsg_len; i++) {
      sscanf(msg_str + 2*i, "%02x", (unsigned int *)&bmsg[i]);
    }
}

/* ---------------------------------------------------------- *
 * These function calls initialize openssl for correct work.  *
 * ---------------------------------------------------------- */
void setup_openssl(){
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
}

int setup_ecc_pubkey(EC_KEY *ecc_params, EC_POINT *pub_key,
                     const EC_GROUP *group) {
    int ret = 0;

    pub_key = EC_POINT_new(group);
    EC_POINT_hex2point(group, pkey_str, pub_key, NULL);
    EC_KEY_set_public_key(ecc_params, pub_key);

    ret = EC_KEY_check_key(ecc_params);

    printf("\nPublic Key: %s\n", pkey_str);
    if (ret)
        printf("Public key verified\n");
    else
        printf("Public Key Invalid: %s\n",
                ERR_error_string(ERR_get_error(),NULL));
    printf("\n");

    return ret;
}

/* ---------------------------------------------------------- *
 * SHA256 Helper functions                                    *
 * ---------------------------------------------------------- */
void bbp_sha256(uint8_t *digest, const uint8_t *message, size_t len) {
    int i = 0;

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, message, len);
    SHA256_Final(digest, &ctx);

    printf("Message digest:\nSHA-256: ");
    for ( i = 0 ; i < sizeof(digest) ; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

/* ---------------------------------------------------------- *
 * Create a EC signature structure, from given C and d        *
 * ---------------------------------------------------------- */
void construct_signature(ECDSA_SIG *signature){
    BIGNUM *c;
    BIGNUM *d;

    c = BN_new();
    BN_hex2bn(&c, c_str);
    
    d = BN_new();
    BN_hex2bn(&d, d_str);

    ECDSA_SIG_set0(signature, c, d);
    
    printf("Signature:\n");
    printf("c: %s\n", BN_bn2hex(c));
    printf("d: %s\n", BN_bn2hex(d));
    printf("\n");
}

/* ---------------------------------------------------------- *
 * Main code                                                  *
 * ---------------------------------------------------------- */
int main(int argc, char *argv[]) {
    /* Get command line arguments */
    getArgs(argc, argv);

    int i = 0;
    uint8_t dgst[digest_len];
    uint8_t *mes_rep;
    int mes_rep_len;

    /* OpenSSL ECC variables*/
    BIO             *outbio = NULL;
    EC_KEY          *ecc_params  = NULL;
    EVP_PKEY        *pkey   = NULL;
    int             eccgrp;
    EC_POINT        *pub_key;
    const EC_GROUP  *group;
    ECDSA_SIG *signature = NULL;

    /* Setup and Initialization of OpenSSL's engine */
    setup_openssl();
    eccgrp = OBJ_txt2nid(curve);
    ecc_params = EC_KEY_new_by_curve_name(eccgrp);
    group = EC_KEY_get0_group(ecc_params);

    /* Verification of public key */
    if(setup_ecc_pubkey(ecc_params, pub_key, group) != SUCCESS){
        exit(EXIT_FAILURE);
    }

    /* OpenSSL works with byte arrays */
    hexstr2btyearray();

    /* Construct mes-rep */
    mes_rep_len = sizeof(mpmr) + bmsg_len;
    mes_rep = malloc(mes_rep_len);
    if (mes_rep == NULL){
        printf("Error: cannot allocate memory\n");
        exit(EXIT_FAILURE);
    }
    memcpy(mes_rep, (uint8_t *)mpmr, sizeof(mpmr));
    memcpy(mes_rep + sizeof(mpmr), (uint8_t *)bmsg, bmsg_len);

    /* Generate Message Digest for mes-rep */
    bbp_sha256(dgst, mes_rep, mes_rep_len);

    /* Construct Signature Strucrture */
    signature = ECDSA_SIG_new();
    construct_signature(signature);

    /* Verify ECDSA signature */
    if (ECDSA_do_verify(dgst, digest_len, signature, ecc_params)) {
        printf("EC Signature: Verified\n");
    } else {
        printf("EC Signature: Invalid\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}

