// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    secureota.c
 *
 * @brief   Demo Application. This should be ONLY used for testing.
 */

/* Standard includes */
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>

/* OpenSSL */
#include <openssl/sha.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <openssl/pem.h>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>


/* Local includes */
#include <ota_ca.h>
#include "kb_test.h"

#define STATUS_SUCCESS 0
#define STATUS_ERROR -1
#define SHA256_DIGEST_LENGTH 32
#define KEY_SIZE 256
#define MAX_KEY_PEM_SIZE 4096
#define SIGNATURE_SIZE 64
#define MPMR_SIZE 32

#define B_FORMAT_TEXT   0x8000
#define FORMAT_PEM     (5 | B_FORMAT_TEXT)

#ifdef DEBUG
#define dbg(args...) do { fprintf(stderr, args); fflush(stderr); } while (0)
#else
#define dbg(args...)
#endif

/* Prototypes */
static int save_file(const char *key_path, const char *key);

/**
 * @brief   Retrieve key and store it to a file
 *
 * @param[in]  to_path  Path to where the key will be stored
 * @param[in]  get_fn   Function retrieving the key
 * @retval 0 if successful, other value if error.
 */

char* concat(const char *s1, const char *s2)
{
    char *result = malloc(strlen(s1) + strlen(s2) + 1);
    if (!result) {
        fprintf(stderr, "malloc() failed: insufficient memory!\n");
        return NULL;
    }
	strcpy(result, s1);
    strcat(result, s2);
    return result;
}

static int store_key(const char *to_path, char* (*get_fn)())
{
	char *out_key = NULL;
	int ret = STATUS_SUCCESS;
	char *blob_file = NULL;
	int ret_c;


	/* Check input */
	if (!to_path || !get_fn)
		return STATUS_ERROR;

	/* Apply key retrieving function */
	out_key = get_fn();
	if (out_key == NULL) {
		fprintf(stderr, "Failed to retrieve key\n");
		ret = STATUS_ERROR;
		goto out;
	}

	/* Save the retrieved key to file */
	if (save_file(to_path, out_key) != 0) {
		fprintf(stderr, "Error storing key\n");
		ret = STATUS_ERROR;
		goto out;
	}

	blob_file = concat(to_path, "blob");
	if (blob_file == NULL) {
		fprintf(stderr, "Failed to concatenate blob file name\n");
		ret = STATUS_ERROR;
		goto out;
	}	
	ret_c = kb_encap_test("red", to_path, blob_file);
	if (ret_c == -1){
		fprintf(stderr, "Error generating blob.\n");
		ret = STATUS_ERROR;
		goto out;	
	}
	if (remove(to_path) != 0)
		fprintf(stderr, "Error deleting mp pem file. Please verify.\n");

	/* Clean */	
out:
	if (out_key)
		free(out_key);
	if(blob_file)
		free(blob_file);
	return ret;
}

/**
 * @brief   Write PEM to file
 *
 * @param[in]  file_path  Path to file to write
 * @param[in]  file_content   Content to write
 * @retval 0 if successful, other value if error.
 */
static int save_file(const char *file_path, const char *file_content)
{
	FILE *fpout = NULL;
	int ret = STATUS_SUCCESS;

	/* Check input */
	if (!file_path || !file_content)
		return STATUS_ERROR;

	fpout = fopen(file_path, "w");
	if (!fpout) {
		fprintf(stderr, "Error Opening file\n");
		ret = STATUS_ERROR;
		goto out;
	}
	fwrite(file_content, sizeof(char), strlen(file_content), fpout);
	if (ferror(fpout) != 0) {
		fprintf(stderr, "Error Writing file\n");
		ret = STATUS_ERROR;
	}

out:
	if (fpout)
		fclose(fpout);
	return ret;
}

/**
 * Hexstring to Byte array.
 * @param[in/out] bmsg is the output byte array buffer
 * @param[in] msg that will be converted to byte array
 * @param[in] msg_len is the lenght of the message to be cnverted
**/
void hexstr2btyearray(uint8_t *bmsg, const char *msg_str, int msg_len){

    int i = 0;
    int bmsg_len;
    bmsg_len = msg_len/2;

    for (i = 0; i < bmsg_len; i++) {
        sscanf(msg_str + 2*i, "%02X", &bmsg[i]);
    }
}

/**
 * Print byte array.
 * @param[in] message to print
 * @param[in] msg_len is the lenght of the message to print
**/
void printuint8(uint8_t *message, uint32_t len)
{
	int i;
	for (i = 0; i < len; i++)
		fprintf(stderr, "%02X ", message[i]); 
}

/**
 * SHA256 Helper functions
 * 
 **/
void bbp_sha256(uint8_t *digest, const uint8_t *message, size_t len) {

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, message, len);
    SHA256_Final(digest, &ctx);

    // printf("Message digest:\nSHA-256: ");
    // for ( i = 0 ; i < 32 ; i++) {
    //     printf("%02X", digest[i]);
    // }
    // printf("\n");
}

/**
 * @brief   Load key in pem format and convert it to EC_KEY*.
 *
 * @param[in]  key_path  Path to key to convert
 * @param[out] publickey Return 
 * @retval 0 if successful, other value if error.
 */
EC_KEY* load_pubkey(const char *key_path)
{
    FILE *fp;

    EC_KEY *publickey = NULL;
    EVP_PKEY *evp_verify_key;
    // load in the keys
    fp = fopen(key_path, "r");
    if (!fp) {
        return NULL;
    }

	evp_verify_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    if (!evp_verify_key)
    {
        fprintf(stderr, "PEM_read_EC_PUBKEY error");
        goto out;
        return NULL;
    }

    publickey = EVP_PKEY_get1_EC_KEY(evp_verify_key);
    if (!publickey) {
        fprintf(stderr, "EVP_PKEY_get1_EC_KEY error");
        goto out;
        return NULL;
    }
out:
	if (fp)
		fclose(fp);
    return publickey;
}

/**
 * @brief   Create a EC signature structure, from given C and d
 *
 * @param[in]  c_str  first part (32 bytes) of the signature
 * @param[in]  d_str  last part (32 bytes) of the signature
 * @param[out] signature  ECDSA_SIG signature buffer
 * @retval 0 if successful, other value if error.
 */
void construct_signature(ECDSA_SIG *signature, char *c_str, char *d_str){
    BIGNUM c, *c_ptr;
    BIGNUM d, *d_ptr;

    BN_init(&c);
    c_ptr = &c;
    BN_hex2bn(&c_ptr, c_str);
    *signature->r = c;

    BN_init(&d);
    d_ptr = &d;
    BN_hex2bn(&d_ptr, d_str);
    *signature->s = d;

    // fprintf(stdout,"Signature:\n");
    // fprintf(stdout, "C: %s\n", BN_bn2hex(signature->r));
    // fprintf(stdout, "d: %s\n", BN_bn2hex(signature->s));
}

/**
 * @brief   Sign a message using MP private key
 *
 * @param[in]  msg  Message to sign
 * @param[in]  to_path  Path to store signature in der format
 * @param[out]  sig Signature buffer
 * @retval 0 if successful, other value if error.
 */
static int sign_with_mpprivk(const char *msg, const char *to_path)
{

	FILE* fpout = NULL;
	uint8_t *signat = NULL;
	uint8_t *mpmr = NULL;
	uint8_t *bmsg = NULL;
	uint8_t dgst[64] = {0};
	uint8_t *mes_rep = NULL;
	uint8_t one[32], two[32];
	uint8_t *derSig = NULL;
	uint8_t *pp = NULL;
	char *r_str = NULL, *s_str = NULL;
	int mes_rep_len;
	int msg_len;
	int bmsg_len;
	int ret = STATUS_SUCCESS;
	ECDSA_SIG *sig_new = NULL;
	int sigSize = 0;
	int k;

	/* Check input */
	if (!msg || !to_path || strlen(msg) > 50){
		fprintf(stderr, "Incorrect parameters\n");
		ret = STATUS_ERROR;
		goto out;
	}

	signat = (uint8_t *) malloc(64);
	if (!signat) {
		ret = STATUS_ERROR;
		goto out;
	}
	
	mpmr = (uint8_t *) malloc(32);
	if (!mpmr) {
		ret = STATUS_ERROR;
		goto out;
	}

	msg_len = strlen(msg);
	bmsg_len = msg_len/2;
	bmsg = (uint8_t *) malloc(bmsg_len);
	if (!bmsg) {
		ret = STATUS_ERROR;
		goto out;
	}
 	
	/* OpenSSL works with byte arrays */
    hexstr2btyearray(bmsg, msg, msg_len);

	if (ota_GenMPPRivSignature(bmsg, bmsg_len, signat, SIGNATURE_SIZE, mpmr, MPMR_SIZE) != 0) {
		fprintf(stderr, "Failed to sign using mp priv key\n");
		ret = STATUS_ERROR;
		goto out;
	}

	/* Construct mes-rep */
    mes_rep_len = 32 + bmsg_len; //sizeof(mpmr) + bmsg_len;
    mes_rep = malloc(mes_rep_len);

    if (mes_rep == NULL){
        printf("Error: cannot allocate memory\n");
		ret = STATUS_ERROR;
		goto out;
    }

    memcpy(mes_rep, (uint8_t *)mpmr, 32);
    memcpy(mes_rep + 32, (uint8_t *)bmsg, bmsg_len);

    /* Generate Message Digest for mes-rep */
    bbp_sha256(dgst, mes_rep, mes_rep_len);

	/* Split signatue buffer in ecdsa r and s */
    memcpy(one, signat, 32 * sizeof(uint8_t)); 
	memcpy(two, &signat[32], 32 * sizeof(uint8_t));
    
    r_str = (char*)calloc(2 * 32 + 1, sizeof(char));
    s_str = (char*)calloc(2 * 32 + 1, sizeof(char));

    for (k = 0; k < 32; k++)
    {
        sprintf(&r_str[2 * k],"%02X", one[k]); 
        sprintf(&s_str[2 * k],"%02X", two[k]);
    }

	sig_new = ECDSA_SIG_new();
    construct_signature(sig_new, r_str, s_str);
    if(!sig_new){
		ret = STATUS_ERROR;
		goto out;
    }

	sigSize = i2d_ECDSA_SIG(sig_new, NULL);
    derSig = (uint8_t*)malloc(sigSize);
    pp = derSig;    
    sigSize= i2d_ECDSA_SIG(sig_new, &pp);

	fpout = fopen(to_path, "w");
	if (!fpout) {
		fprintf(stderr, "Error Opening file\n");
		ret = STATUS_ERROR;
		goto out;
	}

    fwrite(derSig, 1, sigSize, fpout);
    fprintf(stderr, "sigSize before out %d - %d\n", sigSize, ret);
out:
    if(bmsg){
    	free(bmsg);
    }
    if(mes_rep){
    	free(mes_rep);
    }
    if(r_str){
    	free(r_str);
    }
    if(s_str){
    	free(s_str);
    }
	if(fpout){
		fclose(fpout);
	}
    if(derSig){
    	free(derSig);
    }
    if(ret == STATUS_SUCCESS)
    	return sigSize;
    return STATUS_ERROR;
}

/**
 * @brief   Main function.
 *
 * @param[in]  argc     Number of arguments
 * @param[in]  argv     Arguments vector
 */
int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <cmd>\n"
			"signmpprivk  : Sign message using the Manufacturing Protection Private key\n"
			"mppubk  	  : Get the Manufacturing Protection Publick key\n",
				argv[0]);
		return STATUS_ERROR;
	}

	if (strcmp(argv[1], "signmpprivk") == 0) {
		// printf("Sign with manufacturing  protection private key\n");
		if (argc < 4) {
			fprintf(
					stderr,
					"Usage %s %s %s <string - max 30 characters> </path/to/output/dersignature>\n",
					argv[0], argv[1], argv[2]);
			return STATUS_ERROR;
		}
		int ret_c = sign_with_mpprivk(argv[2], argv[3]);
		printf("%d", ret_c);
		return ret_c;
	}else if (strcmp(argv[1], "mppubk") == 0) {
		printf("Generate MP public key\n");
		if (argc < 3) {
			fprintf(stderr, "Usage %s %s </path/to/output/key>\n",
					argv[0], argv[1]);
			return STATUS_ERROR;
		}
		return store_key(argv[2], ota_GetMPPubkey);
	}else if (strcmp(argv[1], "decapblob") == 0) {
		printf("Decapsulate MP public key blob\n");
		if (argc < 4) {
			fprintf(stderr, "Usage %s %s %s </path/to/input/blob> </path/to/output/key>\n",
					argv[0], argv[1], argv[2]);
			return STATUS_ERROR;
		}
		return kb_decap_test("red", argv[2], argv[3]);
	}
	fprintf(stderr, "Unknown command\n");
	return STATUS_ERROR;
}

