// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    castauth.c
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

/* OpenSSL */
#include <openssl/sha.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

/* Local includes */
#include <imx_cast_auth_ca.h>

#define MAX_KEY_PEM_SIZE 4096
#define STATUS_SUCCESS 0
#define STATUS_ERROR -1
#define SHA256_DIGEST_LENGTH 32
#define KEY_SIZE 256

#ifdef DEBUG
#define dbg(args...) do { fprintf(stderr, args); fflush(stderr); } while (0)
#else
#define dbg(args...)
#endif

const unsigned char SHA256_HASH_PREFIX[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
		0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
		0x00, 0x04, 0x20};

const unsigned char SHA1_HASH_PREFIX[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05,
		0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14};

unsigned char CERT_TEMPLATE[] = {0x30, 0x82, 0x03, 0xcd, 0x30, 0x82, 0x02,
		0xb5, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x3c, 0x43,
		0x45, 0x52, 0x54, 0x20, 0x53, 0x45, 0x52, 0x49, 0x41, 0x4c,
		0x20, 0x4e, 0x55, 0x4d, 0x42, 0x45, 0x52, 0x3e, 0x30, 0x0d,
		0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
		0x0b, 0x05, 0x00, 0x30, 0x81, 0x83, 0x31, 0x0b, 0x30, 0x09,
		0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
		0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a,
		0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61,
		0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c,
		0x0d, 0x4d, 0x6f, 0x75, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x20,
		0x56, 0x69, 0x65, 0x77, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03,
		0x55, 0x04, 0x0a, 0x0c, 0x08, 0x54, 0x65, 0x73, 0x74, 0x20,
		0x4f, 0x45, 0x4d, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55,
		0x04, 0x0b, 0x0c, 0x04, 0x43, 0x61, 0x73, 0x74, 0x31, 0x25,
		0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1c, 0x54,
		0x65, 0x73, 0x74, 0x20, 0x4f, 0x45, 0x4d, 0x20, 0x41, 0x73,
		0x73, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x20, 0x52, 0x65,
		0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x30, 0x1e, 0x17,
		0x0d, 0x31, 0x39, 0x30, 0x31, 0x32, 0x31, 0x30, 0x31, 0x35,
		0x33, 0x32, 0x34, 0x5a, 0x17, 0x0d, 0x31, 0x39, 0x30, 0x36,
		0x30, 0x32, 0x30, 0x31, 0x35, 0x33, 0x32, 0x34, 0x5a, 0x30,
		0x31, 0x31, 0x2f, 0x30, 0x2d, 0x06, 0x03, 0x55, 0x04, 0x03,
		0x0c, 0x26, 0x3c, 0x55, 0x4e, 0x49, 0x51, 0x55, 0x45, 0x20,
		0x48, 0x41, 0x52, 0x44, 0x57, 0x41, 0x52, 0x45, 0x20, 0x49,
		0x44, 0x3e, 0x20, 0x41, 0x41, 0x3a, 0x42, 0x42, 0x3a, 0x43,
		0x43, 0x3a, 0x44, 0x44, 0x3a, 0x45, 0x45, 0x3a, 0x46, 0x46,
		0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
		0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03,
		0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82,
		0x01, 0x01, 0x00, 0xd5, 0x96, 0x0d, 0x7e, 0xa7, 0x91, 0x70,
		0x0e, 0xe9, 0xf6, 0x4c, 0xb1, 0x7b, 0x91, 0xe6, 0x6f, 0x47,
		0xa3, 0xe8, 0xa7, 0x9c, 0xac, 0x05, 0xea, 0x39, 0x3b, 0x9c,
		0x35, 0xd4, 0xa4, 0x92, 0x5a, 0xe4, 0x1c, 0x03, 0xa1, 0x52,
		0x70, 0xf8, 0x68, 0xb3, 0x99, 0x70, 0x4f, 0x9f, 0x7b, 0x36,
		0x7c, 0x86, 0x25, 0x94, 0xc4, 0x9e, 0x12, 0x1f, 0x66, 0xfe,
		0x1b, 0x26, 0xb3, 0x73, 0x05, 0x64, 0xab, 0x8a, 0x62, 0xea,
		0xc1, 0x0b, 0xb0, 0x9e, 0xfb, 0x3a, 0x4b, 0x2e, 0x81, 0x6f,
		0x4d, 0xce, 0x7b, 0xc8, 0x08, 0x84, 0xd0, 0x03, 0x08, 0xab,
		0xdd, 0x1d, 0xf2, 0x65, 0x05, 0x89, 0xf0, 0x7f, 0x9b, 0x05,
		0x16, 0xf5, 0x2a, 0x0b, 0xc5, 0x53, 0x43, 0x9d, 0x35, 0xe1,
		0x59, 0x7a, 0xaf, 0x17, 0x5e, 0xe7, 0x95, 0xbf, 0x65, 0x8d,
		0x26, 0x1d, 0x93, 0x59, 0x0a, 0xdb, 0xaa, 0x6b, 0x8c, 0xd2,
		0xea, 0xba, 0x54, 0xb3, 0x7e, 0x77, 0x7f, 0x5a, 0xce, 0x6b,
		0xa8, 0x5a, 0x43, 0x66, 0x0e, 0x6e, 0x18, 0x43, 0x60, 0x0a,
		0x58, 0x15, 0xb7, 0xee, 0xc7, 0x12, 0x91, 0x6c, 0x23, 0xd4,
		0xa9, 0xab, 0xe9, 0xc2, 0xf9, 0x3b, 0x45, 0xd8, 0x79, 0x9a,
		0x7b, 0xed, 0xa5, 0xd7, 0x86, 0xa9, 0x6c, 0x07, 0x1e, 0x7d,
		0xfe, 0xa6, 0x9a, 0xa7, 0xbe, 0xc8, 0x16, 0xe5, 0xa9, 0xb3,
		0xa1, 0x6e, 0x8f, 0xad, 0x74, 0xb8, 0x75, 0x30, 0x76, 0x90,
		0x04, 0x89, 0x48, 0x17, 0x8b, 0xd7, 0x50, 0xf1, 0xb8, 0xba,
		0xce, 0x3a, 0x07, 0x73, 0x86, 0x29, 0x4d, 0x58, 0x6f, 0x78,
		0xb8, 0xed, 0x44, 0xc5, 0xf0, 0x74, 0x15, 0xb3, 0x79, 0xe1,
		0xf5, 0xae, 0x78, 0x31, 0xcf, 0x61, 0x1e, 0x44, 0xa3, 0x22,
		0xb8, 0x87, 0x8c, 0x1c, 0x66, 0x99, 0x9c, 0x93, 0x1d, 0x41,
		0x87, 0xfa, 0xd2, 0x49, 0x73, 0xcb, 0x55, 0x0d, 0x1d, 0x02,
		0x03, 0x01, 0x00, 0x01, 0xa3, 0x81, 0x89, 0x30, 0x81, 0x86,
		0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30,
		0x00, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16,
		0x04, 0x14, 0x4d, 0x3c, 0x82, 0xf5, 0x2f, 0x39, 0x95, 0xaf,
		0x03, 0xe4, 0x96, 0x51, 0x43, 0x62, 0x7d, 0x5d, 0x7a, 0x60,
		0xa1, 0x20, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04,
		0x18, 0x30, 0x16, 0x80, 0x14, 0x85, 0xe5, 0x48, 0x32, 0x9e,
		0x57, 0xb1, 0xde, 0x0a, 0xfb, 0x49, 0xc6, 0xa1, 0x21, 0xdc,
		0xd2, 0xe5, 0x0a, 0x81, 0x67, 0x30, 0x0b, 0x06, 0x03, 0x55,
		0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x13,
		0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06,
		0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x30,
		0x17, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x10, 0x30, 0x0e,
		0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6,
		0x79, 0x02, 0x05, 0x02, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
		0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03,
		0x82, 0x01, 0x01, 0x00, 0xb6, 0x24, 0x95, 0x92, 0x65, 0x83,
		0xcb, 0x97, 0x6a, 0x0c, 0xa1, 0xe5, 0xcd, 0x15, 0x0b, 0xc8,
		0x20, 0xa4, 0x62, 0x1d, 0xe5, 0xbc, 0xb6, 0x51, 0x18, 0x6a,
		0x31, 0x21, 0x39, 0xdb, 0x6b, 0xf3, 0x69, 0x32, 0x43, 0x80,
		0xde, 0xff, 0x23, 0x72, 0x67, 0x99, 0x60, 0xbc, 0xcd, 0xb0,
		0xdf, 0xb4, 0xde, 0x8c, 0x9d, 0xc1, 0x08, 0x8a, 0x94, 0xbd,
		0x02, 0x95, 0x86, 0x1d, 0x15, 0x88, 0xe9, 0x60, 0x06, 0x07,
		0xe4, 0x4f, 0xd8, 0xc6, 0x76, 0xf9, 0xb7, 0xf0, 0x2c, 0xdc,
		0xe4, 0x1d, 0xa6, 0x63, 0x55, 0x82, 0x0c, 0xf2, 0x68, 0x84,
		0x7f, 0x1f, 0x25, 0x3c, 0x9d, 0xe7, 0x15, 0x39, 0x2b, 0x87,
		0xd7, 0x87, 0x93, 0xa5, 0xb1, 0x53, 0x60, 0x88, 0x09, 0x9b,
		0x89, 0x3a, 0x1b, 0xf2, 0xd8, 0x84, 0xeb, 0x0e, 0xd1, 0x3a,
		0x2e, 0xbd, 0xd8, 0x7d, 0x0b, 0x1a, 0x48, 0xaa, 0x80, 0xcf,
		0x75, 0x72, 0x5d, 0xc8, 0x77, 0x97, 0xfa, 0xe6, 0x46, 0xf1,
		0xea, 0x3b, 0x2b, 0x61, 0x06, 0x07, 0x15, 0x7f, 0x35, 0xd3,
		0x1c, 0xfb, 0x33, 0x33, 0x83, 0x00, 0x4e, 0xbb, 0x90, 0xf3,
		0x4a, 0x74, 0xd2, 0xa8, 0x80, 0x85, 0xdd, 0x05, 0x06, 0xc8,
		0xe0, 0xc9, 0x6c, 0xeb, 0x05, 0x4a, 0x20, 0xbe, 0x93, 0x38,
		0x63, 0x86, 0xae, 0x40, 0xee, 0x90, 0x7a, 0x55, 0xef, 0x7d,
		0x08, 0x5c, 0x26, 0xc2, 0x5b, 0xdc, 0xa1, 0x01, 0x28, 0xd1,
		0xe8, 0xe9, 0xba, 0xd7, 0xb7, 0x40, 0xe2, 0x1c, 0x5a, 0xc6,
		0xb8, 0x3f, 0xc7, 0x58, 0x33, 0x19, 0x21, 0x61, 0x94, 0x57,
		0x70, 0xfb, 0xf6, 0x96, 0x93, 0x59, 0x4c, 0x65, 0xb4, 0xf4,
		0x24, 0x9d, 0xff, 0x75, 0x73, 0x98, 0x9f, 0x72, 0xc2, 0x82,
		0x71, 0x38, 0x86, 0x96, 0xff, 0x16, 0x81, 0x60, 0xbe, 0x2c,
		0xd5, 0xa9, 0x9d, 0xc2, 0x94, 0xac, 0x66, 0xd4, 0xeb, 0x4b, };

/* Prototypes */
static EVP_PKEY *read_rsa_private_key(const char *key_path);
static int save_file(const char *key_path, const char *key);
static int verify(const EVP_PKEY *pkey, const char *msg,
		const unsigned char *sig, uint32_t slen);
static EVP_PKEY *read_cert_pubkey(const char *cert_path);
static int verify_cert(const char *msg, const char *cert_path,
		const char *key_path);
static int sign_plain(EVP_PKEY *key, const char *msg, uint32_t msg_len,
		uint8_t *sig, uint32_t *sig_len);
static int sign_hash(const char *msg, const char *pkey_path,
		const char *bkey_path);
static EVP_PKEY *read_rsa_private_key(const char *key_path);
static int conv_key(const char *from_path, const char *to_path,
		char* (*conv_fn)(const char *));
static char *read_file(const char *file_path);
static int sign_with_black_key(const char *msg, const char *bkey_path,
		uint8_t **sig, uint32_t *sig_len);

/**
 * @brief   Verify signature using public key
 *
 * @param[in]  pkey  Public key
 * @param[in]  msg   Message
 * @param[in]  sig  Signature
 * @param[in]  sig_len  Signature length
 * @retval 0 if successful, other value if error.
 */
static int verify(const EVP_PKEY *pkey, const char *msg,
		const unsigned char *sig, uint32_t sig_len)
{
	/* Returned to caller */
	int result = STATUS_ERROR;
	EVP_MD_CTX *ctx = NULL;
	EVP_MD *md = NULL;
	int rc;

	if (!msg || !sig || !sig_len || !pkey) {
		dbg("NULL parameter");
		return STATUS_ERROR;
	}

	do {
		ctx = EVP_MD_CTX_create();
		if (ctx == NULL) {
			printf("EVP_MD_CTX_create failed, error 0x%lx\n",
					ERR_get_error());
			break;
		}
		OpenSSL_add_all_digests();
		md = (EVP_MD *)EVP_get_digestbyname("sha256");
		if (md == NULL) {
			printf("EVP_get_digestbyname failed, error 0x%lx\n",
					ERR_get_error());
			break;
		}

		rc = EVP_DigestInit_ex(ctx, md, NULL);
		if (rc != 1) {
			printf("EVP_DigestInit_ex failed, error 0x%lx\n",
					ERR_get_error());
			break;
		}

		rc
				= EVP_DigestVerifyInit(ctx, NULL, md, NULL,
						(EVP_PKEY *)pkey);
		if (rc != 1) {
			printf("EVP_DigestVerifyInit failed, error 0x%lx\n",
					ERR_get_error());
			break;
		}

		if (EVP_PKEY_CTX_set_rsa_padding(ctx->pctx, RSA_PKCS1_PADDING)
				< 1) {
			printf(
					" EVP_PKEY_CTX_set_rsa_padding failed, error 0x%lx\n",
					ERR_get_error());
			break;
		}

		rc = EVP_DigestVerifyUpdate(ctx, msg, strlen(msg));
		if (rc != 1) {
			printf("EVP_DigestVerifyUpdate failed, error 0x%lx\n",
					ERR_get_error());
			break;
		}

		/* Clear any errors for the call below */
		ERR_clear_error();

		rc = EVP_DigestVerifyFinal(ctx, sig, sig_len);
		if (rc != 1) {
			printf("EVP_DigestVerifyFinal failed, error 0x%lx\n",
					ERR_get_error());
			break;
		}

		result = STATUS_SUCCESS;

	} while (0);

	if (ctx) {
		EVP_MD_CTX_destroy(ctx);
		ctx = NULL;
	}

	return !!result;
}

/**
 * @brief   Read public key form certificate
 *
 * @param[in]  cert_path  Path to certificate
 * @retval 0 Pointer to key if successful, NULL if error.
 */
static EVP_PKEY *read_cert_pubkey(const char *cert_path)
{

	EVP_PKEY *pkey = NULL;
	BIO *certbio = NULL;
	X509 *cert = NULL;

	if (!cert_path)
		return NULL;

	certbio = BIO_new(BIO_s_file());
	if (BIO_read_filename(certbio, cert_path) != 1) {
		fprintf(stderr, "Error reading certificate\n");
		return NULL;
	}
	cert = PEM_read_bio_X509(certbio, NULL, 0, NULL);
	if (!cert) {
		fprintf(stderr, "Error loading cert into memory\n");
		return NULL;
	}

	pkey = X509_get_pubkey(cert);
	if (!pkey) {
		fprintf(stderr, "Error getting public key from certificate\n");
		return NULL;
	}
	return pkey;
}

/**
 * @brief   Sign a message using black key/blob
 *
 * @param[in]  msg  Message to sign
 * @param[in]  key_path Path to Black key/blob
 * @param[out]  sig Signature buffer
 * @param[out]  sig_len Signature buffer length
 * @retval 0 if successful, other value if error.
 */
static int sign_with_black_key(const char *msg, const char *key_path,
		uint8_t **sig, uint32_t *sig_len)
{

	SHA256_CTX sha256;
	uint8_t hash[SHA256_DIGEST_LENGTH] = {0};
	uint8_t *w_sig = NULL;
	uint32_t w_sigsz;
	uint8_t tbs[sizeof(SHA256_HASH_PREFIX) + sizeof(hash)] = {0};
	char *w_key = NULL;
	int i;

	/* Check input */
	if (!msg || !key_path)
		return STATUS_ERROR;

	/* Read wrapped private key */
	w_key = read_file(key_path);
	if (!w_key) {
		fprintf(stderr, "Error reading file\n");
		return STATUS_ERROR;
	}
	/* Compute input message hash */
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, msg, strlen(msg));
	SHA256_Final(hash, &sha256);

	dbg("HASH (%d):\n", SHA256_DIGEST_LENGTH);
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		dbg("%02X", hash[i]); dbg("\n");

	/* PKCS1_5 encode the hash */
	memcpy(tbs, SHA256_HASH_PREFIX, sizeof(SHA256_HASH_PREFIX));
	memcpy(tbs + sizeof(SHA256_HASH_PREFIX), hash, sizeof(hash));

	/* Sign the encoded hash with wrapped private key  */
	w_sigsz = KEY_SIZE;
	w_sig = malloc(w_sigsz);
	if (!w_sig) {
		free(w_key);
		return STATUS_ERROR;
	}

	if (castauth_SignHash(w_key, tbs, sizeof(tbs), w_sig, w_sigsz) != 0) {
		fprintf(stderr, "Failed to sign hash\n");
		free(w_key);
		return STATUS_ERROR;
	}

	dbg("SIG_W (%d):\n", w_sigsz);
	for (i = 0; i < w_sigsz; i++)
		dbg("%02X", w_sig[i]); dbg("\n");

	*sig = w_sig;
	*sig_len = w_sigsz;

	return 0;
}

/**
 * @brief   Sign a message and verify it using certificate
 *
 * @param[in]  msg  Message to sign
 * @param[in]  cert_path Path to certificate
 * @param[in]  key_path Path to Black key/blob
 * @retval 0 if successful, other value if error.
 */
static int verify_cert(const char *msg, const char *cert_path,
		const char *key_path)
{

	EVP_PKEY *p_key = NULL;
	uint8_t *w_sig = NULL;
	uint32_t w_sigsz;
	int ret;

	/* Check input */
	if (!msg || !cert_path || !key_path)
		return STATUS_ERROR;

	/* Read public key from cert */
	p_key = read_cert_pubkey(cert_path);
	if (!p_key) {
		fprintf(stderr, "Failed reading plain RSA private key\n");
		ret = STATUS_ERROR;
		goto out;
	}

	/* Sign message with black key */
	if (sign_with_black_key(msg, key_path, &w_sig, &w_sigsz) != 0) {
		fprintf(stderr, "Error signing using HW\n");
		ret = STATUS_ERROR;
		goto out;
	}

	/* Verify signature with public key */
	if (verify(p_key, msg, w_sig, w_sigsz) == 0) {
		fprintf(stdout, "Verify successful\n");
		ret = STATUS_SUCCESS;
	} else {
		fprintf(stdout, "Verify fail\n");
		ret = STATUS_ERROR;
	}

out:
	if (w_sig)
		free(w_sig);
	if (p_key)
		OPENSSL_free(p_key);
	return ret;
}

/**
 * @brief   Sign a message using RSA private key
 *
 * @param[in]  key  Private key
 * @param[in]  msg  Message to sign
 * @param[in]  msg_len Length of message to sign
 * @param[out]  sig Signature buffer
 * @param[out]  sig_len Signature buffer length
 * @retval 0 if successful, other value if error.
 */
static int sign_plain(EVP_PKEY *key, const char *msg, uint32_t msg_len,
		uint8_t *sig, uint32_t *sig_len)
{
	EVP_MD_CTX md_ctx;
	EVP_PKEY_CTX *pkey_ctx;
	int ret = 0;

	/* Check input */
	if (!key || !msg || !sig)
		return STATUS_ERROR;

	EVP_MD_CTX_init(&md_ctx);

	pkey_ctx = EVP_PKEY_CTX_new(key, NULL);
	if (!pkey_ctx) {
		fprintf(stderr, "EVP_PKEY_CTX_new error.\n");
		ret = 1;
		goto out;
	}

	if (!EVP_DigestSignInit(&md_ctx, &pkey_ctx, EVP_sha256(), NULL, key)
			|| EVP_PKEY_CTX_set_rsa_padding(pkey_ctx,
					RSA_PKCS1_PADDING) != 1) {
		fprintf(stderr, "RSA-PSS failed\n");
		ret = 1;
		goto out;
	}

	if (!EVP_SignUpdate(&md_ctx, msg, msg_len)) {
		fprintf(stderr, "Signing data failed");
		ret = 1;
		goto out;
	}
	if (!EVP_SignFinal(&md_ctx, sig, sig_len, key)) {
		fprintf(stderr, "Could not obtain signature");
		ret = 1;
		goto out;
	}

out:
	EVP_MD_CTX_cleanup(&md_ctx);
	EVP_PKEY_free(key);
	return ret;
}

/**
 * @brief   Sign a message using Black key/blob and plain key
 *
 * @param[in]  msg  Data to sign
 * @param[in]  pkey_path  Path to plain key
 * @param[in]  bkey_path  Path to black key
 * @retval 0 if successful, other value if error.
 */
static int sign_hash(const char *msg, const char *pkey_path,
		const char *bkey_path)
{

	EVP_PKEY *p_key = NULL;
	uint8_t p_sig[KEY_SIZE] = {0};
	uint32_t p_sigsz = KEY_SIZE;
	uint8_t *w_sig = NULL;
	uint32_t w_sigsz = 0;
	int i;

	/* Check input */
	if (!msg || !pkey_path || !bkey_path)
		return STATUS_ERROR;

	/* Read plain private key */
	p_key = read_rsa_private_key(pkey_path);
	if (!p_key) {
		fprintf(stderr, "Failed reading plain RSA private key\n");
		return STATUS_ERROR;
	}

	/* Sign using SW */
	if (sign_plain(p_key, msg, strlen(msg), p_sig, &p_sigsz) != 0) {
		fprintf(stderr, "Error signing using SW\n");
		return STATUS_ERROR;
	}

	dbg("SIG_P (%d):\n", p_sigsz);
	for (i = 0; i < p_sigsz; i++)
		dbg("%02X", p_sig[i]); dbg("\n\n");

	/* Sign using HW */
	if (sign_with_black_key(msg, bkey_path, &w_sig, &w_sigsz) != 0) {
		fprintf(stderr, "Error signing using HW\n");
		return STATUS_ERROR;
	}

	dbg("SIG_W (%d):\n", w_sigsz);
	for (i = 0; i < w_sigsz; i++)
		dbg("%02X", w_sig[i]); dbg("\n\n");

	if (memcmp(p_sig, w_sig, KEY_SIZE) == 0) {
		fprintf(stdout, "Sign successful\n");
	} else {
		fprintf(stdout, "Sign fail\n");
		return STATUS_ERROR;
	}

	if (verify(p_key, msg, w_sig, w_sigsz) == 0) {
		fprintf(stdout, "Verify successful\n");
	} else {
		fprintf(stdout, "Verify fail\n");
		return STATUS_ERROR;
	}
	return 0;
}

/**
 * @brief   Read RSA private key from file
 *
 * @param[in]  key_path  Path to key file to read
 * @retval pointer to private key if success, NULL if error.
 */
static EVP_PKEY *read_rsa_private_key(const char *key_path)
{
	EVP_PKEY *pPrivKey = NULL;
	FILE *pFile = NULL;

	/* Check input */
	if (!key_path)
		return NULL;

	pFile = fopen(key_path, "rt");

	if (!pFile) {
		fprintf(stderr, "Key file does not exist.\n");
		goto out;
	}
	pPrivKey = PEM_read_PrivateKey(pFile, NULL, NULL, NULL);
	if (!pPrivKey) {
		fprintf(stderr, "Error reading key from PEM.\n");
		goto out;
	}

out:
	if (pFile)
		fclose(pFile);
	return pPrivKey;
}

/**
 * @brief   Read PEM from file
 *
 * @param[in]  file_path  Path to file to read
 * @retval pointer to file content if success, NULL if error.
 */
static char *read_file(const char *file_path)
{

	FILE *fpin = NULL;
	uint32_t rlen;
	char *file_content = NULL;

	/* Check input */
	if (!file_path)
		return NULL;

	/* Read wrapped private key */
	fpin = fopen(file_path, "r");
	if (!fpin) {
		fprintf(stderr, "Error reading file\n");
		return NULL;
	}
	file_content = malloc(MAX_KEY_PEM_SIZE);
	if (!file_content)
		return NULL;

	rlen = fread(file_content, sizeof(char), MAX_KEY_PEM_SIZE, fpin);
	if (ferror(fpin) != 0) {
		fprintf(stderr, "Error reading file\n");
		fclose(fpin);
		free(file_content);
		return NULL;
	}

	file_content[rlen++] = '\0';
	fclose(fpin);

	return file_content;
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
 * @brief   Load key, convert it and stores the result.
 *
 * @param[in]  from_path  Path to key to convert
 * @param[in]  to_path   Path to where converted key will be stored
 * @param[in]  conv_fn   Conversion function
 * @retval 0 if successful, other value if error.
 */
static int conv_key(const char *from_path, const char *to_path,
		char* (*conv_fn)(const char *))
{
	char in_key[MAX_KEY_PEM_SIZE + 1] = {0};
	char *out_key = NULL;
	FILE *fpin = NULL;
	int ret = STATUS_SUCCESS;
	uint32_t rlen;

	/* Check input */
	if (!from_path || !to_path || !conv_fn)
		return STATUS_ERROR;

	/* Read input key */
	fpin = fopen(from_path, "r");
	if (!fpin) {
		fprintf(stderr, "Error reading file\n");
		ret = STATUS_ERROR;
		goto out;
	}

	rlen = fread(in_key, sizeof(char), MAX_KEY_PEM_SIZE, fpin);
	if (ferror(fpin) != 0) {
		fprintf(stderr, "Error reading file\n");
		ret = STATUS_ERROR;
		goto out;
	} else {
		in_key[rlen++] = '\0';
	}

	/* Convert key */
	out_key = conv_fn(in_key);
	if (out_key == NULL) {
		fprintf(stderr, "Failed to wrap key\n");
		ret = STATUS_ERROR;
		goto out;
	}
	if (save_file(to_path, out_key) != 0) {
		fprintf(stderr, "Error storing key\n");
		ret = STATUS_ERROR;
	}
	/* Write output key */
out:
	if (fpin)
		fclose(fpin);
	if (out_key)
		free(out_key);
	return ret;
}

/**
 * @brief   Retrieve key and store it to a file
 *
 * @param[in]  to_path  Path to where the key will be stored
 * @param[in]  get_fn   Function retrieving the key
 * @retval 0 if successful, other value if error.
 */
static int store_key(const char *to_path, char* (*get_fn)())
{
	char *out_key = NULL;
	int ret = STATUS_SUCCESS;

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
	}
	/* Clean */
out:
	if (out_key)
		free(out_key);
	return ret;
}

/**
 * @brief   Create device key and certificate
 *
 * @param[in]  cert_path  Path to device certificate
 * @param[in]  key_path   Path to device key
 * @retval 0 if successful, other value if error.
 */
static int indiv(const char *cert_path, const char *key_path)
{

	char *cert = NULL;
	char *key = NULL;
	const char *bss_id = "FE:FD:FC:01:02:03";
	int ret = STATUS_SUCCESS;
	BIO *bio = NULL;
	X509 *x509 = NULL;

	/* Check input */
	if (!cert_path || !key_path)
		return STATUS_ERROR;

	if (castauth_GenDevKeyCert(bss_id, strlen(bss_id), CERT_TEMPLATE,
			sizeof(CERT_TEMPLATE), &key) != 0) {
		fprintf(stderr, "Error creating device key and cert\n");
		ret = STATUS_ERROR;
		goto out;
	}
	/* Save the generated key to file */
	if (save_file(key_path, key) != 0) {
		fprintf(stderr, "Error storing key\n");
		ret = STATUS_ERROR;
		goto out;
	}

	/* Convert der cert to pem */
	bio = BIO_new(BIO_s_mem());

	BIO_write(bio, CERT_TEMPLATE, sizeof(CERT_TEMPLATE));
	x509 = d2i_X509_bio(bio, NULL);

	PEM_write_bio_X509(bio, x509);
	BIO_get_mem_data(bio, &cert);

	/* Save the generated cert to file */
	if (save_file(cert_path, cert) != 0) {
		fprintf(stderr, "Error storing cert\n");
		ret = STATUS_ERROR;
		goto out;
	}

out:
	if (cert)
		free(cert);
	if (key)
		free(key);

	X509_free(x509);
	return ret;
}

/**
 * @brief   Main function.
 *
 * @param[in]  argc     Number of arguments
 * @param[in]  argv     Arguments vector
 */
int main(int argc, char *argv[])
{
	uint64_t hwid;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <cmd>\n"
			"wrap    : Convert a plain RSA private key to a black key\n"
			"export  : Encapsulate a black key into a black blob\n"
			"import  : Decapuslate a black blob into a black key\n"
			"gen     : Generate RSA key-pair\n"
			"mppubk  : Get Manufacturing Protection Public key\n",
				argv[0]);
		fprintf(stderr,
				"sign    : Sign a hash using black key or black blob\n"
				"hwid    : Get Hardware Unique Id\n"
				"prov    : Decrypt RSA key and transform it to a black blob\n"
				"modkey  : Get Model key\n"
				"modcert : Get Model certificate\n"
				"indiv   : Generate a device key and device certificate\n"
				"cert    : Match a black key to a certificate\n");
		return STATUS_ERROR;
	}

	if (strcmp(argv[1], "wrap") == 0) {
		printf("Wrapping key\n");
		if (argc < 4) {
			fprintf(
					stderr,
					"Usage %s %s </path/to/plain/key> </path/to/black/key>\n",
					argv[0], argv[1]);
			return STATUS_ERROR;
		}
		return conv_key(argv[2], argv[3], castauth_WrapKey);
	} else if (strcmp(argv[1], "export") == 0) {
		printf("Exporting key\n");
		if (argc < 4) {
			fprintf(
					stderr,
					"Usage %s %s </path/to/black/key> </path/to/blob/key>\n",
					argv[0], argv[1]);
			return STATUS_ERROR;
		}
		return conv_key(argv[2], argv[3], castauth_ExportKey);
	} else if (strcmp(argv[1], "import") == 0) {
		printf("Importing key\n");
		if (argc < 4) {
			fprintf(
					stderr,
					"Usage %s %s </path/to/blob/key> </path/to/black/key>\n",
					argv[0], argv[1]);
			return STATUS_ERROR;
		}
		return conv_key(argv[2], argv[3], castauth_ImportKey);
	} else if (strcmp(argv[1], "sign") == 0) {
		printf("Sign hash\n");
		if (argc < 5) {
			fprintf(
				stderr,
				"Usage %s %s <msg> </path/to/plain/key> </path/to/black/key>\n",
				argv[0], argv[1]);
			return STATUS_ERROR;
		}
		return sign_hash(argv[2], argv[3], argv[4]);

	} else if (strcmp(argv[1], "prov") == 0) {
		printf("Provisioning key\n");
		if (argc < 4) {
			fprintf(
				stderr,
				"Usage %s %s </path/to/encrypted/key> </path/to/blob/key>\n",
				argv[0], argv[1]);
			return STATUS_ERROR;
		}
		return conv_key(argv[2], argv[3], castauth_ProvKey);
	} else if (strcmp(argv[1], "gen") == 0) {
		printf("Generating key\n");
		if (argc < 3) {
			fprintf(stderr, "Usage %s %s </path/to/output/key>\n",
					argv[0], argv[1]);
			return STATUS_ERROR;
		}
		return store_key(argv[2], castauth_GenKeyPair);
	} else if (strcmp(argv[1], "mppubk") == 0) {
		printf("Generate MP public key\n");
		if (argc < 3) {
			fprintf(stderr, "Usage %s %s </path/to/output/key>\n",
					argv[0], argv[1]);
			return STATUS_ERROR;
		}
		return store_key(argv[2], castauth_GetMPPubkey);
	} else if (strcmp(argv[1], "hwid") == 0) {
		printf("Get Hardware Unique Id\n");
		hwid = castauth_GetHwId();
		if (hwid) {
			printf("HWID: %08llx\n", hwid);
			return STATUS_SUCCESS;
		}
		fprintf(stderr, "Error getting Hardware Id\n");
		return STATUS_ERROR;
	} else if (strcmp(argv[1], "cert") == 0) {
		printf("Verify cert\n");
		if (argc < 5) {
			fprintf(
					stderr,
					"Usage %s %s <msg> </path/to/cert> </path/to/black/key>\n",
					argv[0], argv[1]);
			return STATUS_ERROR;
		}
		return verify_cert(argv[2], argv[3], argv[4]);
	} else if (strcmp(argv[1], "modkey") == 0) {
		printf("Get Model key\n");
		if (argc < 3) {
			fprintf(stderr, "Usage %s %s </path/to/output/key>\n",
					argv[0], argv[1]);
			return STATUS_ERROR;
		}
		return store_key(argv[2], castauth_GetModelKey);
	} else if (strcmp(argv[1], "modcert") == 0) {
		printf("Get Model Certificate\n");
		if (argc < 3) {
			fprintf(
					stderr,
					"Usage %s %s </path/to/output/certificate>\n",
					argv[0], argv[1]);
			return STATUS_ERROR;
		}
		return store_key(argv[2], castauth_GetModelCertChain);
	} else if (strcmp(argv[1], "indiv") == 0) {
		printf("Generate device certificate/key\n");
		if (argc < 4) {
			fprintf(
				stderr,
				"Usage %s %s </path/to/out/certificate> </path/to/out/key>\n",
				argv[0], argv[1]);
			return STATUS_ERROR;
		}
		return indiv(argv[2], argv[3]);
	}

	fprintf(stderr, "Unknown command\n");
	return STATUS_ERROR;
}

