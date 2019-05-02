// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    imx_cast_auth_ta.c
 *
 * @brief   Trusted Application implementing Cast receiver
 *			authentication aspects.
 *
 */

/* Standard includes */
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>

/* Library tee includes */
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

/* PTA include */
#include <pta_manufact_protec_mx.h>
#include <pta_blob.h>
#include <pta_bk.h>
#include <pta_ocotp.h>

/* Library mbedtls includes */
#include <mbedtls/config.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <mbedtls/pem.h>
#include <mbedtls/oid.h>
#include <mbedtls/rsa.h>
#include <mbedtls/md.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/oid.h>
#include <mbedtls/sha1.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/cipher.h>
#include <mbedtls/ccm.h>
#include <mbedtls/base64.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

/* Local includes */
#include "imx_cast_auth_ta.h"

/*
 * Debug Macros
 */
#define CAST_DEBUG
#ifdef CAST_DEBUG
#define CAST_TRACE		EMSG
#else
#define CAST_TRACE(...)
#endif

#define CAST_AUTH_KEY_SIZE 256
#define CAST_AUTH_HASH_SIZE 32

#define RSA_PKCS1_PADDING_SIZE   11
#define MAX_ASN1_BUF_SIZE 1024

#define KEY_INTEGRITY_BYTES 12
#define KEY_BLOB_BYTES 12
#define BLOB_OVERHEAD_BYTES 48
#define CAST_AUTH_BSS_ID_SIZE 17

#define IMX_CRYPT_ALG_RSA 5

#define CCM_NONCE_IDX 0
#define CCM_HDR_IDX 1
#define CCM_CIPHER_IDX 2
#define CCM_MAC_IDX 3

/* MP Public key size in bytes */
#define MP_PUBKEY_SIZE	((2*32) + 1)

/*
 * Black RSA private keys:
 *  Black RSAPrivateKey ::= SEQUENCE {   1 + 3
 *      version           Version,       1 + 1 + 1
 *      modulus           INTEGER,       1 + 3 + MPI_MAX + 1
 *      publicExponent    INTEGER,       1 + 3 + MPI_MAX + 1
 *      privateExponent   INTEGER,       1 + 3 + MPI_MAX + 1 +
 *		(12 KEY_INTEGRITY_BYTES) + 48 (KEY_BLOB_BYTES)
 *  }
 */

#define WRAPPED_KEY_DER_MAX_BYTES 22 + \
	KEY_INTEGRITY_BYTES + \
	KEY_BLOB_BYTES + \
	3 * MBEDTLS_MPI_MAX_SIZE

#define MAX_KEY_PEM_SIZE 4096

const uint8_t cast_pubexp[3] = {0x01, 0x00, 0x01};

typedef enum {
	KEY_CLASS_PLAIN = 0, KEY_CLASS_BLACK, KEY_CLASS_BLOB, KEY_CLASS_ALL
} key_class_t;

typedef struct {
	const char *begin;
	const char *end;
} pem_anchor_t;

typedef struct {
	key_class_t key_class;
	pem_anchor_t pem_anchor;
} key_class_pem_t;

#define KEY_CLASS_PEM(CNAME) \
	{KEY_CLASS_ ## CNAME, \
	{PEM_BEGIN_PRIVATE_KEY_ ## CNAME, PEM_END_PRIVATE_KEY_ ## CNAME} }

/* CAAM built-in curves with data */
static const key_class_pem_t key_class_pem[] = {KEY_CLASS_PEM(PLAIN),
		KEY_CLASS_PEM(BLACK), KEY_CLASS_PEM(BLOB), {0, {0, 0} }, };

struct dbuf {
	uint8_t *data;
	uint32_t length;
};

struct rsa_attributes {
	/* private exponent */
	struct dbuf d;
	/* public exponent */
	struct dbuf e;
	/* public modulus */
	struct dbuf n;
};

typedef enum {
	blob_encap = 0, blob_decap,
} blob_op_t;

/** @brief  Model certificate serial number, length: 20  */
const uint8_t CERT_SERIAL_NUMBER_PLACEHOLDER[] = {0x3c, 0x43, 0x45, 0x52, 0x54,
		0x20, 0x53, 0x45, 0x52, 0x49, 0x41, 0x4c, 0x20, 0x4e, 0x55,
		0x4d, 0x42, 0x45, 0x52, 0x3e};

/** @brief  Model certificate unique hardware Id, length: 20  */
const uint8_t HARDWARE_ID_PLACEHOLDER[] = {0x3c, 0x55, 0x4e, 0x49, 0x51, 0x55,
		0x45, 0x20, 0x48, 0x41, 0x52, 0x44, 0x57, 0x41, 0x52, 0x45,
		0x20, 0x49, 0x44, 0x3e};

/** @brief  Model certificate BSS Id, length: 17  */
const uint8_t MAC_ADDRESS_PLACEHOLDER[] = {0x41, 0x41, 0x3a, 0x42, 0x42, 0x3a,
		0x43, 0x43, 0x3a, 0x44, 0x44, 0x3a, 0x45, 0x45, 0x3a, 0x46,
		0x46};

/** @brief  Model certificate subject key Id, length: 20  */
const uint8_t SUBJECT_KEY_ID_PLACEHOLDER[] = {0x4d, 0x3c, 0x82, 0xf5, 0x2f,
		0x39, 0x95, 0xaf, 0x03, 0xe4, 0x96, 0x51, 0x43, 0x62, 0x7d,
		0x5d, 0x7a, 0x60, 0xa1, 0x20};

/** @brief  Model certificate public modulus, length: 257  */
const uint8_t PUBLIC_MODULUS_PLACEHOLDER[] = {0x00, 0xd5, 0x96, 0x0d, 0x7e,
		0xa7, 0x91, 0x70, 0x0e, 0xe9, 0xf6, 0x4c, 0xb1, 0x7b, 0x91,
		0xe6, 0x6f, 0x47, 0xa3, 0xe8, 0xa7, 0x9c, 0xac, 0x05, 0xea,
		0x39, 0x3b, 0x9c, 0x35, 0xd4, 0xa4, 0x92, 0x5a, 0xe4, 0x1c,
		0x03, 0xa1, 0x52, 0x70, 0xf8, 0x68, 0xb3, 0x99, 0x70, 0x4f,
		0x9f, 0x7b, 0x36, 0x7c, 0x86, 0x25, 0x94, 0xc4, 0x9e, 0x12,
		0x1f, 0x66, 0xfe, 0x1b, 0x26, 0xb3, 0x73, 0x05, 0x64, 0xab,
		0x8a, 0x62, 0xea, 0xc1, 0x0b, 0xb0, 0x9e, 0xfb, 0x3a, 0x4b,
		0x2e, 0x81, 0x6f, 0x4d, 0xce, 0x7b, 0xc8, 0x08, 0x84, 0xd0,
		0x03, 0x08, 0xab, 0xdd, 0x1d, 0xf2, 0x65, 0x05, 0x89, 0xf0,
		0x7f, 0x9b, 0x05, 0x16, 0xf5, 0x2a, 0x0b, 0xc5, 0x53, 0x43,
		0x9d, 0x35, 0xe1, 0x59, 0x7a, 0xaf, 0x17, 0x5e, 0xe7, 0x95,
		0xbf, 0x65, 0x8d, 0x26, 0x1d, 0x93, 0x59, 0x0a, 0xdb, 0xaa,
		0x6b, 0x8c, 0xd2, 0xea, 0xba, 0x54, 0xb3, 0x7e, 0x77, 0x7f,
		0x5a, 0xce, 0x6b, 0xa8, 0x5a, 0x43, 0x66, 0x0e, 0x6e, 0x18,
		0x43, 0x60, 0x0a, 0x58, 0x15, 0xb7, 0xee, 0xc7, 0x12, 0x91,
		0x6c, 0x23, 0xd4, 0xa9, 0xab, 0xe9, 0xc2, 0xf9, 0x3b, 0x45,
		0xd8, 0x79, 0x9a, 0x7b, 0xed, 0xa5, 0xd7, 0x86, 0xa9, 0x6c,
		0x07, 0x1e, 0x7d, 0xfe, 0xa6, 0x9a, 0xa7, 0xbe, 0xc8, 0x16,
		0xe5, 0xa9, 0xb3, 0xa1, 0x6e, 0x8f, 0xad, 0x74, 0xb8, 0x75,
		0x30, 0x76, 0x90, 0x04, 0x89, 0x48, 0x17, 0x8b, 0xd7, 0x50,
		0xf1, 0xb8, 0xba, 0xce, 0x3a, 0x07, 0x73, 0x86, 0x29, 0x4d,
		0x58, 0x6f, 0x78, 0xb8, 0xed, 0x44, 0xc5, 0xf0, 0x74, 0x15,
		0xb3, 0x79, 0xe1, 0xf5, 0xae, 0x78, 0x31, 0xcf, 0x61, 0x1e,
		0x44, 0xa3, 0x22, 0xb8, 0x87, 0x8c, 0x1c, 0x66, 0x99, 0x9c,
		0x93, 0x1d, 0x41, 0x87, 0xfa, 0xd2, 0x49, 0x73, 0xcb, 0x55,
		0x0d, 0x1d};

const size_t CERT_PREFIX_BYTES = 4;
const size_t CERT_SUFFIX_BYTES = 276;
const size_t CERT_PUBMOD_PREFIX_BYTES = 8;
const size_t CERT_PUBMOD_SUFFIX_BYTES = 5;

const unsigned char SHA256_HASH_PREFIX[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
		0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
		0x00, 0x04, 0x20};

char *sp; /* the start position of the string used by strtok */

/* prototypes */

static bool replace_placeholder(uint8_t *cert, size_t cert_len,
		const uint8_t *placeholder, size_t placeholder_len,
		const uint8_t *value, size_t value_len);
static uint8_t *memmem(const uint8_t *haystack, size_t hl,
		const uint8_t *needle, size_t nl);
static char *strtok1(char *str, const char *delimiters);
static TEE_Result castauth_GenKeyPair(char *private_key,
		uint32_t private_key_len, char *public_key,
		uint32_t public_key_len);
static TEE_Result castauth_SignHash(const char *in_wprivkey_pem,
		uint8_t *hash, uint32_t hash_len,
		uint8_t *outsig, uint32_t outsig_len);
static TEE_Result castauth_WrapKey(char *key_pem, char *wkey_pem);
static TEE_Result castauth_add_pkcs1_type1_padding(uint8_t *to,
		unsigned int tlen, const uint8_t *from,
		unsigned int flen);
static TEE_Result castauth_BlobKey(blob_op_t blob_op, const char *in_key,
		char *out_key);
static TEE_Result pem_to_rsa_attr(const char *key_pem,
		struct rsa_attributes *rsa_attrs, key_class_t key_class);
static TEE_Result castauth_WriteKeyPem(mbedtls_pk_context *key, char *buf,
		size_t size, key_class_t key_class);
static TEE_Result rsa_attr_to_pem(struct rsa_attributes *rsa_attrs,
		char *outpem, key_class_t key_class);
static TEE_Result castauth_VerifyCertSignature(const uint8_t *cert,
		uint32_t cert_len, const char *model_key,
		uint32_t model_key_len __maybe_unused);
static TEE_Result castauth_GenDevKeyCert(
		const char *bss_id, uint32_t bss_id_len __maybe_unused,
		const char *blackmodel_key, uint32_t blackmodel_key_len,
		uint8_t *inout_cert, uint32_t inout_cert_len,
		char *out_dev_key, uint32_t out_dev_keylen __maybe_unused
);
static TEE_Result castauth_ProvKey(const char *ekey_pem, char *blob_pem,
		uint32_t blob_pem_len);
static TEE_Result castauth_mp_pubkey(unsigned char *mp_pubkey,
		uint32_t mp_pubkey_len);
static TEE_Result castauth_MPPubKey(unsigned char *mp_pubkey_pem,
		uint32_t mp_pubkey_pem_len);
static TEE_Result castauth_GetHwId(uint8_t *hwid, uint32_t hwid_len);

/**
 * @brief   Cover a plain RSA private key into a black key
 *
 * @param[in]   plain_key   Plain RSA private key in PEM format
 * @param[out]  black_key   Blacken RSA private key in PEM format
 *
 * @retval TEE_SUCCESS                Success
 * @retval TEE_ERROR_BAD_PARAMETERS   Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY    Can't allocate memory for one object
 * @retval TEE_ERROR_GENERIC Any      Other error condition
 */
static TEE_Result castauth_WrapKey(char *plain_key, char *black_key)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	TEE_TASessionHandle session;
	TEE_UUID uuid = PTA_BK_PTA_UUID;
	uint32_t err_origin;
	uint32_t exp_param_types;
	TEE_Param params[TEE_NUM_PARAMS];
	key_class_t key_class = KEY_CLASS_ALL;

	struct rsa_attributes rsa = {0};

	/* Wrapped private exponent buffer */
	uint32_t tmp_buf_len = MBEDTLS_MPI_MAX_SIZE;
	void *tmp_buf = NULL;

	/* Check input arguments */
	if ((!plain_key) || (!black_key)) {
		CAST_TRACE("NULL parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	key_class = KEY_CLASS_PLAIN;
	if (pem_to_rsa_attr(plain_key, &rsa, key_class) != TEE_SUCCESS) {
		CAST_TRACE("Bad key format");
		return TEE_ERROR_BAD_FORMAT;
	}

	tmp_buf = TEE_Malloc(tmp_buf_len, 0);
	if (!tmp_buf) {
		CAST_TRACE("Error allocating memory");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = TEE_OpenTASession(&uuid, 0, 0, NULL, &session, &err_origin);
	if (res != TEE_SUCCESS) {
		CAST_TRACE(
				"TEE open session failed with code 0x%x origin 0x%x",
				res, err_origin);
		goto out;
	}

	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE);

	/* params[0] represents the algo id and key encap type */
	/* params[1] represents the private exponent */
	/* params[2] represents the black key */

	params[0].value.a = IMX_CRYPT_ALG_RSA;
	params[0].value.b = PTA_BK_ECB;
	params[1].memref.buffer = rsa.d.data;
	params[1].memref.size = rsa.d.length;
	params[2].memref.buffer = tmp_buf;
	params[2].memref.size = tmp_buf_len;

	/* Wrap the key in PTA */
	res = TEE_InvokeTACommand(session, 0, PTA_BK_CMD_ENCAPS,
			exp_param_types, params, &err_origin);
	if (res != TEE_SUCCESS) {
		CAST_TRACE(
				"TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		goto out;
	}

	/* Zeroise plain key */
	memset(rsa.d.data, 0, rsa.d.length);
	/* Free it */
	TEE_Free(rsa.d.data);

	/* Update exponent size */
	tmp_buf_len = params[2].memref.size;

	/* Update exponent buffer */
	rsa.d.data = tmp_buf;

	/* Update exponent bytes */
	rsa.d.length = tmp_buf_len;

	/* Encode black key in PEM format */
	key_class = KEY_CLASS_BLACK;
	res = rsa_attr_to_pem(&rsa, black_key, key_class);

out:
	if (rsa.d.data)
		TEE_Free(rsa.d.data);
	if (rsa.e.data)
		TEE_Free(rsa.e.data);
	if (rsa.n.data)
		TEE_Free(rsa.n.data);

	TEE_CloseTASession(session);
	return res;
}

/**
 * @brief   Encapsulate/Decapsulate a Black key/Black Blob.
 *
 * @param[in]   in_key    Input key in PEM format
 * @param[out]  out_key   Output key in PEM format
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 * @retval TEE_ERROR_GENERIC         Any other error condition
 */
static TEE_Result castauth_BlobKey(blob_op_t blob_op, const char *in_key,
		char *out_key)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	TEE_TASessionHandle session;
	TEE_UUID uuid = PTA_BLOB_PTA_UUID;
	uint32_t err_origin;
	uint32_t exp_param_types;
	TEE_Param params[TEE_NUM_PARAMS];
	key_class_t key_class = KEY_CLASS_ALL;
	struct rsa_attributes rsa = {0};
	uint8_t key_mod[PTA_BLOB_KEY_SIZE] = {0xad, 0x9a, 0x9d, 0xb0, 0x68,
			0x6b, 0xbc, 0x67, 0xa6, 0xdb, 0xe8, 0x1f, 0x7b, 0x16,
			0xa0, 0x7e};
	uint32_t cmd;

	/* Wrapped private exponent buffer */
	void *tmp_buf = NULL;
	uint32_t tmp_buf_len;

	/* Check input arguments */
	if ((!in_key) || (!out_key)) {
		CAST_TRACE("Null parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	/* Parse Input key */
	key_class = (blob_op == blob_encap) ? KEY_CLASS_BLACK : KEY_CLASS_BLOB;
	res = pem_to_rsa_attr(in_key, &rsa, key_class);
	if (res != TEE_SUCCESS) {
		CAST_TRACE("Bad key format");
		goto out;
	}

	tmp_buf_len = (blob_op == blob_encap) ? rsa.d.length
			+ PTA_BLOB_PAD_SIZE : rsa.d.length - PTA_BLOB_PAD_SIZE;

	/* Allocate memory for blob bytes */
	tmp_buf = TEE_Malloc(tmp_buf_len, 0);
	if (!tmp_buf) {
		CAST_TRACE("Error allocating memory");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/*
	 * opening session with PTA
	 */
	res = TEE_OpenTASession(&uuid, 0, 0, NULL, &session, &err_origin);
	if (res != TEE_SUCCESS) {
		CAST_TRACE(
				"TEE open session failed with code 0x%x origin 0x%x",
				res, err_origin);
		goto out;
	}

	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT);

	/* params[0] represents the blob type */
	/* params[1] represents the key modifier */
	/* params[2] represents the black private exponent */
	/* params[3] represents the blobbed private exponent */

	params[0].value.a = PTA_BLOB_BLACK_ECB;

	params[1].memref.buffer = key_mod;
	params[1].memref.size = sizeof(key_mod);

	params[2].memref.buffer = rsa.d.data;
	params[2].memref.size = rsa.d.length;

	params[3].memref.buffer = tmp_buf;
	params[3].memref.size = tmp_buf_len;

	cmd = (blob_op == blob_encap)
					 ? PTA_BLOB_CMD_ENCAPS
					 : PTA_BLOB_CMD_DECAPS;

	res = TEE_InvokeTACommand(session, 0, cmd, exp_param_types, params,
			&err_origin);
	if (res != TEE_SUCCESS) {
		CAST_TRACE(
				"TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		goto out;
	}

	/* Update buffer size */
	tmp_buf_len = params[3].memref.size;

	/* Free previous exponent */
	TEE_Free(rsa.d.data);

	/* Replace previous private exponent */
	rsa.d.data = tmp_buf;
	rsa.d.length = tmp_buf_len;

	/* Write output key as PEM */
	key_class = (blob_op == blob_encap) ? KEY_CLASS_BLOB : KEY_CLASS_BLACK;
	res = rsa_attr_to_pem(&rsa, out_key, key_class);
	if (res != TEE_SUCCESS) {
		CAST_TRACE("Bad key format");
		goto out;
	}

out:
	if (rsa.d.data)
		TEE_Free(rsa.d.data);
	if (rsa.e.data)
		TEE_Free(rsa.e.data);
	if (rsa.n.data)
		TEE_Free(rsa.n.data);
	TEE_CloseTASession(session);
	return res;
}

/**
 * @brief   Generates Device key and certificate
 *
 * @param[in]      bss_id BSS ID
 * @param[in]      bss_id_len BSS ID length
 * @param[in]      model_key Wrapped model key in PEM format
 * @param[in]      model_key_len Model key length
 * @param[in,out]  inout_cert Template certificate in DER format
 * @param[in,out]  inout_cert_len Template certificate length
 * @param[out]     device_key Generated device key
 * @param[out]     device_key_len Device key length
 *
 * @retval TEE_SUCCESS              No errors
 * @retval TEE_ERROR_OUT_OF_MEMORY  Can't allocate memory for one object
 * @retval TEE_ERROR_BAD_PARAMETERS Bad input parameters
 * @retval TEE_ERROR_BAD_FORMAT     Parameter is in a bad format
 * @retval TEE_ERROR_GENERIC        Any other error condition
 */
static TEE_Result castauth_GenDevKeyCert(
		const char *bss_id, uint32_t bss_id_len __maybe_unused,
		const char *model_key, uint32_t model_key_len __maybe_unused,
		uint8_t *inout_cert, uint32_t inout_cert_len,
		char *device_key, uint32_t device_key_len __maybe_unused
)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	mbedtls_rsa_context *rsa = NULL;
	mbedtls_pk_context pk;
	mbedtls_x509write_cert write_cert;
	mbedtls_x509_crt cert;
	uint8_t *certw = NULL;
	char *public_key = NULL;
	char *private_key = NULL;
	char *black_key = NULL;
	char *blob_key = NULL;
	uint32_t keysize = MAX_KEY_PEM_SIZE;
	char hwid_str[20] = {0x32};
	union hwid_t {
		uint8_t as_bytes[8];
		uint64_t as_long;
	} hwid;
	uint8_t serial[20] = {0};
	uint8_t *skid = NULL;
	int i;
	size_t nlen = 0;
	uint8_t hash[CAST_AUTH_HASH_SIZE];
	uint8_t tbs[sizeof(SHA256_HASH_PREFIX) + sizeof(hash)] = {0};
	uint32_t public_modulus_len = sizeof(PUBLIC_MODULUS_PLACEHOLDER);
	uint8_t *modulus = NULL;
	uint32_t tbs_range_from = CERT_PREFIX_BYTES;
	uint32_t tbs_range_len = inout_cert_len -
	CERT_PREFIX_BYTES - CERT_SUFFIX_BYTES;
	uint8_t *tbs_sig = NULL;
	uint32_t tbs_sig_len = 0;
	unsigned char buf[MBEDTLS_MPI_MAX_SIZE * 2 + 20];
	unsigned char *c = buf + sizeof(buf);
	size_t len = 0;

	/* Check input parameters */
	if ((!bss_id) || (strlen(bss_id) != CAST_AUTH_BSS_ID_SIZE) ||
			(!device_key) || (!inout_cert) || (!model_key)) {
		CAST_TRACE("NULL parameter");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Initialize x509 context */
	mbedtls_x509_crt_init(&cert);
	mbedtls_x509write_crt_init(&write_cert);

	/* Initialize RSA context */
	mbedtls_pk_init(&pk);

	/* 0. Verify the signature of the cert template  */
	res = castauth_VerifyCertSignature(
	inout_cert, inout_cert_len, model_key,
	strlen(model_key) + 1);
	if (res != TEE_SUCCESS) {
		CAST_TRACE("Invalid template certificate signature");
		return res;
	}

	/* Allocate a working copy of the template certificate */
	certw = TEE_Malloc(inout_cert_len, 0);
	if (!certw) {
		CAST_TRACE("Out of memory");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Copy input certificate to a local working copy */
	memcpy(certw, inout_cert, inout_cert_len);

	/* Check if the template certificate is valid */
	if (mbedtls_x509_crt_parse_der(&cert, certw, inout_cert_len) != 0) {
		CAST_TRACE("Invalid template certificate");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	/* Allocate memory for public key */
	public_key = TEE_Malloc(keysize, 0);
	if (!public_key) {
		CAST_TRACE("Out of memory");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Allocate memory for private key */
	private_key = TEE_Malloc(keysize, 0);
	if (!private_key) {
		CAST_TRACE("Out of memory");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Allocate memory for black key */
	black_key = TEE_Malloc(keysize, 0);
	if (!black_key) {
		CAST_TRACE("Out of memory");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Allocate memory for blob key */
	blob_key = TEE_Malloc(keysize, 0);
	if (!blob_key) {
		CAST_TRACE("Out of memory");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* 2. Generate device-specific wrapping key */
	/* 3. Generate RSA private key */
	res = castauth_GenKeyPair(private_key, keysize, public_key, keysize);
	if (res != TEE_SUCCESS) {
		CAST_TRACE("Error generating key-pair");
		goto out;
	}
	/* 4. Wrap the private key */
	res = castauth_WrapKey(private_key, black_key);
	if (res != TEE_SUCCESS) {
		CAST_TRACE("Error wrapping key");
		goto out;
	}

	/* Export the key */
	res = castauth_BlobKey(blob_encap, black_key, blob_key);
	if (res != TEE_SUCCESS) {
		CAST_TRACE("Error exporting black key");
		goto out;
	}
	/* Read the RSA public key */
	if (mbedtls_pk_parse_public_key(&pk, (uint8_t *)public_key,
	strlen(public_key) + 1) != 0) {
		CAST_TRACE("Error reading public key");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	/* 5. Compute the SKID (subject key id) */
	mbedtls_x509write_crt_set_subject_key(&write_cert, &pk);

	memset(buf, 0, sizeof(buf));
	mbedtls_pk_write_pubkey(&c, buf, write_cert.subject_key);

	skid = buf + sizeof(buf) - 20;
	mbedtls_sha1(buf + sizeof(buf) - len, len, skid);

	if (!replace_placeholder(certw, inout_cert_len,
		SUBJECT_KEY_ID_PLACEHOLDER,
		sizeof(SUBJECT_KEY_ID_PLACEHOLDER), skid, 20)) {
		CAST_TRACE("Error setting certificate subject key id");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	/* 6. Obtain HW unique Id*/
	memset(hwid.as_bytes, 0, sizeof(hwid.as_bytes));
	res = castauth_GetHwId(&hwid.as_bytes[0], sizeof(hwid.as_bytes));
	if (res != TEE_SUCCESS) {
		CAST_TRACE("Error getting HW Id");
		goto out;
	}

	snprintf(hwid_str, sizeof(hwid_str), "%08llx", hwid.as_long);

	if (!replace_placeholder(certw, inout_cert_len,
			HARDWARE_ID_PLACEHOLDER,
			sizeof(HARDWARE_ID_PLACEHOLDER),
			(uint8_t *)hwid_str,
			sizeof(hwid_str))) {
		CAST_TRACE("Error setting certificate subject");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	/* 7. Generate Serial Number  */
	memset(serial, 0, sizeof(serial));
	for (i = 0; i < 20; i++)
		serial[i] = skid[i] ^ ((uint8_t)hwid_str[i]);

	if (!replace_placeholder(certw, inout_cert_len,
			CERT_SERIAL_NUMBER_PLACEHOLDER,
			sizeof(CERT_SERIAL_NUMBER_PLACEHOLDER), serial,
			sizeof(serial))) {
		CAST_TRACE("Error setting certificate serial number");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	/* 8. Verify BSS ID  */
	if (strlen(bss_id) != 17) {
		CAST_TRACE("BSS id length is incorrect");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	/* Replace BSS_ID */
	if (!replace_placeholder(certw, inout_cert_len,
			MAC_ADDRESS_PLACEHOLDER,
			sizeof(MAC_ADDRESS_PLACEHOLDER), (uint8_t *)bss_id,
			strlen(bss_id))) {
		CAST_TRACE("Error setting certificate BSS Id");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	/* 9. Certificate template as DER */
	rsa = mbedtls_pk_rsa(pk);
	if (!rsa) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	nlen = mbedtls_mpi_size(&rsa->N);
	modulus = TEE_Malloc(nlen, 0);
	if (!modulus) {
		CAST_TRACE("Out of memory");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	if (mbedtls_mpi_write_binary(&rsa->N, modulus, nlen)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (!replace_placeholder(certw, inout_cert_len,
			PUBLIC_MODULUS_PLACEHOLDER +
			(public_modulus_len - nlen),
			public_modulus_len - (public_modulus_len - nlen),
			modulus, nlen)) {
		CAST_TRACE("Error setting certificate public key");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	/* 12. Sign the "To Be Signed" part of the certificate */
	if ( mbedtls_md(
			mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
			(certw + tbs_range_from), tbs_range_len, hash) != 0) {
		CAST_TRACE("Error signing certificate TBS");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	tbs_sig_len = CAST_AUTH_KEY_SIZE;
	tbs_sig = TEE_Malloc(tbs_sig_len, 0);
	if (!tbs_sig) {
		CAST_TRACE("Out of memory");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	memcpy(tbs, SHA256_HASH_PREFIX, sizeof(SHA256_HASH_PREFIX));
	memcpy(tbs + sizeof(SHA256_HASH_PREFIX), hash, sizeof(hash));

	res = castauth_SignHash(model_key, tbs,
	sizeof(tbs), tbs_sig, tbs_sig_len);
	if (res != TEE_SUCCESS) {
		CAST_TRACE("Error signing certificate");
		goto out;
	}

	/* 13. Replace the signature in template with the TBS signature */
	memcpy((void *)(certw + inout_cert_len - tbs_sig_len),
	tbs_sig, tbs_sig_len);

	/* Return the device certificate to the caller  */
	memcpy(inout_cert, certw, inout_cert_len);

	/* Return the device key to the caller */
	memcpy(device_key, blob_key, strlen(blob_key));

out:
	if (public_key)
		TEE_Free(public_key);
	if (private_key)
		TEE_Free(private_key);
	if (black_key)
		TEE_Free(black_key);
	if (blob_key)
		TEE_Free(blob_key);
	if (certw)
		TEE_Free(certw);
	if (modulus)
		TEE_Free(modulus);
	if (tbs_sig)
		TEE_Free(tbs_sig);

	mbedtls_pk_free(&pk);
	mbedtls_x509_crt_free(&cert);
	mbedtls_x509write_crt_free(&write_cert);
	return res;
}

/**
 * @brief   Verify template certificate signature
 *
 * @param[in]  cert Template certificate in DER format
 * @param[in]  cert_len Template certificate length
 * @param[in]  model_key Wrapped model key in PEM format
 * @param[in]  model_key_len Model key length
 *
 * @retval TEE_SUCCESS                 Signature is correct
 * @retval TEE_ERROR_SIGNATURE_INVALID Signature is incorrect
 * @retval TEE_ERROR_BAD_FORMAT        Parameter is in a bad format
 * @retval TEE_ERROR_GENERIC Any       Other error condition
 */
static TEE_Result castauth_VerifyCertSignature(const uint8_t *cert,
uint32_t cert_len, const char *model_key,
uint32_t model_key_len __maybe_unused)
{
	TEE_Result res = TEE_ERROR_SIGNATURE_INVALID;
	mbedtls_rsa_context rsa;
	mbedtls_mpi N, E;
	struct rsa_attributes rsa_attrs = {0};
	key_class_t key_class = KEY_CLASS_BLACK;
	uint8_t hash[CAST_AUTH_HASH_SIZE];
	uint32_t tbs_range_from = CERT_PREFIX_BYTES;
	uint32_t tbs_range_len = cert_len -
	CERT_PREFIX_BYTES - CERT_SUFFIX_BYTES;
	uint32_t signature_from = cert_len - CAST_AUTH_KEY_SIZE;

	/* Context initialisation */
	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
	mbedtls_mpi_init(&N);
	mbedtls_mpi_init(&E);

	/* Extract public key from PEM */
	res = pem_to_rsa_attr(model_key, &rsa_attrs, key_class);
	if (res != TEE_SUCCESS) {
		CAST_TRACE("Bad key format");
		goto out;
	}

	/* Import public key */
	if ((mbedtls_mpi_read_binary(&N, rsa_attrs.n.data, rsa_attrs.n.length)
	!= 0) || (mbedtls_mpi_read_binary(&E, cast_pubexp, sizeof(cast_pubexp))
	!= 0)) {
		CAST_TRACE("Error importing public key");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	/* Import is not implemented in this version of mbedtls */
	if ((mbedtls_mpi_copy(&rsa.N, &N) != 0) ||
	(mbedtls_mpi_copy(&rsa.E, &E)	!= 0)) {
		CAST_TRACE("Error importing public key");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	/* Set key size */
	rsa.len = (mbedtls_mpi_bitlen(&rsa.N) + 7) >> 3;

	/* Hash the TBS region */
	if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
		(cert + tbs_range_from), tbs_range_len, hash) != 0) {
		CAST_TRACE("Error hashing TBS region");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	/* Verify the signature */
	if (mbedtls_rsa_pkcs1_verify(&rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC,
	MBEDTLS_MD_SHA256, CAST_AUTH_HASH_SIZE, hash,
	(cert + signature_from)) != 0) {
		CAST_TRACE("Certificate signature is invalid");
		res = TEE_ERROR_SIGNATURE_INVALID;
		goto out;
	}

	/* Signature is valid */
	res = TEE_SUCCESS;

out:
	mbedtls_mpi_free(&N);
	mbedtls_mpi_free(&E);
	mbedtls_rsa_free(&rsa);

	return res;
}

/**
 * @brief   Replace place-holder in certificate with value
 *
 * @param[in,out]  cert       Input Certificate in DER format
 * @param[in] cert_len        Certificate length
 * @param[in] placeholder     Content to replace
 * @param[in] placeholder_len Content length
 * @param[in] value           New value
 * @param[in] value_len       Value length
 *
 * @retval true if OK
 * @retval false if Error
 */
static bool replace_placeholder(uint8_t *cert, size_t cert_len,
		const uint8_t *placeholder, size_t placeholder_len,
		const uint8_t *value, size_t value_len)
{
	uint8_t *placeholder_ptr = NULL;

	if (!cert || !placeholder || !value)
		return false;
	if (placeholder_len != value_len)
		return false;
	placeholder_ptr = memmem(cert, cert_len, placeholder, placeholder_len);
	if (!placeholder_ptr)
		return false;
	memcpy(placeholder_ptr, value, value_len);
	return true;
}

/**
 * @brief   Get MP public key
 *
 * @param[in]  mp_pubkey  Manufacturing protection public key
 * @param[in]  mp_pubkey_len  MP public key length
 *
 * @retval TEE_SUCCESS              Success
 * @retval TEE_ERROR_BAD_PARAMETERS Bad input parameters
 * @retval TEE_ERROR_BAD_PARAMETERS Parameter is in bad format
 * @retval TEE_ERROR_GENERIC        Any other error condition
 */
static TEE_Result castauth_mp_pubkey(unsigned char *mp_pubkey,
uint32_t mp_pubkey_len)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_TASessionHandle session;
	TEE_UUID uuid = PTA_MANUFACT_PROTEC_PTA_UUID;
	uint32_t err_origin;
	uint32_t exp_param_types;
	TEE_Param params[4];

	/*
	 * openning session with MP PTA
	 */
	res = TEE_OpenTASession(&uuid, 0, 0, NULL, &session, &err_origin);
	if (res != TEE_SUCCESS) {
		CAST_TRACE(
				"TEE open session failed with code 0x%x origin 0x%x",
				res, err_origin);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* params[0] represents the mp public key */
	params[0].memref.buffer = mp_pubkey;
	params[0].memref.size = mp_pubkey_len;

	/* get the MPPub key (issuer key of the certificate) from the TA */
	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	res = TEE_InvokeTACommand(session, 0, PTA_MANUFACT_PROTEC_CMD_PUBKEY,
			exp_param_types, params, &err_origin);

out:
	return res;
}

/**
 * @brief   Get PEM encoded MP public key
 *
 * @param[in]  mp_pubkey  Manufacturing protection public key
 * @param[in]  mp_pubkey_len  MP public key length
 *
 * @retval TEE_SUCCESS if OK
 * @retval TEE_ERROR_BAD_PARAMETERS Bad input parameters
 * @retval TEE_ERROR_BAD_PARAMETERS Parameter is in bad format
 * @retval TEE_ERROR_GENERIC Any other error condition
 */
static TEE_Result castauth_MPPubKey(unsigned char *mp_pubkey_pem,
		uint32_t mp_pubkey_pem_len)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	uint8_t *mp_pubkey = NULL, *tmp_buff = NULL;
	uint32_t mp_pubkey_len = MP_PUBKEY_SIZE;
	mbedtls_pk_context pk;
	const mbedtls_pk_info_t *pk_info = NULL;
	mbedtls_ecp_keypair *ec = NULL;

	mbedtls_pk_init(&pk);

	/* Get information associated with the PK type. */
	pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
	if (mbedtls_pk_setup(&pk, pk_info)) {
		CAST_TRACE("Error mbedtls_pk_setup");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* Check if PK context can do RSA */
	if (mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECKEY) == 0) {
		CAST_TRACE("Error mbedtls_pk_can_do");
		res = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	/* Access the ECC context inside PK context */
	ec = mbedtls_pk_ec(pk);
	if (!ec) {
		CAST_TRACE("Error mbedtls_pk_ec");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	mp_pubkey = TEE_Malloc(mp_pubkey_len, 0);
	tmp_buff = TEE_Malloc(mp_pubkey_len, 0);
	if (!mp_pubkey || !tmp_buff) {
		CAST_TRACE("Error TEE_Malloc");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	res = castauth_mp_pubkey(tmp_buff, mp_pubkey_len);
	if (res != TEE_SUCCESS) {
		CAST_TRACE("Failed to get MP pubkey");
		goto out;
	}

	memcpy(mp_pubkey, "\x04", 1);
	memcpy(mp_pubkey + 1, tmp_buff, mp_pubkey_len - 1);

	if (mbedtls_ecp_group_load(&ec->grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
		res = TEE_ERROR_BAD_FORMAT;
		CAST_TRACE("Error mbedtls_ecp_group_load()");
		goto out;
	}

	if (mbedtls_ecp_point_read_binary(&ec->grp, &ec->Q, mp_pubkey,
			mp_pubkey_len) != 0) {
		CAST_TRACE("Error mbedtls_ecp_point_read_binary()");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	if (mbedtls_ecp_check_pubkey(&ec->grp, &ec->Q) != 0) {
		CAST_TRACE("Error mbedtls_ecp_check_pubkey()");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	if (mbedtls_pk_write_pubkey_pem(&pk, mp_pubkey_pem, mp_pubkey_pem_len)
			!= 0) {
		CAST_TRACE("Error mbedtls_pk_write_pubkey_pem()");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	res = TEE_SUCCESS;
out:
	mbedtls_pk_free(&pk);
	TEE_Free(mp_pubkey);
	TEE_Free(tmp_buff);
	return res;
}

/**
 * @brief   Get Hardware Unique Id
 *
 * @param[out] hwid  Hardware Id
 *
 * @retval TEE_SUCCESS              Success
 * @retval TEE_ERROR_BAD_PARAMETERS Bad input parameters
 * @retval TEE_ERROR_GENERIC        Any other error condition
 */
static TEE_Result castauth_GetHwId(uint8_t *hwid, uint32_t hwid_len)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_TASessionHandle session;
	TEE_UUID uuid = PTA_OCOTP_PTA_UUID;
	uint32_t err_origin;
	uint32_t exp_param_types;
	TEE_Param params[TEE_NUM_PARAMS];

	/*
	 * openning session with PTA
	 * in this case the TA plays the role of the CA
	 */
	res = TEE_OpenTASession(&uuid, 0, 0, NULL, &session, &err_origin);
	if (res != TEE_SUCCESS) {
		CAST_TRACE(
				"TEE open session failed with code 0x%x origin 0x%x",
				res, err_origin);
		goto out;
	}

	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	params[0].memref.buffer = hwid;
	params[0].memref.size = hwid_len;

	res = TEE_InvokeTACommand(session, 0, PTA_OCOTP_CMD_CHIP_UID,
			exp_param_types, params, &err_origin);
	if (res != TEE_SUCCESS) {
		CAST_TRACE(
				"TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		goto out;
	}

out:
	return res;

}

/**
 * @brief   Exports an RSA Key to PEM format
 *
 * @param[in]  key       Context
 * @param[in]  buf       PEM buffer
 * @param[in]  size      PEM buffer size
 * @param[in]  key_class Key class (plain, black, blob)
 *
 * @retval TEE_SUCCESS              Success
 * @retval TEE_ERROR_OUT_OF_MEMORY  Can't allocate memory for one object
 * @retval TEE_ERROR_BAD_PARAMETERS Bad input parameters
 * @retval TEE_ERROR_BAD_FORMAT     Parameter is in bad format
 * @retval TEE_ERROR_GENERIC        Any other error condition
 */
static TEE_Result castauth_WriteKeyPem(mbedtls_pk_context *key, char *buf,
		size_t size, key_class_t key_class)
{
	unsigned char output_buf[WRAPPED_KEY_DER_MAX_BYTES];
	const char *begin_pem;
	const char *end_pem;
	size_t olen = 0;
	int der_bytes = 0;

	if ((key == NULL) || (buf == NULL) || (size == 0) || (key_class
			>= KEY_CLASS_ALL)) {
		CAST_TRACE("NULL parameter");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Encode in DER first */
	der_bytes = mbedtls_pk_write_key_der(key, output_buf,
			sizeof(output_buf));
	if (der_bytes < 0) {
		CAST_TRACE("Invalid key");
		return TEE_ERROR_BAD_FORMAT;
	}

	if (mbedtls_pk_get_type(key) != MBEDTLS_PK_RSA) {
		CAST_TRACE("Key is not an RSA key");
		return TEE_ERROR_BAD_FORMAT;
	}

	/* Add PEM anchor */
	begin_pem = key_class_pem[key_class].pem_anchor.begin;
	end_pem = key_class_pem[key_class].pem_anchor.end;

	/* Encode to PEM */
	if (mbedtls_pem_write_buffer(begin_pem, end_pem,
			output_buf + sizeof(output_buf) - der_bytes, der_bytes,
			(uint8_t *)buf, size, &olen) != 0) {
		CAST_TRACE("Error encoding key to PEM");
		return TEE_ERROR_GENERIC;
	}
	return TEE_SUCCESS;
}

/**
 * @brief   Exports key bytes from PEM
 *
 * @param[in]  key_pem    Input key in PEM format
 * @param[out] rsa_attrs  RSA attributes
 * @param[in]  key_class  Key class (plain, black, blob)
 *
 * @retval TEE_SUCCESS              Success
 * @retval TEE_ERROR_OUT_OF_MEMORY  Can't allocate memory for one object
 * @retval TEE_ERROR_BAD_PARAMETERS Bad input parameters
 * @retval TEE_ERROR_BAD_FORMAT     Parameter is in bad format
 * @retval TEE_ERROR_GENERIC        Any other error condition
 */
static TEE_Result pem_to_rsa_attr(const char *key_pem,
		struct rsa_attributes *rsa_attrs, key_class_t key_class)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	mbedtls_pem_context pem_ctx;
	size_t use_len = 0;
	uint32_t z;
	char *begin_pem = NULL, *end_pem = NULL;

	/* DER parsing parameters */
	uint8_t *ptr, *end;
	size_t len;
	int version;

	if ((!key_pem) || !(rsa_attrs) || (key_class >= KEY_CLASS_ALL)) {
		CAST_TRACE("Invalid parameter");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Setup PEM context */
	memset(&pem_ctx, 0, sizeof(mbedtls_pem_context));

	mbedtls_pem_init(&pem_ctx);

	/* Set PEM anchor */
	begin_pem = strdup(key_class_pem[key_class].pem_anchor.begin);
	end_pem = strdup(key_class_pem[key_class].pem_anchor.end);

	/* Read PEM then remove line break */
	begin_pem[strlen(begin_pem) - 1] = '\0';
	end_pem[strlen(end_pem) - 1] = '\0';

	if ((mbedtls_pem_read_buffer(&pem_ctx, begin_pem, end_pem,
			(uint8_t *)key_pem, NULL, 0, &use_len)) != 0) {
		CAST_TRACE("Bad key format");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	/*
	 * Parses the RSAPrivateKey (PKCS#1)
	 *
	 *  RSAPrivateKey ::= SEQUENCE {
	 *      version           Version,
	 *      modulus           INTEGER,  -- n
	 *      publicExponent    INTEGER,  -- e
	 *      privateExponent   INTEGER,  -- d
	 *      prime1            INTEGER,  -- p
	 *      prime2            INTEGER,  -- q
	 *      exponent1         INTEGER,  -- d mod (p-1)
	 *      exponent2         INTEGER,  -- d mod (q-1)
	 *      coefficient       INTEGER,  -- (inverse of q) mod p
	 *      otherPrimeInfos   OtherPrimeInfos OPTIONAL
	 *  }
	 */

	ptr = (uint8_t *)pem_ctx.buf;
	end = ptr + pem_ctx.buflen;

	/* Parse DER private key  */
	if (mbedtls_asn1_get_tag(&ptr, end, &len,
			MBEDTLS_ASN1_CONSTRUCTED |
			MBEDTLS_ASN1_SEQUENCE) != 0) {
		CAST_TRACE("Bad key format");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	end = ptr + len;

	/* Parse version */
	if (mbedtls_asn1_get_int(&ptr, end, &version) != 0) {
		CAST_TRACE("Bad key format");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	if (version != 0) {
		CAST_TRACE("Bad key format");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	/* Parse & Import N */
	if (mbedtls_asn1_get_tag(&ptr, end, &len, MBEDTLS_ASN1_INTEGER) != 0) {
		CAST_TRACE("Bad key format");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	for (z = 0; z < len; z++)
		if (ptr[z] != 0)
			break;
	rsa_attrs->n.length = len - z;
	rsa_attrs->n.data = TEE_Malloc(rsa_attrs->n.length, 0);
	if (!rsa_attrs->n.data) {
		CAST_TRACE("Out of memory");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	memcpy(rsa_attrs->n.data, ptr + z, rsa_attrs->n.length);

	ptr += len;

	/* Parse & Import E */
	if (mbedtls_asn1_get_tag(&ptr, end, &len, MBEDTLS_ASN1_INTEGER) != 0) {
		CAST_TRACE("Bad key format");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	for (z = 0; z < len; z++)
		if (ptr[z] != 0)
			break;

	rsa_attrs->e.length = len - z;

	rsa_attrs->e.data = TEE_Malloc(rsa_attrs->e.length, 0);
	if (!rsa_attrs->e.data) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	memcpy(rsa_attrs->e.data, ptr + z, rsa_attrs->e.length);

	ptr += len;

	/* Parse & Import D */
	if (mbedtls_asn1_get_tag(&ptr, end, &len, MBEDTLS_ASN1_INTEGER) != 0) {
		CAST_TRACE("Bad key format");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	for (z = 0; z < len; z++)
		if (ptr[z] != 0)
			break;

	rsa_attrs->d.length = len - z;

	rsa_attrs->d.data = TEE_Malloc(rsa_attrs->d.length, 0);
	if (!rsa_attrs->d.data) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	memcpy(rsa_attrs->d.data, ptr + z, rsa_attrs->d.length);

	ptr += len;

	res = TEE_SUCCESS;

out:
	if (begin_pem)
		TEE_Free(begin_pem);
	if (end_pem)
		TEE_Free(end_pem);
	mbedtls_pem_free(&pem_ctx);
	return res;
}

/**
 * @brief   Construct PEM key form key attributes bytes
 *
 * @param[in]  rsa_attrs  RSA attributes
 * @param[out] outpem     Output key in PEM format
 * @param[in]  key_class  Key class (plain, black, blob)
 *
 * @retval TEE_SUCCESS              Success
 * @retval TEE_ERROR_OUT_OF_MEMORY  Can't allocate memory for one object
 * @retval TEE_ERROR_BAD_PARAMETERS Bad input parameters
 * @retval TEE_ERROR_BAD_FORMAT     Parameter is in bad format
 * @retval TEE_ERROR_GENERIC        Any other error condition
 */
static TEE_Result rsa_attr_to_pem(struct rsa_attributes *rsa_attrs,
char *outpem, key_class_t key_class)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	mbedtls_pk_context pk;
	const mbedtls_pk_info_t *pk_info = NULL;
	mbedtls_rsa_context *rsa = NULL;

	/* Check arguments */
	if ((!rsa_attrs) || (!outpem) || (key_class >= KEY_CLASS_ALL)) {
		CAST_TRACE("Bad parameter");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Initialize RSA context */
	memset(&pk, 0, sizeof(mbedtls_pk_context));
	mbedtls_pk_init(&pk);

	/* Get information associated with the PK type. */
	pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
	if (mbedtls_pk_setup(&pk, pk_info)) {
		CAST_TRACE("Bad key format");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* Check if PK context can do RSA */
	if (mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA) == 0) {
		CAST_TRACE("Bad key format");
		res = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	/* Access the RSA context inside PK context */
	rsa = mbedtls_pk_rsa(pk);
	if (!rsa) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* Import RSA key */
	/* Import N */
	if (mbedtls_mpi_read_binary(&rsa->N, rsa_attrs->n.data,
			rsa_attrs->n.length)) {
		CAST_TRACE("Error reading modulus");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	rsa->len = mbedtls_mpi_size(&rsa->N);

	/* Import D */
	if (mbedtls_mpi_read_binary(&rsa->D, rsa_attrs->d.data,
			rsa_attrs->d.length)) {
		CAST_TRACE("Error reading private exponent");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* Import E */
	if (mbedtls_mpi_read_binary(&rsa->E, rsa_attrs->e.data,
			rsa_attrs->e.length)) {
		CAST_TRACE("Error reading public exponent");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* Check the consistency of public key */
	if (mbedtls_rsa_check_pubkey(rsa) != 0) {
		CAST_TRACE("Bad key format");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* Write private key as PEM format */
	res = castauth_WriteKeyPem(&pk, outpem, MAX_KEY_PEM_SIZE, key_class);
	if (res != TEE_SUCCESS) {
		CAST_TRACE("Error writing key as PEM");
		goto out;
	}

out:
	mbedtls_pk_free(&pk);
	return res;
}

/**
 * @brief   Decrypt a key and export it to black blob
 *
 * @param[in]   enc_key      Encrypted RSA key
 * @param[out]  blob_pem     Output Blob in PEM format
 * @param[out]  blob_pem_len Blob length
 *
 * @retval TEE_SUCCESS              Success
 * @retval TEE_ERROR_OUT_OF_MEMORY  Can't allocate memory for one object
 * @retval TEE_ERROR_BAD_PARAMETERS Bad input parameters
 * @retval TEE_ERROR_BAD_FORMAT     Parameter is in bad format
 * @retval TEE_ERROR_GENERIC        Any other error condition
 */
static TEE_Result castauth_ProvKey(const char *enc_key, char *blob_pem,
		uint32_t blob_pem_len)
{

	TEE_Result res = TEE_ERROR_GENERIC;

	uint8_t *mp_pubkey = NULL;
	uint32_t mp_pubkey_len = MP_PUBKEY_SIZE;

	struct ccm_param_buf {
		uint8_t *buf;
		uint32_t len;
	};

	struct ccm_param_buf ccm_params[4] = {0};

	uint8_t kek[32] = {0};

	char *plain_key = NULL;
	char *black_key = NULL;
	char *blob_key = NULL;
	size_t olen;
	uint32_t ccm_parami = 0;
	char *str = NULL;

	mbedtls_ccm_context ccm_ctx;

	if ((!enc_key) || (!blob_pem)) {
		CAST_TRACE("NULL parameter");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	mbedtls_ccm_init(&ccm_ctx);

	str = strtok1((char *)enc_key, "\n");
	while (str) {
		printf("%s", str);

		/* Decode it */
		mbedtls_base64_decode(NULL, 0, &olen, (uint8_t *)str,
				strlen(str));

		ccm_params[ccm_parami].buf = TEE_Malloc(olen, 0);
		ccm_params[ccm_parami].len = olen;
		if (!ccm_params[ccm_parami].buf) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
		mbedtls_base64_decode(ccm_params[ccm_parami].buf, olen, &olen,
				(uint8_t *)str, strlen(str));

		ccm_parami += 1;

		str = strtok1(NULL, "\n");
	}

	/* Get MP pub key*/
	mp_pubkey = TEE_Malloc(MP_PUBKEY_SIZE, 0);
	if (!mp_pubkey) {
		CAST_TRACE("Error allocating memory");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	res = castauth_mp_pubkey(mp_pubkey, mp_pubkey_len);
	if (res != TEE_SUCCESS) {
		CAST_TRACE("Failed to get MP public key");
		goto out;
	}

	/* Get Derive a key from it */
	mbedtls_sha256(mp_pubkey, mp_pubkey_len - 1, kek, 0);

	/* Decrypt the encrypted key */
	if (mbedtls_ccm_setkey(&ccm_ctx, MBEDTLS_CIPHER_ID_AES, kek,
			sizeof(kek) * 8) != 0) {
		CAST_TRACE("Error setting CCM key");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* Allocate memory for plain key */
	plain_key = TEE_Malloc(ccm_params[CCM_CIPHER_IDX].len, 0);
	if (!plain_key) {
		CAST_TRACE("Out of memory");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	if (mbedtls_ccm_auth_decrypt(&ccm_ctx, ccm_params[CCM_CIPHER_IDX].len,
			ccm_params[CCM_NONCE_IDX].buf,
			ccm_params[CCM_NONCE_IDX].len,
			ccm_params[CCM_HDR_IDX].buf,
			ccm_params[CCM_HDR_IDX].len,
			ccm_params[CCM_CIPHER_IDX].buf, (uint8_t *)plain_key,
			ccm_params[CCM_MAC_IDX].buf,
			ccm_params[CCM_MAC_IDX].len) != 0) {
		CAST_TRACE("Error decrypting key");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* Wrap it into a black key */
	black_key = TEE_Malloc(MAX_KEY_PEM_SIZE, 0);
	if (!black_key) {
		CAST_TRACE("Out of memory");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	res = castauth_WrapKey(plain_key, black_key);
	if (res != TEE_SUCCESS) {
		CAST_TRACE("Error wrapping RSA key to black key");
		goto out;
	}

	blob_key = TEE_Malloc(MAX_KEY_PEM_SIZE, 0);
	if (!blob_key) {
		CAST_TRACE("Error allocating memory for blob");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	/* Export it into a black blob */
	res = castauth_BlobKey(blob_encap, black_key, blob_key);
	if (res != TEE_SUCCESS) {
		CAST_TRACE("Error exporting RSA black key to blob");
		goto out;
	}

	/* Return the blob */
	strncpy(blob_pem, blob_key, blob_pem_len);

out:
	if (mp_pubkey)
		TEE_Free(mp_pubkey);
	if (plain_key)
		TEE_Free(plain_key);
	if (black_key)
		TEE_Free(black_key);
	if (blob_key)
		TEE_Free(blob_key);
	mbedtls_ccm_free(&ccm_ctx);
	return res;

}

/**
 * @brief   Generates an RSA Key-pair
 *
 * @param[out]  private_key      Wrapped private key in PEM format
 * @param[out]  private_key_len  Private key length
 * @param[out]  public_key       Public key in PEM format
 * @param[out]  public_key_len   Public key length
 *
 * @retval TEE_SUCCESS              Success
 * @retval TEE_ERROR_NOT_SUPPORTED  The context does not support RSA
 * @retval TEE_ERROR_OUT_OF_MEMORY  Can't allocate memory for one object
 * @retval TEE_ERROR_BAD_PARAMETERS Bad input parameters
 * @retval TEE_ERROR_BAD_FORMAT     Bad key format
 * @retval TEE_ERROR_GENERIC        Any other error condition
 */
static TEE_Result castauth_GenKeyPair(char *private_key,
uint32_t private_key_len, char *public_key, uint32_t public_key_len)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	mbedtls_pk_context pk;
	mbedtls_rsa_context *rsa = NULL;
	const mbedtls_pk_info_t *pk_info = NULL;
	struct dbuf e = {0};
	struct dbuf d = {0};
	struct dbuf n = {0};
	int ret = 0;
	char *key_pem = NULL;

	TEE_ObjectHandle key = (TEE_ObjectHandle)NULL;

	if ((!private_key) || (!public_key)) {
		CAST_TRACE("NULL parameter");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	d.length = CAST_AUTH_KEY_SIZE;
	e.length = sizeof(cast_pubexp);
	n.length = CAST_AUTH_KEY_SIZE;

	/* Allocate memory for (d,e,n)*/
	d.data = TEE_Malloc(d.length, 0);
	e.data = TEE_Malloc(e.length, 0);
	n.data = TEE_Malloc(n.length, 0);

	if (!(d.data) || !(e.data) || !(n.data)) {
		CAST_TRACE("Out of memory");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* Generate the RSA key pair */
	res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR,
			CAST_AUTH_KEY_SIZE * 8, &key);
	if (res != TEE_SUCCESS) {
		CAST_TRACE("AllocateTransientObject failed, res: 0x%x", res);
		goto out;
	}

	res = TEE_GenerateKey(key, CAST_AUTH_KEY_SIZE * 8, NULL, 0);
	if (res != TEE_SUCCESS) {
		CAST_TRACE("TEE_GenerateKey failed, res: 0x%x", res);
		goto out;
	}

	/* Get the private exponent as an octet string */
	res = TEE_GetObjectBufferAttribute(key, TEE_ATTR_RSA_PRIVATE_EXPONENT,
			d.data, &d.length);
	if (res != TEE_SUCCESS) {
		CAST_TRACE(
				"TEE_GetObjectBufferAttribute (d) failed, res: 0x%x",
				res);
		goto out;
	}

	/* Get the modulus as an octet string */
	res = TEE_GetObjectBufferAttribute(key, TEE_ATTR_RSA_MODULUS, n.data,
			&n.length);
	if (res != TEE_SUCCESS) {
		CAST_TRACE(
				"TEE_GetObjectBufferAttribute (n) failed, res: 0x%x",
				res);
		goto out;
	}

	/* Get the public exponent as an octet string */
	res = TEE_GetObjectBufferAttribute(key, TEE_ATTR_RSA_PUBLIC_EXPONENT,
			e.data, &e.length);
	if (res != TEE_SUCCESS) {
		CAST_TRACE(
				"TEE_GetObjectBufferAttribute (e) failed, res: 0x%x",
				res);
		goto out;
	}

	/* Initialize RSA context */
	memset(&pk, 0, sizeof(mbedtls_pk_context));
	mbedtls_pk_init(&pk);

	/* Get information associated with the PK type. */
	pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
	if (mbedtls_pk_setup(&pk, pk_info)) {
		CAST_TRACE("Bad key format");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* Check if PK context can do RSA */
	ret = mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA);
	if (ret == 0) {
		CAST_TRACE("Context can't do RSA");
		res = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	/* Access the RSA context inside PK context */
	rsa = mbedtls_pk_rsa(pk);
	if (!rsa) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* Import RSA key */
	/* Import N */
	if (mbedtls_mpi_read_binary(&rsa->N, n.data, n.length)) {
		CAST_TRACE("Error reading modulus");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	rsa->len = mbedtls_mpi_size(&rsa->N);

	/* Import D */
	if (mbedtls_mpi_read_binary(&rsa->D, d.data, d.length)) {
		CAST_TRACE("Error reading private exponent");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* Import E */
	if (mbedtls_mpi_read_binary(&rsa->E, e.data, e.length)) {
		CAST_TRACE("Error reading public exponent");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* Check the consistency of public key */
	ret = mbedtls_rsa_check_pubkey(rsa);
	if (ret != 0) {
		CAST_TRACE("Bad key format");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	/* Allocate a temporary buffer to encode keys in PEM */
	key_pem = TEE_Malloc(MAX_KEY_PEM_SIZE, 0);
	if (!key_pem) {
		CAST_TRACE("Out of memory");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	/* Write public key as PEM format */
	if (mbedtls_pk_write_pubkey_pem(&pk, (uint8_t *)key_pem,
			MAX_KEY_PEM_SIZE) != 0) {
		CAST_TRACE("Error writing public key as PEM");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	public_key_len = strlen((char *)key_pem) + 1;
	memcpy(public_key, key_pem, public_key_len);

	/* Write private key as PEM format */
	if (mbedtls_pk_write_key_pem(&pk, (uint8_t *)key_pem, MAX_KEY_PEM_SIZE)
			!= 0) {
		CAST_TRACE("Error writing private key as PEM");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	private_key_len = strlen((char *)key_pem) + 1;
	memcpy(private_key, key_pem, private_key_len);

out:
	mbedtls_pk_free(&pk);
	if (d.data)
		TEE_Free(d.data);
	if (e.data)
		TEE_Free(e.data);
	if (n.data)
		TEE_Free(n.data);
	if (key_pem != NULL)
		TEE_Free(key_pem);

	return res;
}

/**
 * @brief   Sign a hash using a black RSA key in TA
 *
 * @param[in]  key_pem    Wrapped private key in PEM format
 * @param[in]  hash       Hash to sign
 * @param[in]  hash_len   Hash size
 * @param[out] outsig     Signature output
 * @param[out] outsig_len Signature length
 *
 * @retval TEE_SUCCESS              Success
 * @retval TEE_ERROR_NOT_SUPPORTED  The context does not support RSA
 * @retval TEE_ERROR_OUT_OF_MEMORY  Can't allocate memory for one object
 * @retval TEE_ERROR_BAD_PARAMETERS Bad input parameters
 * @retval TEE_ERROR_BAD_FORMAT     Format is in a bad format
 * @retval TEE_ERROR_GENERIC        Any other error condition
 */
static TEE_Result castauth_SignHash(const char *key_pem, uint8_t *hash,
		uint32_t hash_len, uint8_t *outsig, uint32_t outsig_len)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	TEE_TASessionHandle session;
	TEE_UUID uuid = PTA_BK_PTA_UUID;
	uint32_t err_origin;
	uint32_t exp_param_types;
	TEE_Param params[TEE_NUM_PARAMS] = {0};
	struct rsa_attributes rsa = {0};
	uint8_t hash_p[CAST_AUTH_KEY_SIZE] = {0};
	uint32_t hash_p_len = sizeof(hash_p);
	struct pta_bk_buf key[2] = {0};

	/* Check input arguments */
	if (!key_pem || !hash || !outsig) {
		CAST_TRACE("NULL parameter");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Parse input key */
	if (pem_to_rsa_attr(key_pem, &rsa, KEY_CLASS_BLACK) != TEE_SUCCESS) {
		CAST_TRACE("Bad key format");
		return TEE_ERROR_BAD_FORMAT;
	}

	/*
	 * openning session with PTA
	 * in this case the TA plays the role of the CA
	 */
	res = TEE_OpenTASession(&uuid, 0, 0, NULL, &session, &err_origin);
	if (res != TEE_SUCCESS) {
		CAST_TRACE(
				"TEE open session failed with code 0x%x origin 0x%x",
				res, err_origin);
		goto out;
	}

	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_INOUT);

	/* Pad the Hash */
	res = castauth_add_pkcs1_type1_padding(hash_p, hash_p_len, hash,
			hash_len);
	if (res != TEE_SUCCESS) {
		CAST_TRACE("Error padding hash");
		goto out;
	}

	/* params[0] represents the algo id and black key type */
	/* params[1] represents the key components */
	/* params[2] represents the hash */
	/* params[3] represents the signature */

	params[0].value.a = IMX_CRYPT_ALG_RSA;
	params[0].value.b = PTA_BK_ECB;

	key[0].length = rsa.d.length;
	key[0].data = rsa.d.data;

	key[1].length = rsa.n.length;
	key[1].data = rsa.n.data;

	params[1].memref.buffer = key;
	params[1].memref.size = sizeof(key);

	params[2].memref.buffer = hash_p;
	params[2].memref.size = hash_p_len;

	params[3].memref.buffer = outsig;
	params[3].memref.size = outsig_len;

	/* Sign in PTA */
	res = TEE_InvokeTACommand(session, 0, PTA_BK_CMD_SIGN, exp_param_types,
			params, &err_origin);
	if (res != TEE_SUCCESS) {
		CAST_TRACE(
				"TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		goto out;
	}

	res = TEE_SUCCESS;
out:
	TEE_CloseTASession(session);
	return res;
}

/**
 * @brief   Pad a buffer using PKCS1 type 1 padding.
 *
 * @param[in]  to    padded buffer
 * @param[in]  tlen  padded buffer length
 * @param[in]  from  unpadded buffer
 * @param[in]  flen  unpadded buffer length
 *
 * @retval TEE_SUCCESS                Success
 * @retval TEE_ERROR_BAD_PARAMETERS   Bad parameters
 */
static TEE_Result castauth_add_pkcs1_type1_padding(uint8_t *to,
unsigned int tlen, const uint8_t *from, unsigned int flen)
{

	TEE_Result res = TEE_SUCCESS;
	unsigned int j;
	uint8_t *p;

	if (!to || !from)
		return (res = TEE_ERROR_BAD_PARAMETERS);

	if (tlen < RSA_PKCS1_PADDING_SIZE)
		return (res = TEE_ERROR_BAD_PARAMETERS);

	if (flen > tlen - RSA_PKCS1_PADDING_SIZE)
		return (res = TEE_ERROR_BAD_PARAMETERS);

	p = (uint8_t *)to;
	*(p++) = 0;
	*(p++) = 1; /* Private Key BT (Block Type) */
	/* pad out with 0xff data */
	j = tlen - 3 - flen;
	memset(p, 0xff, j);
	p += j;
	*(p++) = 0;
	memcpy(p, from, (unsigned int)flen);
	return (res = TEE_SUCCESS);
}

/**
 * @brief   Locate a substring
 *
 * @param[in]  haystack Haystack
 * @param[in]  hl Haystack length
 * @param[in]  needle Needle
 * @param[out] nl Needle length
 *
 * @retval Pointer to the beginning of the substring,
 * NULL if NULL if the substring is not found
 */
static uint8_t *memmem(const uint8_t *haystack, size_t hl,
	const uint8_t *needle, size_t nl)
{
	int i;

	if (nl > hl)
		return NULL;
	for (i = hl - nl + 1; i; --i) {
		if (!memcmp(haystack, needle, nl))
			return (uint8_t *)haystack;
		++haystack;
	}
	return NULL;
}

static char *strtok1(char *str, const char *delimiters)
{

	int i = 0;
	char *p_start = NULL;
	int len;

	len = strlen(delimiters);

	/* check in the delimiters */
	if (len == 0)
		printf("delimiters are empty\n");

	/* if the original string has nothing left */
	if (!str && !sp)
		return NULL;

	/* initialize the sp during the first call */
	if (str && !sp)
		sp = str;

	/* find the start of the substring, skip delimiters */
	p_start = sp;
	while (true) {
		for (i = 0; i < len; i++) {
			if (*p_start == delimiters[i]) {
				p_start++;
				break;
			}
		}

		if (i == len) {
			sp = p_start;
			break;
		}
	}

	/* return NULL if nothing left */
	if (*sp == '\0') {
		sp = NULL;
		return sp;
	}

	/*
	* find the end of the substring, and
	* replace the delimiter with null
	*/
	while (*sp != '\0') {
		for (i = 0; i < len; i++) {
			if (*sp == delimiters[i]) {
				*sp = '\0';
				break;
			}
		}

		sp++;
		if (i < len)
			break;
	}

	return p_start;
}

/**
 * @brief   TA Generate RSA Key-pair.
 *
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 *
 * @retval TEE_SUCCESS                Success
 * @retval TEE_ERROR_BAD_PARAMETERS   Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY    Out of memory
 */
static TEE_Result TA_CastAuthGenKeypair(uint32_t param_types,
		TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		CAST_TRACE("Bad parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	/*
	 * params[0] represents the private key in PEM format
	 * params[1] represents the public key in PEM format
	 */
	return castauth_GenKeyPair(params[0].memref.buffer,
			params[0].memref.size, params[1].memref.buffer,
			params[1].memref.size);
}

/**
 * @brief   Cast Sign Hash.
 *
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 *
 * @retval TEE_SUCCESS                Success
 * @retval TEE_ERROR_BAD_PARAMETERS   Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY    Out of memory
 */
static TEE_Result TA_CastAuthSignHash(uint32_t param_types,
		TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		CAST_TRACE("Bad parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/*
	 * params[0] represents the device black key
	 * params[1] represents the hash
	 * params[2] represents the signature
	 */
	return castauth_SignHash(params[0].memref.buffer,
			params[1].memref.buffer, params[1].memref.size,
			params[2].memref.buffer, params[2].memref.size);
}

/**
 * @brief   TA Provision the device with its key.
 *
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 *
 * @retval TEE_SUCCESS                Success
 * @retval TEE_ERROR_BAD_PARAMETERS   Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY    Out of memory
 */
static TEE_Result TA_CastAuthProvDevKey(uint32_t param_types,
		TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		CAST_TRACE("Bad parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/*
	 * params[0] represents the encrypted device key
	 * params[1] represents the output device key as blob
	 */

	return castauth_ProvKey(params[0].memref.buffer,
			params[1].memref.buffer, params[1].memref.size);

}

/**
 * @brief   TA Generate Device key and certificate from model certificate.
 *
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 *
 * @retval TEE_SUCCESS                Success
 * @retval TEE_ERROR_BAD_PARAMETERS   Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY    Out of memory
 */
static TEE_Result TA_CastAuthGenDevKeyCert(uint32_t param_types,
		TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_INOUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT);

	if (param_types != exp_param_types) {
		CAST_TRACE("Bad parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	/*
	 * params[0] represents the BSS Id
	 * params[1] represents the Model key
	 * params[2] represents the template/device certificate
	 * params[3] represents the device key
	 */
	return castauth_GenDevKeyCert(params[0].memref.buffer,
			params[0].memref.size, params[1].memref.buffer,
			params[1].memref.size, params[2].memref.buffer,
			params[2].memref.size, params[3].memref.buffer,
			params[3].memref.size);
}

/**
 * @brief   TA Wrap Key.
 *
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 *
 * @retval TEE_SUCCESS                Success
 * @retval TEE_ERROR_BAD_PARAMETERS   Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY    Out of memory
 */
static TEE_Result TA_CastAuthWrapKey(uint32_t param_types,
		TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		CAST_TRACE("Bad parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	/*
	 * params[0] represents the private key in PEM format
	 * params[1] represents the black key in PEM format
	 */
	return castauth_WrapKey(params[0].memref.buffer,
			params[1].memref.buffer);
}

/**
 * @brief   TA Export Key.
 *
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 *
 * @retval TEE_SUCCESS                Success
 * @retval TEE_ERROR_BAD_PARAMETERS   Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY    Out of memory
 */
static TEE_Result TA_CastAuthExportKey(uint32_t param_types,
		TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		CAST_TRACE("Bad parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	/*
	 * params[0] represents the black key in PEM format
	 * params[1] represents the output blob key in PEM format
	 */
	return castauth_BlobKey(blob_encap, params[0].memref.buffer,
			params[1].memref.buffer);
}

/**
 * @brief   TA Export Key.
 *
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 *
 * @retval TEE_SUCCESS                Success
 * @retval TEE_ERROR_BAD_PARAMETERS   Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY    Out of memory
 */
static TEE_Result TA_CastAuthImportKey(uint32_t param_types,
		TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		CAST_TRACE("Bad parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	/*
	 * params[0] represents the Blob private key in PEM format
	 * params[1] represents the output black key in PEM format
	 */
	return castauth_BlobKey(blob_decap, params[0].memref.buffer,
			params[1].memref.buffer);
}

/**
 * @brief   TA Get Manufacturing Protection Public Key.
 *
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 *
 * @retval TEE_SUCCESS                Success
 * @retval TEE_ERROR_BAD_PARAMETERS   Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY    Out of memory
 */
static TEE_Result TA_CastAuthGetMPPubkey(uint32_t param_types,
		TEE_Param params[TEE_NUM_PARAMS])
{

	uint32_t exp_param_types = TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		CAST_TRACE("Bad parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	/*
	 * params[0] represents the MP public key in PEM format
	 */
	return castauth_MPPubKey(
	params[0].memref.buffer,
	params[0].memref.size);
}

/**
 * @brief   TA Get Manufacturing Protection Public Key.
 *
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 *
 * @retval TEE_SUCCESS                Success
 * @retval TEE_ERROR_BAD_PARAMETERS   Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY    Out of memory
 */
static TEE_Result TA_CastAuthGetHwId(uint32_t param_types,
		TEE_Param params[TEE_NUM_PARAMS])
{

	uint32_t exp_param_types = TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		CAST_TRACE("Bad parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	/*
	 * params[0] represents the Hardware Unique Id
	 */
	return castauth_GetHwId(params[0].memref.buffer, params[0].memref.size);
}

/**
 * @brief   First call in the TA.\n
 *          Called when the instance of the TA is created.
 *
 * @retval  TEE_SUCCESS   Success
 */
TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

/**
 * @brief   Last call in the TA.\n
 *          Called when the instance of the TA is destroyed.
 */
void TA_EXPORT TA_DestroyEntryPoint(void)
{
}

/**
 * @brief   Called when a new session is opened to the TA.
 *
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 * @param[in]  sess_ctx       Session Identifier
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 */
TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param params[TEE_NUM_PARAMS] __maybe_unused,
		void **sess_ctx __maybe_unused)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* If return value != TEE_SUCCESS the session will not be created. */
	CAST_TRACE("TA_OpenSessionEntryPoint success");
	return TEE_SUCCESS;
}

/**
 * @brief   Called when a session is closed.
 *
 * @param[in]  sess_ctx       Session Identifier
 */
void TA_EXPORT TA_CloseSessionEntryPoint(void *sess_ctx __maybe_unused)
{
}

/**
 * @brief   Called when a TA is invoked.
 *
 * @param[in]  sess_ctx       Session Identifier
 * @param[in]  cmd_id         Command ID
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 *
 * @retval TEE_SUCCESS		        Success
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 */
TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sess_ctx __maybe_unused,
uint32_t cmd_id, uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {

	case TA_CASTAUTH_CMD_PROV_DEV_KEY:
		return TA_CastAuthProvDevKey(param_types, params);

	case TA_CASTAUTH_CMD_GEN_DEV_KEY_CERT:
		return TA_CastAuthGenDevKeyCert(param_types, params);

	case TA_CASTAUTH_CMD_GEN_KEYPAIR:
		return TA_CastAuthGenKeypair(param_types, params);

	case TA_CASTAUTH_CMD_WRAP_KEY:
		return TA_CastAuthWrapKey(param_types, params);

	case TA_CASTAUTH_CMD_EXPORT_KEY:
		return TA_CastAuthExportKey(param_types, params);

	case TA_CASTAUTH_CMD_IMPORT_KEY:
		return TA_CastAuthImportKey(param_types, params);

	case TA_CASTAUTH_CMD_SIGN_HASH:
		return TA_CastAuthSignHash(param_types, params);

	case TA_CASTAUTH_CMD_GET_MP_PUBKEY:
		return TA_CastAuthGetMPPubkey(param_types, params);

	case TA_CASTAUTH_CMD_GET_HW_ID:
		return TA_CastAuthGetHwId(param_types, params);

	default:
		CAST_TRACE("Command ID 0x%08x is not supported", cmd_id);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
