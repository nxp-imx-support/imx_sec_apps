// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    cast_auth_imx.c
 *
 * @brief   Cast Authentication aspects implementation on i.MX.
 */

/* Standard includes */
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* Library tee includes */
#include <tee_client_api.h>
#include <tee_client_api_extensions.h>

/* Local includes */
#include <imx_cast_auth_ta.h>
#include <imx_cast_auth_ca.h>

#define CASTAUTH_MODEL_CRT_ENV "CAST_MODEL_CHAIN"
#define CASTAUTH_MODEL_KEY_ENV "CAST_MODEL_PRIVKEY"

#define CASTAUTH_MODEL_CRT_PATH "/factory/model.crt"
#define CASTAUTH_MODEL_KEY_PATH "/factory/model.key.bin"

#define BSS_ID_SIZE 17
#define CERT_DER_SIZE 977
#define MAX_KEY_PEM_SIZE 2048
#define MAX_CERT_PEM_SIZE 8192

void __attribute__((constructor)) castauth_init();
void __attribute__((destructor)) castauth_exit();

/* Prototypes */

static void castauth_fini_session(TEEC_Session *sess);
static TEEC_Session *castauth_get_session();

static TEEC_Context ctx;
static TEEC_Session *g_session;

/** @brief Finish TEE session.
 *
 *  This function destroys current session.
 */
static void castauth_fini_session(TEEC_Session *sess)
{
	/* Close the session */
	TEEC_CloseSession(sess);

	/* Destroy the context */
	TEEC_FinalizeContext(&ctx);

	/* Free the session buffer */
	if (sess)
		free(sess);
}

/** @brief Convert TEE status code to local code.
 *
 *  This function converts TEE status code to local
 *  status code. For now it returns false if success.
 *  and true if error.
 *
 * @return false if success, true otherwise.
 */
static int castauth_error(TEEC_Result err)
{
	return (err != TEEC_SUCCESS);
}

/** @brief Get session handler.
 *
 *  This function retrieves the session handler.
 *  It creates a new session if not initialized.
 *
 * @return pointer to session handler.
 */
static TEEC_Session *castauth_get_session()
{
	TEEC_Result res;
	TEEC_UUID uuid = TA_CAST_AUTH_UUID;
	uint32_t err_origin;

	if (g_session != NULL)
		return g_session;

	g_session = malloc(sizeof(TEEC_Session));
	if (!g_session) {
		errx(1, "Error getting session handler");
		goto out;
	}
	memset(g_session, 0, sizeof(TEEC_Session));

	/* Initialize a context connecting to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
		free(g_session);
		g_session = NULL;
		goto out;
	}

	/* open a session with the TA */
	res = TEEC_OpenSession(&ctx, g_session, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
				res, err_origin);
		TEEC_FinalizeContext(&ctx);
		free(g_session);
		g_session = NULL;
	}

out: return g_session;
}

/** @brief Retrieve the wrapped model key.
 *
 *  This function retrieves the wrapped model key
 *  from the file system. Th path to the key is defined
 *  by CAST_MODEL_PRIVKEY environment variable.
 *  Output Key is in PEM format. User should allocate
 *  enough memory space for key to hold the result.
 *
 * @return pointer to key. NULL if error.
 */
char *castauth_GetModelKey()
{
	int fkey = -1;
	off_t flen;
	const char *cckey = NULL;
	char *key = NULL;

	const char *model_key_path = getenv(CASTAUTH_MODEL_KEY_ENV);

	if (!model_key_path)
		model_key_path = CASTAUTH_MODEL_KEY_PATH;

	key = malloc(MAX_KEY_PEM_SIZE);
	if (!key) {
		errx(1, "Out of memory\n");
		return NULL;
	}

	memset(key, 0, MAX_KEY_PEM_SIZE);

	fkey = open(model_key_path, O_RDONLY);
	if (fkey < 0) {
		errx(1, "Error reading %s\n", model_key_path);
		free(key);
		return NULL;
	}
	flen = lseek(fkey, 0, SEEK_END);

	cckey = mmap(NULL, flen, PROT_READ, MAP_SHARED, fkey, 0);
	strcpy(key, cckey);
	munmap((void *)cckey, flen);
	close(fkey);

	return key;
}

/** @brief Retrieve the model certificate chain.
 *
 *  This function retrieves the certificate chain linking
 *  the device certificate template through the model RSA key up
 *  to the Cast Root CA. The chain is a series of concatenated X.509
 *  certificates in PEM format,
 *  starting with the device certificate template and ending
 *  with Cast audio root.
 *  The path to the certificate is defined
 *  by CASTAUTH_MODEL_CRT_ENV environment variable.
 *  Output Cert is in PEM format. User should allocate
 *  enough memory space for cert to hold the result.
 *
 * @return pointer to cert. NULL if error.
 */
char *castauth_GetModelCertChain()
{
	int fcert = -1;
	off_t flen;
	const char *ccert = NULL;
	char *cert = NULL;

	const char *model_cert_path = getenv(CASTAUTH_MODEL_CRT_ENV);

	if (!model_cert_path)
		model_cert_path = CASTAUTH_MODEL_CRT_PATH;

	cert = malloc(MAX_CERT_PEM_SIZE);
	if (!cert) {
		errx(1, "Out of memory\n");
		return NULL;
	}
	memset(cert, 0, MAX_CERT_PEM_SIZE);

	fcert = open(model_cert_path, O_RDONLY);
	if (fcert < 0) {
		errx(1, "Error reading %s\n", model_cert_path);
		free(cert);
		return NULL;
	}
	flen = lseek(fcert, 0, SEEK_END);

	ccert = mmap(NULL, flen, PROT_READ, MAP_SHARED, fcert, 0);
	strcpy(cert, ccert);
	munmap((void *)ccert, flen);
	close(fcert);

	return cert;
}

/** @brief Sign a Hash.
 *
 *  This function signs a hash using the wrapped client private key.
 *  The supplied hash should be encoded, have the ASN.1 DER prefix
 *  that identifies the hash type pretended.
 *  This function is responsible for padding the supplied hash uisng
 *  PKCS1 type1 padding.
 *  Output signature is 256 byte value.
 *
 * @return 0 if success other value if error.
 */
int castauth_SignHash(const char *inkey, uint8_t *hash, uint32_t hash_len,
		uint8_t *sig, uint32_t sig_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op;
	uint32_t err_origin;

	char *bkey = NULL;
	TEEC_Session *sess = NULL;

	if (!inkey) {
		errx(1, "NULL arguments");
		return castauth_error(TEEC_ERROR_BAD_PARAMETERS);
	}

	sess = castauth_get_session();
	if (!sess) {
		errx(1, "Error getting session\n");
		return castauth_error(res);
	}

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
			TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
			TEEC_NONE);

/* CAAM implements different types of blobs that are intended for storage
 * of keys across power cycles. Because encapsulation or decapsulation
 * of blobs takes longer than encapsulation and decapsulation of black keys,
 * if a long-term in_key is stored in a blob and must be used multiple times
 * during a power-on session, for performance reasons it is preferable
 * to decapsulate the blob at power-up and reencapsulate the in_key as
 * a black in_key. In this implementation we check if the input in_key type
 * is a BLACK BLOB or BLACK in_key. If it is a black blob then import it to
 * a black in_key. If it is a black in_key then use it directly. **/

	if (strncmp(inkey, PEM_BEGIN_PRIVATE_KEY_BLOB,
			strlen(PEM_BEGIN_PRIVATE_KEY_BLOB) - 1) == 0) {
		/* It is a black blob, import it */
		bkey = castauth_ImportKey(inkey);
		if (bkey == NULL) {
			errx(1, "Error castauth_ImportKey");
			return castauth_error(TEEC_ERROR_BAD_FORMAT);
		}
		op.params[0].tmpref.buffer = (char *)bkey;
		op.params[0].tmpref.size = strlen(bkey) + 1;
	} else {
		op.params[0].tmpref.buffer = (char *)inkey;
		op.params[0].tmpref.size = strlen(inkey) + 1;
	}

	op.params[1].tmpref.buffer = (void *)hash;
	op.params[1].tmpref.size = hash_len;

	op.params[2].tmpref.buffer = (void *)sig;
	op.params[2].tmpref.size = sig_len;

	/**
	 * params[0] represents the wrapped device in_key in pem format
	 * params[1] represents the hash
	 * params[2] represents the signature
	 */

	res = TEEC_InvokeCommand(sess, TA_CASTAUTH_CMD_SIGN_HASH, &op,
			&err_origin);
	if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		if (bkey != NULL)
			free(bkey);
		return castauth_error(res);
	}
	if (bkey != NULL)
		free(bkey);

	return castauth_error(res);
}

/** @brief Import a Black RSA Blob.
 *
 *  This function imports a RSA black key blob to a RSA black key.
 *  Key configuration which was used to generate the blob is not
 *  included in the key.The API exported the key should be used to import it.
 *	The result is a black key in PEM format.
 *
 * @return pointer to black key. NULL if error.
 */
char *castauth_ImportKey(const char *in_key)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;

	TEEC_Operation op;
	uint32_t err_origin;

	TEEC_Session *sess = NULL;

	char *out_key = NULL;

	if (!in_key) {
		errx(1, "NULL arguments");
		return NULL;
	}

	sess = castauth_get_session();

	if (!sess) {
		errx(1, "Error getting session\n");
		return NULL;
	}

	out_key = malloc(MAX_KEY_PEM_SIZE);

	if (!out_key) {
		errx(1, "Out of memory\n");
		return NULL;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
			TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);

	/*
	 * params[0] represents the private key in PEM format
	 * params[1] represents the wrapped private key in PEM format
	 */

	op.params[0].tmpref.buffer = (char *)in_key;
	op.params[0].tmpref.size = strlen(in_key) + 1;

	op.params[1].tmpref.buffer = out_key;
	op.params[1].tmpref.size = MAX_KEY_PEM_SIZE;

	res = TEEC_InvokeCommand(sess, TA_CASTAUTH_CMD_IMPORT_KEY, &op,
			&err_origin);

	if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		free(out_key);
		return NULL;
	}

	return out_key;
}

/** @brief Export a Black RSA Key.
 *
 *  This function exports a RSA black key to a RSA black blob.
 *  Key configuration which was used to generate the blob is not included
 *  in the output blob. The API importing the blob should be used to import
 *  back the key. The result is a RSA black blob in PEM format.
 *
 * @return pointer to blob. NULL if error.
 */
char *castauth_ExportKey(const char *in_key)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;

	TEEC_Operation op;
	uint32_t err_origin;

	TEEC_Session *sess = NULL;

	char *out_key = NULL;

	if (!in_key) {
		errx(1, "NULL arguments");
		return NULL;
	}

	sess = castauth_get_session();

	if (!sess) {
		errx(1, "Error getting session\n");
		return NULL;
	}

	out_key = malloc(MAX_KEY_PEM_SIZE);

	if (!out_key) {
		errx(1, "Out of memory\n");
		return NULL;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
			TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);

	/*
	 * params[0] represents the private key in PEM format
	 * params[1] represents the wrapped private key in PEM format
	 */

	op.params[0].tmpref.buffer = (char *)in_key;
	op.params[0].tmpref.size = strlen(in_key) + 1;

	op.params[1].tmpref.buffer = out_key;
	op.params[1].tmpref.size = MAX_KEY_PEM_SIZE;

	res = TEEC_InvokeCommand(sess, TA_CASTAUTH_CMD_EXPORT_KEY, &op,
			&err_origin);

	if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		free(out_key);
		return NULL;
	}

	return out_key;
}

/** @brief Wraps a plain RSA Key into a Black RSA key.
 *
 *  This function wraps a RSA plain key to an RSA black key.
 *  Key configuration which was used to generate the black key is not included
 *  in the output black key.
 *
 *	The result is a RSA black key in PEM format.
 *
 * @return pointer to black key. NULL if error.
 */
char *castauth_WrapKey(const char *in_key)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;

	TEEC_Operation op;
	uint32_t err_origin;

	char *out_key = NULL;

	TEEC_Session *sess = NULL;

	if (!in_key) {
		errx(1, "NULL arguments");
		return NULL;
	}

	sess = castauth_get_session();

	if (!sess) {
		errx(1, "Error getting session\n");
		return NULL;
	}

	out_key = malloc(MAX_KEY_PEM_SIZE);

	if (!out_key) {
		errx(1, "Out of memory\n");
		return NULL;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
			TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);

	/*
	 * params[0] represents the private key in PEM format
	 * params[1] represents the wrapped private key in PEM format
	 */

	op.params[0].tmpref.buffer = (char *)in_key;
	op.params[0].tmpref.size = strlen(in_key) + 1;

	op.params[1].tmpref.buffer = out_key;
	op.params[1].tmpref.size = MAX_KEY_PEM_SIZE;

	res = TEEC_InvokeCommand(sess, TA_CASTAUTH_CMD_WRAP_KEY, &op,
			&err_origin);

	if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		free(out_key);
		return NULL;
	}

	return out_key;
}

/** @brief Generate an RSA key-pair.
 *
 *  This function generates an RSA key-pair.
 *  The output private key and public key are PEM encoded.
 *
 * @return pointer to key if success. NULL if error.
 */
char *castauth_GenKeyPair()
{
	TEEC_Result res = TEEC_ERROR_GENERIC;

	TEEC_Operation op;
	uint32_t err_origin;

	TEEC_Session *sess = NULL;

	char *priv_key = NULL;
	char *pub_key = NULL;

	sess = castauth_get_session();

	if (!sess) {
		errx(1, "Error getting session\n");
		return NULL;
	}

	priv_key = malloc(MAX_KEY_PEM_SIZE);
	pub_key = malloc(MAX_KEY_PEM_SIZE);

	if ((!priv_key) || (!pub_key)) {
		errx(1, "Out of memory\n");
		return NULL;
	}

	memset(priv_key, 0, MAX_KEY_PEM_SIZE);
	memset(pub_key, 0, MAX_KEY_PEM_SIZE);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
			TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = priv_key;
	op.params[0].tmpref.size = MAX_KEY_PEM_SIZE;
	op.params[1].tmpref.buffer = pub_key;
	op.params[1].tmpref.size = MAX_KEY_PEM_SIZE;

	res = TEEC_InvokeCommand(sess, TA_CASTAUTH_CMD_GEN_KEYPAIR, &op,
			&err_origin);
	if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		free(priv_key);
		free(pub_key);
		return NULL;
	}
	/*We don't need the publoc key */
	free(pub_key);
	return priv_key;
}

/** @brief Provision a Device key.
 *
 *  This function takes an encrypted RSA plain key generated on a host
 *  decrypt it then turns it into a black key which can be stored in
 *  the file system.
 *
 * @return pointer to blob if success, NULL if error.
 */
char *castauth_ProvKey(const char *key)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op;
	uint32_t err_origin;
	TEEC_Session *sess = NULL;

	char *blob = NULL;

	if (!key) {
		errx(1, "NULL arguments");
		return NULL;
	}

	sess = castauth_get_session();

	if (!sess) {
		errx(1, "Error getting session\n");
		return NULL;
	}

	blob = malloc(MAX_KEY_PEM_SIZE);
	if (!blob) {
		errx(1, "Out of memory\n");
		return NULL;
	}

	memset(blob, 0, MAX_KEY_PEM_SIZE);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
			TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = (char *)key;
	op.params[0].tmpref.size = strlen(key) + 1;

	op.params[1].tmpref.buffer = blob;
	op.params[1].tmpref.size = MAX_KEY_PEM_SIZE;

	res = TEEC_InvokeCommand(sess, TA_CASTAUTH_CMD_PROV_DEV_KEY, &op,
			&err_origin);
	if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		free(blob);
		return NULL;
	}

	return blob;
}

/** @brief Generate device key and certificate.
 *
 * @return 0 if success other value if error.
 */
int castauth_GenDevKeyCert(const char *bss_id, uint32_t bss_id_len,
		uint8_t *cert_temp, uint32_t cert_temp_len, char **key)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op;
	uint32_t err_origin;
	TEEC_Session *sess = NULL;

	char *model_blob = NULL;
	char *model_key = NULL;
	char *device_key = NULL;

	sess = castauth_get_session();

	if (!bss_id || !cert_temp) {
		errx(1, "NULL arguments");
		return castauth_error(TEEC_ERROR_BAD_PARAMETERS);
	}

	if (!sess) {
		errx(1, "Error getting session\n");
		return castauth_error(res);
	}

	/* Read the blob from the filesystem */
	model_blob = castauth_GetModelKey();
	if (!model_blob) {
		errx(1, "Error reading model key\n");
		return castauth_error(res);
	}
	/* Import it as black key  */
	model_key = castauth_ImportKey(model_blob);
	if (model_key == NULL) {
		errx(1, "Error importing model key\n");
		return castauth_error(res);
	}

	device_key = malloc(MAX_KEY_PEM_SIZE);
	if (!device_key) {
		errx(1, "Out of memory\n");
		res = TEEC_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
			TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INOUT,
			TEEC_MEMREF_TEMP_OUTPUT);

	op.params[0].tmpref.buffer = (char *)bss_id;
	op.params[0].tmpref.size = bss_id_len;

	op.params[1].tmpref.buffer = model_key;
	op.params[1].tmpref.size = strlen(model_key) + 1;

	op.params[2].tmpref.buffer = cert_temp;
	op.params[2].tmpref.size = cert_temp_len;

	op.params[3].tmpref.buffer = device_key;
	op.params[3].tmpref.size = MAX_KEY_PEM_SIZE;

	res = TEEC_InvokeCommand(sess, TA_CASTAUTH_CMD_GEN_DEV_KEY_CERT, &op,
			&err_origin);
	if (res != TEEC_SUCCESS) {
		errx(1, "TA failed with code 0x%x origin 0x%x",
			res, err_origin);
		goto out;
	}

	*key = device_key;

out:
	if (model_blob)
		free(model_blob);
	if (model_key)
		free(model_key);
	return castauth_error(res);
}

/** @brief Retrieve Manufacturing Protection Public Key.
 *
 *  This function retrieves the Manufacturing Protection public key.
 *
 * @return pointer to MP public key if success, NULL if error.
 */
char *castauth_GetMPPubkey()
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op;
	uint32_t err_origin;
	TEEC_Session *sess = NULL;
	char *mp_pubkey = NULL;

	sess = castauth_get_session();

	if (!sess) {
		errx(1, "Error getting session\n");
		return NULL;
	}

	mp_pubkey = malloc(MAX_KEY_PEM_SIZE);
	if (!mp_pubkey) {
		errx(1, "Out of memory\n");
		return NULL;
	}

	memset(mp_pubkey, 0, MAX_KEY_PEM_SIZE);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
			TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = (void *)mp_pubkey;
	op.params[0].tmpref.size = MAX_KEY_PEM_SIZE;

	res = TEEC_InvokeCommand(sess, TA_CASTAUTH_CMD_GET_MP_PUBKEY, &op,
			&err_origin);
	if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		free(mp_pubkey);
		return NULL;
	}

	return mp_pubkey;
}

/** @brief Retrieve The Hardware Id.
 *
 *  This function retrieves the Hardware Unique Id.
 *
 * @return Word value, 0 if error.
 */
uint64_t castauth_GetHwId(void)
{

	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op;
	uint32_t err_origin;
	TEEC_Session *sess = NULL;

	union hwid_t {
		uint8_t as_bytes[8];
		uint64_t as_long;
	} hwid;

	sess = castauth_get_session();

	if (!sess) {
		errx(1, "Error getting session\n");
		return 0;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
			TEEC_NONE, TEEC_NONE);

	memset(hwid.as_bytes, 0, sizeof(hwid.as_bytes));

	op.params[0].tmpref.buffer = &hwid.as_bytes[0];
	op.params[0].tmpref.size = sizeof(hwid.as_bytes);

	res = TEEC_InvokeCommand(sess, TA_CASTAUTH_CMD_GET_HW_ID, &op,
			&err_origin);
	if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		return 0;
	}

	return hwid.as_long;
}

void castauth_init(void)
{
	TEEC_Session *sess = castauth_get_session();
	(void)sess;
}

void castauth_exit(void)
{
	if (g_session != NULL)
		castauth_fini_session(g_session);
}
