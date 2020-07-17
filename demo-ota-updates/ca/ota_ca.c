// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    ota_ca.c
 *
 * @brief   OTA device authentication on i.MX.
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
#include <ota_ta.h>
#include <ota_ca.h>

#define MAX_KEY_PEM_SIZE 2048

#define STATUS_SUCCESS 0
#define STATUS_ERROR -1


/* Prototypes */

static void ota_fini_session(void);
static TEEC_Result ota_get_session(void);
static int ota_call(uint32_t cmd, TEEC_Operation *op);


static TEEC_Context g_context;
static TEEC_Session g_session;

/** 
 * @brief Finish TEE session.
 *
 *  This function destroys current session.
 */
static void ota_fini_session()
{
	/* Close the session */
	TEEC_CloseSession(&g_session);

	/* Destroy the context */
	TEEC_FinalizeContext(&g_context);
}

/** 
 * @brief Convert TEE status code to local code.
 *
 *  This function converts TEE status code to local
 *  status code. For now it returns false if success.
 *  and true if error.
 *
 * @return false if success, true otherwise.
 */
static int ota_error(TEEC_Result err)
{
	return (err != TEEC_SUCCESS);
}

/** 
 * @brief Get session handler.
 *
 *  This function retrieves the session handler.
 *  It creates a new session if not initialized.
 *
 * @return pointer to session handler.
 */
static TEEC_Result ota_get_session()
{
	TEEC_Result res;
	TEEC_UUID uuid = TA_OTA_AUTH_UUID;
	uint32_t err_origin;

	/* Initialize a context connecting to the TEE */
	res = TEEC_InitializeContext(NULL, &g_context);
	if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
		return res;
	}

	/* Open a session with the TA */
	res = TEEC_OpenSession(&g_context, &g_session, &uuid,
		TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
				res, err_origin);
		TEEC_FinalizeContext(&g_context);
	}

	return res;
}

/** 
 * @brief Call the TA.
 *
 *  This function calls the OTA Trusted Application.
 *  It creates a new session for every call and terminates it
 *  after finishing.
 *
 * @return 0 on success, other value if error.
 */
static int ota_call(uint32_t cmd, TEEC_Operation *op){
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t err_origin;

	/* Create a new TA session */
	res = ota_get_session();
	if (res != TEEC_SUCCESS) {
		errx(1, "Error getting session\n");
		return ota_error(res);
	}
	/* Invoke a command in TA */
	res = TEEC_InvokeCommand(&g_session, cmd, op, &err_origin);
	if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
	}
	/* Terminate the session */
	ota_fini_session();

	return ota_error(res); 
}

/**
 * @brief Retrieve Manufacturing Protection Public Key.
 *
 *  This function retrieves the Manufacturing Protection public key.
 *
 * @return pointer to MP public key if success, NULL if error.
 */
char *ota_GetMPPubkey()
{
	int res;
	TEEC_Operation op;
	char *mp_pubkey = NULL;

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
	op.params[0].tmpref.size = MAX_KEY_PEM_SIZE - 1;

	res = ota_call(TA_OTA_CMD_GET_MP_PUBKEY, &op);

	if (res != 0) {
		free(mp_pubkey);
		return NULL;
	}

	return mp_pubkey;
}

/**
 * @brief Sign with Manufacturing Protection Private key.
 *
 *  This function signs data using manufacturing potection private key.
 *  The supplied data should be uint8_t type. 
 *  Output signature is 64 byte value.
 *  Output mpmr is 32 byte value.
 *
 * @param data to be signed.
 * @param data_len Input hash length.
 * @param sig Output signature buffer.
 * @param sig_len Output signature buffer length.
 * @param mpmr Output mpmr buffer.
 * @param mpmr_len Output mpmr buffer length.
 * @return 0 if success other value if error.
 */
int ota_GenMPPRivSignature(uint8_t *data, uint32_t data_len, uint8_t *signat, uint32_t signat_len, uint8_t *mpmr, uint32_t mpmr_len)
{
	int res;
	TEEC_Operation op;

	if (!data || !mpmr || !signat) {
		errx(1, "NULL arguments");
		return ota_error(TEEC_ERROR_BAD_PARAMETERS);
	}

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
			TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
			TEEC_NONE);

	op.params[0].tmpref.buffer = data;
	op.params[0].tmpref.size = data_len;

	op.params[1].tmpref.buffer = signat;
	op.params[1].tmpref.size = signat_len;

	op.params[2].tmpref.buffer = mpmr;
	op.params[2].tmpref.size = mpmr_len;

	res = ota_call(TA_OTA_CMD_GEN_MPPRIV_SIGN, &op);

	return ota_error(res);
}
