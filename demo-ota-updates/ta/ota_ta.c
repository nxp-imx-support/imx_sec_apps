// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    ota_ta.c
 *
 * @brief   Trusted Application implementing OTA
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
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <mbedtls/pem.h>
#include <inttypes.h>

/* Local includes */
#include "ota_ta.h"

/*
 * Debug Macros
 */
#define OTA_DEBUG
#ifdef OTA_DEBUG
#define OTA_TRACE EMSG
#else
#define OTA_TRACE (...)
#endif

/* MP Public key size in bytes */
#define MP_PUBKEY_SIZE	((2*32) + 1)

/* prototypes */

static TEE_Result otaauth_mp_pubkey(unsigned char *mp_pubkey,
		uint32_t mp_pubkey_len);
static TEE_Result otaauth_MPPubKey(unsigned char *mp_pubkey_pem,
		uint32_t mp_pubkey_pem_len);

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
static TEE_Result otaauth_mp_pubkey(unsigned char *mp_pubkey,
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
		OTA_TRACE(
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
	TEE_CloseTASession(session);
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
static TEE_Result otaauth_MPPubKey(unsigned char *mp_pubkey_pem,
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
		OTA_TRACE("Error mbedtls_pk_setup");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* Check if PK context can do RSA */
	if (mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECKEY) == 0) {
		OTA_TRACE("Error mbedtls_pk_can_do");
		res = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	/* Access the ECC context inside PK context */
	ec = mbedtls_pk_ec(pk);
	if (!ec) {
		OTA_TRACE("Error mbedtls_pk_ec");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	mp_pubkey = TEE_Malloc(mp_pubkey_len, 0);
	tmp_buff = TEE_Malloc(mp_pubkey_len, 0);
	if (!mp_pubkey || !tmp_buff) {
		OTA_TRACE("Error TEE_Malloc");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = otaauth_mp_pubkey(tmp_buff, mp_pubkey_len);
	if (res != TEE_SUCCESS) {
		OTA_TRACE("Failed to get MP pubkey");
		goto out;
	}

	memcpy(mp_pubkey, "\x04", 1);
	memcpy(mp_pubkey + 1, tmp_buff, mp_pubkey_len - 1);

	if (mbedtls_ecp_group_load(&ec->grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
		res = TEE_ERROR_BAD_FORMAT;
		OTA_TRACE("Error mbedtls_ecp_group_load()");
		goto out;
	}

	if (mbedtls_ecp_point_read_binary(&ec->grp, &ec->Q, mp_pubkey,
			mp_pubkey_len) != 0) {
		OTA_TRACE("Error mbedtls_ecp_point_read_binary()");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	if (mbedtls_ecp_check_pubkey(&ec->grp, &ec->Q) != 0) {
		OTA_TRACE("Error mbedtls_ecp_check_pubkey()");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	if (mbedtls_pk_write_pubkey_pem(&pk, mp_pubkey_pem, mp_pubkey_pem_len)
			!= 0) {
		OTA_TRACE("Error mbedtls_pk_write_pubkey_pem()");
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
 * @brief   TA Get Manufacturing Protection Public Key.
 *
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 *
 * @retval TEE_SUCCESS                Success
 * @retval TEE_ERROR_BAD_PARAMETERS   Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY    Out of memory
 */
static TEE_Result TA_OtaAuthGetMPPubkey(uint32_t param_types,
		TEE_Param params[TEE_NUM_PARAMS])
{

	uint32_t exp_param_types = TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		OTA_TRACE("Bad parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	/*
	 * params[0] represents the MP public key in PEM format
	 */

	return otaauth_MPPubKey(
	params[0].memref.buffer,
	params[0].memref.size);
}

static TEE_Result otaauth_GenMPPRivSignature(uint8_t *data, uint32_t data_len, uint8_t *sig, uint32_t sig_len, uint8_t *mpmr, uint32_t mpmr_len)
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
		OTA_TRACE("TEE open session failed with code 0x%x origin 0x%x",
				res, err_origin);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	params[0].memref.buffer = data;
	params[0].memref.size = data_len;

	params[1].memref.buffer = sig;
	params[1].memref.size = sig_len;

	params[2].memref.buffer = mpmr;
	params[2].memref.size = mpmr_len;

	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE);

	res = TEE_InvokeTACommand(session, 0, PTA_MANUFACT_PROTEC_CMD_CERT,
			exp_param_types, params, &err_origin);
out:
	return res;
}

static TEE_Result TA_OtaAuthSignMPPriv(uint32_t param_types,
		TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		OTA_TRACE("Bad parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return otaauth_GenMPPRivSignature(params[0].memref.buffer,
			params[0].memref.size, params[1].memref.buffer, params[1].memref.size, params[2].memref.buffer, params[2].memref.size);
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
	OTA_TRACE("TA Open Session success");
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

	//TA Get Manufacturing Protection Public Key
	case TA_OTA_CMD_GET_MP_PUBKEY:
		return TA_OtaAuthGetMPPubkey(param_types, params);

	//TA Sign data using Manufacturing Protection Private Key
	case TA_OTA_CMD_GEN_MPPRIV_SIGN:
		return TA_OtaAuthSignMPPriv(param_types, params);

	default:
		OTA_TRACE("Command ID 0x%08x is not supported", cmd_id);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
