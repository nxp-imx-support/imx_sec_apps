// SPDX-License-Identifier: BSD-2-Clause
/**
* @copyright 2019 NXP
*
* @file    pta_hash_mx.c
*
* @brief   Pseudo Trusted Application.
*			Uses SKM_SHA to generate hash of a message
*/

/* Standard includes */
#include <stdlib.h>
#include <string.h>

/* Library kernel includes */
#include <kernel/pseudo_ta.h>

/* Library libutee includes */
#include <pta_hash.h>

/* Library tee includes */
#include <tee_api_types.h>

/* Library crypto includes */
#include <crypto_extension.h>
#include <libimxcrypt_hash.h>
#include <libimxcrypt.h>

/* Library crypto includes */
#include <crypto/crypto.h>

/* Global includes */
#include <tee_api_defines.h>

/* PTA Name */
#define HASH_PTA_NAME "hash.pta"

/**
 * @brief   Call the Cryptographic Extension API to digest
 *          data
 *
 *  Params are:
 *    Input:
 *     params[0].value.a = Cryptographic Algorithm
 * 	   params[0].value.b = Digest Size
 *     params[1].memref  = Message to do Hash
 *	  Output:
 *     params[2].memref  = Output Hash
 * 	   params[3].memref = NONE
 * 	   params[4].memref = NONE
 *
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_SHORT_BUFFER      Output buffer too short
 * @retval TEE_ERROR_GENERIC           Generic error
 */

static TEE_Result digest(uint32_t param_types,
        TEE_Param params[4]) {
		TEE_Result res = TEE_SUCCESS;
		uint32_t algorithm;
		uint8_t *message, *digest;
		size_t msg_len, digest_size;

		void *ctx = NULL;
		uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_INOUT,
			TEE_PARAM_TYPE_NONE);
		if (param_types != exp_param_types) {
			res = TEE_ERROR_BAD_PARAMETERS;
			goto out;
		}
		/*unpack parameters*/
		algorithm = params[0].value.a;
		digest_size = params[0].value.b;
		message = params[1].memref.buffer;
		msg_len = params[1].memref.size;
		digest = params[2].memref.buffer;
		/* call libimxcrypt hash functions */
		res = crypto_hash_alloc_ctx(&ctx, algorithm);
		if (res != TEE_SUCCESS)
			goto out;
		res = crypto_hash_init(ctx, algorithm);
		if (res != TEE_SUCCESS)
			goto out;
		res = crypto_hash_update(ctx, algorithm, 
				message, msg_len);
		if (res != TEE_SUCCESS)
			goto out;
		res = crypto_hash_final(ctx, algorithm, digest, 
			digest_size);
		if (res != TEE_SUCCESS)
			goto out;
out:
	crypto_hash_free_ctx(ctx, algorithm);
	return res;
}

/**
 * @brief   Open Session function verifying that only a TA opened
 *          the current PTA
 *
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 * @param[in]  sess_ctx       Session Identifier
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_ACCESS_DENIED     PTA access is denied
 */
static TEE_Result open_session(uint32_t param_types __unused,
		TEE_Param pParams[TEE_NUM_PARAMS] __unused,
		void **sess_ctx)
{
	struct tee_ta_session *sess;

	/* Check if the session is opened by a TA */
	sess = tee_ta_get_calling_session();
	if (!sess)
		return TEE_ERROR_ACCESS_DENIED;

	*sess_ctx = (void *)(vaddr_t)sess->ctx->ops->get_instance_id(sess->ctx);

	return TEE_SUCCESS;
}

/**
 * @brief   Called when a pseudo TA is invoked.
 *
 * @param[in]  sess_ctx       Session Identifier
 * @param[in]  cmd_id         Command ID
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_SHORT_BUFFER      Output buffer too short
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result invokeCommandEntryPoint(void *sess_ctx __unused,
		uint32_t cmd_id, uint32_t param_types,
		TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_HASH_CMD_DIGEST:
		return digest(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}


pseudo_ta_register(
		.uuid = PTA_HASH_PTA_UUID,
		.name = HASH_PTA_NAME,
		.flags = PTA_DEFAULT_FLAGS,
		.open_session_entry_point = open_session,
		.invoke_command_entry_point = invokeCommandEntryPoint);