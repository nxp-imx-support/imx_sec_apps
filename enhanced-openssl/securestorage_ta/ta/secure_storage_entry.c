/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#define STR_TRACE_USER_TA "SECURE_STORAGE"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "string.h"
#include "ta_secure_storage.h"
#include "secure_storage_common.h"

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	uint32_t ret = TEE_SUCCESS;

	/* Try to open db object, if not present create new db object */
	ret = TA_OpenDatabase();

	return ret;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param  params[4], void **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	DMSG("Goodbye!\n");
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TEE_CREATE_OBJECT:
		return TA_CreateObject(param_types, params);
	case TEE_FIND_OBJECTS:
		return TA_FindObjects(param_types, params);
	case TEE_GET_OBJ_ATTRIBUTES:
		return TA_GetObjectAttributes(param_types, params);
	case TEE_ERASE_OBJECT:
		return TA_EraseObject(param_types, params);
	case TEE_SIGN_DIGEST:
		return TA_SignDigest(param_types, params);
	case TEE_DECRYPT_DATA:
		return TA_DecryptData(param_types, params);
	case TEE_DIGEST_DATA:
		return TA_DigestData(param_types, params);
	case TEE_GENERATE_KEYPAIR:
		return TA_GenerateKeyPair(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
