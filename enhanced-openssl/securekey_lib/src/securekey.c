/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <tee_client_api.h>
#include <ta_secure_storage.h>
#include <securekey_api_types.h>
#include <securekey_api.h>

struct tee_attr_packed {
	uint32_t attr_id;
	uint32_t a;
	uint32_t b;
};

#define	PRINT_ERROR
//#define	PRINT_INFO

#ifdef PRINT_ERROR
#define print_error(msg, ...) { \
printf("[securekey_lib:%s, %d] Error: ", __func__, __LINE__); \
printf(msg, ##__VA_ARGS__); \
}
#else
#define print_error(msg, ...)
#endif

#ifdef PRINT_INFO
#define print_info(msg, ...) { \
printf("[securekey_lib:%s, %d] Info: ", __func__, __LINE__); \
printf(msg, ##__VA_ARGS__); \
}
#else
#define print_info(msg, ...)
#endif


/* Round up the even multiple of size, size has to be a multiple of 2 */
#define ROUNDUP(v, size) (((v) + (size - 1)) & ~(size - 1))

static uint32_t pack_attrs(uint8_t *buffer, size_t size,
		SK_ATTRIBUTE *attrs, uint32_t attr_cnt)
{
	uint8_t *b = buffer;
	struct tee_attr_packed *a;
	uint32_t i;

	if (b == NULL || size == 0)
		return SKR_ERR_BAD_PARAMETERS;

	*(uint32_t *)(void *)b = attr_cnt;
	b += sizeof(uint32_t);
	a = (struct tee_attr_packed *)(void *)b;
	b += sizeof(struct tee_attr_packed) * attr_cnt;

	for (i = 0; i < attr_cnt; i++) {
		a[i].attr_id = attrs[i].type;

		a[i].b = attrs[i].valueLen;

		if (attrs[i].valueLen == 0) {
			a[i].a = 0;
			continue;
		}

		memcpy(b, attrs[i].value, attrs[i].valueLen);

		/* Make buffer pointer relative to *buf */
		a[i].a = (uint32_t)(uintptr_t)(b - buffer);

		/* Round up to good alignment */
		b += ROUNDUP(attrs[i].valueLen, 4);
	}

	return SKR_OK;
}

static uint32_t unpack_sk_attrs(const uint8_t *buf, size_t blen,
			 SK_ATTRIBUTE *attrs, uint32_t *attr_count)
{
	uint32_t res = TEEC_SUCCESS;
	SK_ATTRIBUTE *a = NULL;
	const struct tee_attr_packed *ap;
	size_t num_attrs = 0;
	const size_t num_attrs_size = sizeof(uint32_t);

	if (blen == 0)
		goto out;

	if (((uintptr_t)buf & 0x3) != 0 || blen < num_attrs_size)
		return TEEC_ERROR_GENERIC;
	num_attrs = *(uint32_t *) (void *)buf;

	if ((blen - num_attrs_size) < (num_attrs * sizeof(*ap)))
		return TEEC_ERROR_GENERIC;

	ap = (const struct tee_attr_packed *)(buf + num_attrs_size);

	if (num_attrs > 0) {
		size_t n;

		a = attrs;
		for (n = 0; n < num_attrs; n++) {
			uintptr_t p;
			a[n].type = ap[n].attr_id;
			a[n].valueLen = ap[n].b;
			p = (uintptr_t)ap[n].a;
			if (p) {
				if ((p + a[n].valueLen) > blen) {
					res = TEEC_ERROR_GENERIC;
					goto out;
				}
				p += (uintptr_t)buf;

			}
			if (p)
				memcpy(a[n].value, (void *)p, a[n].valueLen);
		}
	}

	res = TEEC_SUCCESS;
out:
	if (res == TEEC_SUCCESS)
		*attr_count = num_attrs;

	return res;
}

static SK_RET_CODE map_teec_err_to_sk(TEEC_Result tee_ret,
	uint32_t err_origin)
{
	SK_RET_CODE ret;
	switch(err_origin) {
		case TEEC_ORIGIN_API:
			ret =  SKR_ERR_TEE_API;
			break;
		case TEEC_ORIGIN_COMMS:
			ret =  SKR_ERR_TEE_COMM;
			break;
		case TEEC_ORIGIN_TEE:
		case TEEC_ORIGIN_TRUSTED_APP:
		default:
		{
			switch (tee_ret) {
				case TEEC_ERROR_GENERIC:
					ret =  SKR_ERR_GENERAL_ERROR;
					break;
				case TEEC_ERROR_ACCESS_DENIED:
					ret =  SKR_ERR_ACCESS_DENIED;
					break;
				case TEEC_ERROR_CANCEL:
					ret =  SKR_ERR_CANCEL;
					break;
				case TEEC_ERROR_ACCESS_CONFLICT:
					ret =  SKR_ERR_ACCESS_CONFLICT;
					break;
				case TEEC_ERROR_EXCESS_DATA:
					ret =  SKR_ERR_EXCESS_DATA;
					break;
				case TEEC_ERROR_BAD_FORMAT:
					ret =  SKR_ERR_BAD_FORMAT;
					break;
				case TEEC_ERROR_BAD_PARAMETERS:
					ret =  SKR_ERR_BAD_PARAMETERS;
					break;
				case TEEC_ERROR_BAD_STATE:
					ret =  SKR_ERR_BAD_STATE;
					break;
				case TEEC_ERROR_ITEM_NOT_FOUND:
					ret =  SKR_ERR_ITEM_NOT_FOUND;
					break;
				case TEEC_ERROR_NOT_IMPLEMENTED:
					ret =  SKR_ERR_NOT_IMPLEMENTED;
					break;
				case TEEC_ERROR_NOT_SUPPORTED:
					ret =  SKR_ERR_NOT_SUPPORTED;
					break;
				case TEEC_ERROR_NO_DATA:
					ret =  SKR_ERR_NO_DATA;
					break;
				case TEEC_ERROR_OUT_OF_MEMORY:
					ret =  SKR_ERR_OUT_OF_MEMORY;
					break;
				case TEEC_ERROR_BUSY:
					ret =  SKR_ERR_BUSY;
					break;
				case TEEC_ERROR_COMMUNICATION:
					ret =  SKR_ERR_COMMUNICATION;
					break;
				case TEEC_ERROR_SECURITY:
					ret =  SKR_ERR_SECURITY;
					break;
				case TEEC_ERROR_SHORT_BUFFER:
					ret =  SKR_ERR_SHORT_BUFFER;
					break;
				case TEEC_ERROR_TARGET_DEAD:
					ret =  SKR_ERR_BAD_PARAMETERS;
					break;
				default:
					ret =  SKR_ERR_GENERAL_ERROR;
			}
		}
	}

	return ret;
}

static size_t get_attr_size(SK_ATTRIBUTE *attrs, uint32_t attr_cnt)
{
	size_t size = sizeof(uint32_t);
	uint32_t i;

	if (attr_cnt == 0 || attrs == NULL)
		return size;

	size = sizeof(uint32_t) + sizeof(struct tee_attr_packed) * attr_cnt;
	for (i = 0; i < attr_cnt; i++) {
		if (attrs[i].valueLen == 0)
			continue;

		/* Make room for padding */
		size += ROUNDUP(attrs[i].valueLen, 4);
	}

	return size;
}
/**
 * @brief: Creates an object that is shared between CA and TA
 * 
 * @param[in] attr SK_ATTRIBUTE list
 * @param[int] attrCount number of attributes
 * @param[out] phObject SK_OBJECT_HANDLE for the new object
 * 
 */
SK_RET_CODE SK_CreateObject(SK_ATTRIBUTE *attr,
		uint16_t attrCount, SK_OBJECT_HANDLE *phObject)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SECURE_STORAGE_UUID;
	TEEC_SharedMemory shm;
	uint32_t err_origin;
	SK_RET_CODE ret = SKR_OK;

	if (attr == NULL || attrCount <= 0 || phObject == NULL) {
		ret = SKR_ERR_BAD_PARAMETERS;
		goto end;
	}

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_InitializeContext failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto end;
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_Opensession failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, err_origin);
		goto fail1;
	}

	shm.size = get_attr_size(attr, attrCount);
	shm.flags = TEEC_MEM_INPUT;

	res = TEEC_AllocateSharedMemory(&ctx, &shm);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_AllocateSharedMemory failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto fail2;
	}

	res = pack_attrs(shm.buffer, shm.size, attr, attrCount);
	if (res != SKR_OK) {
		print_error("pack_attrs failed with code 0x%x\n", res);
		ret = res;
		goto fail3;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_VALUE_OUTPUT,
			TEEC_NONE, TEEC_NONE);
	op.params[0].memref.parent = &shm;
	op.params[0].memref.offset = 0;
	op.params[0].memref.size = shm.size;

	print_info("Invoking TEE_CREATE_OBJECT\n");
	res = TEEC_InvokeCommand(&sess, TEE_CREATE_OBJECT, &op,
			&err_origin);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_InvokeCommand failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, err_origin);
		goto fail3;
	}
	*phObject = op.params[1].value.a;

	print_info("TEE_CREATE_OBJECT successful\n");

fail3:
	TEEC_ReleaseSharedMemory(&shm);
fail2:
	TEEC_CloseSession(&sess);
fail1:
	TEEC_FinalizeContext(&ctx);
end:
	return ret;
}

/**
 * @brief Generate a key-pair for a specific Mechanism
 * @param[in] pMechanism Mechanism Info
 * @param[in] attr List of attributes for pub key
 * @param[in] attrCount Number of attributes in list
 * @param[out] phKey Handle to the generated Key Pair
 */
SK_RET_CODE SK_GenerateKeyPair(SK_MECHANISM_INFO *pMechanism,
			       SK_ATTRIBUTE *attr, uint16_t attrCount,
			       SK_OBJECT_HANDLE *phKey)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SECURE_STORAGE_UUID;
	TEEC_SharedMemory shm;
	uint32_t err_origin;
	SK_RET_CODE ret = SKR_OK;

	if ((pMechanism == NULL) || (attr == NULL) || (attrCount <= 0) ||
	    (phKey == NULL)) {
		ret = SKR_ERR_BAD_PARAMETERS;
		goto end;
	}

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_InitializeContext failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto end;
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_Opensession failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, err_origin);
		goto fail1;
	}

	/* Copy object key attributes to shared memory */
	shm.size = get_attr_size(attr, attrCount);
	shm.flags = TEEC_MEM_INPUT;

	res = TEEC_AllocateSharedMemory(&ctx, &shm);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_AllocateSharedMemory failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto fail2;
	}

	res = pack_attrs(shm.buffer, shm.size, attr, attrCount);
	if (res != SKR_OK) {
		print_error("pack_attrs failed with code 0x%x\n", res);
		ret = res;
		goto fail3;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_WHOLE,
					 TEEC_VALUE_OUTPUT, TEEC_NONE);
	op.params[0].value.a = pMechanism->mechanism;
	op.params[1].memref.parent = &shm;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = shm.size;

	print_info("Invoking TEE_GENERATE_KEYPAIR\n");
	// the key is restored in op.params[2]
	res = TEEC_InvokeCommand(&sess, TEE_GENERATE_KEYPAIR, &op,
				 &err_origin);

	if (res != TEEC_SUCCESS) {
		print_error("TEEC_InvokeCommand failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, err_origin);
		goto fail3;
	}
	*phKey = op.params[2].value.a;

	print_info("TEE_GENERATE_KEYPAIR successful\n");

fail3:
	TEEC_ReleaseSharedMemory(&shm);
fail2:
	TEEC_CloseSession(&sess);
fail1:
	TEEC_FinalizeContext(&ctx);
end:
	return ret;
}

SK_RET_CODE SK_EraseObject(SK_OBJECT_HANDLE hObject)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SECURE_STORAGE_UUID;
	uint32_t err_origin;
	SK_RET_CODE ret = SKR_OK;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_InitializeContext failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto end;
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_Opensession failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, err_origin);
		goto fail1;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = hObject;

	print_info("Invoking TEE_ERASE_OBJECT\n");
	res = TEEC_InvokeCommand(&sess, TEE_ERASE_OBJECT, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_InvokeCommand failed with code 0x%x", res);
		ret = map_teec_err_to_sk(res, err_origin);
		goto fail2;
	}
	print_info("TEE_ERASE_OBJECT successful\n");

fail2:
	TEEC_CloseSession(&sess);
fail1:
	TEEC_FinalizeContext(&ctx);
end:
	return ret;
}

/**
 * @brief: Returns a list of all key objects stored inside the TA
 * 
 * @param[in]	pTemplate
 * @param[in] 	attrcount
 * @param[out]	phObject		 Array of Secure Objects stored in TA
 * @param[in] 	maxObjects
 * @param[out]	pulObjectCount	 Number of Objects returned by TA
 */
SK_RET_CODE SK_EnumerateObjects(SK_ATTRIBUTE *pTemplate,
		uint32_t attrCount, SK_OBJECT_HANDLE *phObject,
		uint32_t maxObjects, uint32_t *pulObjectCount)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SECURE_STORAGE_UUID;
	TEEC_SharedMemory shm_in, shm_out;
	uint32_t err_origin;
	SK_RET_CODE ret = SKR_OK;

	if (phObject == NULL || pulObjectCount == NULL) {
		ret = SKR_ERR_BAD_PARAMETERS;
		goto end;
	}

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_InitializeContext failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto end;
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_Opensession failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, err_origin);
		goto fail1;
	}

	shm_in.size = get_attr_size(pTemplate, attrCount);
	shm_in.flags = TEEC_MEM_INPUT;

	res = TEEC_AllocateSharedMemory(&ctx, &shm_in);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_AllocateSharedMemory failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto fail2;
	}

	res = pack_attrs(shm_in.buffer, shm_in.size, pTemplate, attrCount);
	if (res != SKR_OK) {
		print_error("pack_attrs failed with code 0x%x\n", res);
		ret = res;
		goto fail3;
	}

	shm_out.size = sizeof(SK_OBJECT_HANDLE) * maxObjects;
	shm_out.flags = TEEC_MEM_OUTPUT;

	res = TEEC_AllocateSharedMemory(&ctx, &shm_out);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_AllocateSharedMemory failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto fail3;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE,
					TEEC_VALUE_OUTPUT, TEEC_NONE);
	op.params[0].memref.parent = &shm_in;
	op.params[0].memref.offset = 0;
	op.params[0].memref.size = shm_in.size;
	op.params[1].memref.parent = &shm_out;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = shm_out.size;

	print_info("Invoking TEE_FIND_OBJECTS\n");
	res = TEEC_InvokeCommand(&sess, TEE_FIND_OBJECTS, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_InvokeCommand failed with code 0x%x", res);
		ret = map_teec_err_to_sk(res, err_origin);
		goto fail4;
	}
	print_info("TEE_FIND_OBJECTS successful\n");
	*pulObjectCount = op.params[2].value.a;

	memcpy(phObject, shm_out.buffer,
		*pulObjectCount * sizeof(SK_OBJECT_HANDLE));
fail4:
	TEEC_ReleaseSharedMemory(&shm_out);
fail3:
	TEEC_ReleaseSharedMemory(&shm_in);
fail2:
	TEEC_CloseSession(&sess);
fail1:
	TEEC_FinalizeContext(&ctx);
end:
	return ret;
}

/**
 * @brief: Get an attribute of a Secure Object stored in TA
 * 
 * @param[in]		hObject		Handle to Secure Key Object
 * @param[in/out]   attribute	Array of attributes to be returned by TA.
 * 								The value fileds will be filled inside the TA call
 * @param[in]		attrCount	Number of attributes
 */
SK_RET_CODE SK_GetObjectAttribute(SK_OBJECT_HANDLE hObject,
		SK_ATTRIBUTE *attribute, uint32_t attrCount)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SECURE_STORAGE_UUID;
	TEEC_SharedMemory shm_in;
	uint32_t err_origin;
	SK_RET_CODE ret = SKR_OK;

	if (attribute == NULL || attrCount <= 0)
		ret = SKR_ERR_BAD_PARAMETERS;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_InitializeContext failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto end;
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_Opensession failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, err_origin);
		goto fail1;
	}

	shm_in.size = get_attr_size(attribute, attrCount);
	shm_in.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

	res = TEEC_AllocateSharedMemory(&ctx, &shm_in);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_AllocateSharedMemory failed with code 0x%x", res);
		ret = map_teec_err_to_sk(res, 0);
		goto fail2;
	}

	res = pack_attrs(shm_in.buffer, shm_in.size, attribute, attrCount);
	if (res != SKR_OK) {
		print_error("pack_attrs failed with code 0x%x", res);
		ret = res;
		goto fail3;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_WHOLE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = hObject;
	op.params[1].memref.parent = &shm_in;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = shm_in.size;

	print_info("Invoking TEE_GET_OBJ_ATTRIBUTES\n");
	res = TEEC_InvokeCommand(&sess, TEE_GET_OBJ_ATTRIBUTES, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_InvokeCommand failed with code 0x%x", res);
		ret = map_teec_err_to_sk(res, err_origin);
		goto fail3;
	}
	print_info("TEE_GET_OBJ_ATTRIBUTES successful\n");

	unpack_sk_attrs((void *)shm_in.buffer, shm_in.size, attribute,
			&attrCount);

fail3:
	TEEC_ReleaseSharedMemory(&shm_in);
fail2:
	TEEC_CloseSession(&sess);
fail1:
	TEEC_FinalizeContext(&ctx);
end:
	return ret;
}

/**
 * @brief: Signs a message using RSA/ECC keys and returns the output
 * 
 * @param[in] pMechanismType 	specific mechanism for each key
 * @param[in] hObject			handle to Secure Key Object
 * @param[in] inDigest 			Message to be signed
 * @param[in] inDigestLen		Length of the message
 * @param[out] outSignature		The Signature of the message, returne by the TA call
 * @param[out] outSignatureLen	The length of the signature, returned by the TA call
 */
SK_RET_CODE SK_Sign(SK_MECHANISM_INFO *pMechanismType,
		SK_OBJECT_HANDLE hObject, const uint8_t *inDigest,
		uint16_t inDigestLen, uint8_t *outSignature,
		uint16_t *outSignatureLen)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SECURE_STORAGE_UUID;
	TEEC_SharedMemory shm_in, shm_out;
	uint32_t err_origin;
	SK_RET_CODE ret = SKR_OK;

	if ((pMechanismType == NULL) || (inDigest == NULL) ||
	    (inDigestLen == 0) ||
	    ((outSignature == NULL) && (*outSignatureLen != 0))) {
		ret = SKR_ERR_BAD_PARAMETERS;
		goto end;
	}

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_InitializeContext failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto end;
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_Opensession failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, err_origin);
		goto fail1;
	}

	shm_in.size = inDigestLen;
	shm_in.flags = TEEC_MEM_INPUT;

	res = TEEC_AllocateSharedMemory(&ctx, &shm_in);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_AllocateSharedMemory failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto fail2;
	}

	memcpy(shm_in.buffer, inDigest, shm_in.size);

	shm_out.size = *outSignatureLen;
	shm_out.flags = TEEC_MEM_OUTPUT;

	res = TEEC_AllocateSharedMemory(&ctx, &shm_out);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_AllocateSharedMemory failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto fail3;
	}

	/* Initialize params for the TA call */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_WHOLE,
					 TEEC_MEMREF_WHOLE, TEEC_NONE);
	op.params[0].value.a = hObject;
	op.params[0].value.b = pMechanismType->mechanism;
	op.params[1].memref.parent = &shm_in;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = shm_in.size;
	op.params[2].memref.parent = &shm_out;
	op.params[2].memref.offset = 0;
	op.params[2].memref.size = shm_out.size;

	print_info("Invoking TEE_SIGN_DIGEST\n");
	res = TEEC_InvokeCommand(&sess, TEE_SIGN_DIGEST, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_InvokeCommand failed with code 0x%x", res);
		ret = map_teec_err_to_sk(res, err_origin);
		goto fail4;
	}
	print_info("TEE_SIGN_DIGEST successful\n");
	*outSignatureLen = op.params[2].memref.size;

	if (outSignature)
		memcpy(outSignature, shm_out.buffer, *outSignatureLen);
fail4:
	TEEC_ReleaseSharedMemory(&shm_out);
fail3:
	TEEC_ReleaseSharedMemory(&shm_in);
fail2:
	TEEC_CloseSession(&sess);
fail1:
	TEEC_FinalizeContext(&ctx);
end:
	return ret;
}

/**
 * @brief: Decrypts a message using RSA keys
 * 
 * @param[in] pMechanismType 	specific mechanism for decryption
 * @param[in] hObject			handle to Secure Key Object
 * @param[in] inData 			Message to be decrypted
 * @param[in] inDataLen			Length of the message
 * @param[out] outData			Decrypted message returned by TA
 * @param[out] outDataLen		Length of the decrypted message returned by TA
 */
SK_RET_CODE SK_Decrypt(SK_MECHANISM_INFO *pMechanismType,
		SK_OBJECT_HANDLE hObject, const uint8_t *inData,
		uint16_t inDataLen, uint8_t *outData, uint16_t *outDataLen)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SECURE_STORAGE_UUID;
	TEEC_SharedMemory shm_in, shm_out;
	uint32_t err_origin;
	SK_RET_CODE ret = SKR_OK;

	if ((pMechanismType == NULL) || (inData == NULL) ||
	    (inDataLen == 0) || ((outData == NULL) && (*outDataLen != 0))) {
		ret = SKR_ERR_BAD_PARAMETERS;
		goto end;
	}
	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_InitializeContext failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto end;
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_Opensession failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, err_origin);
		goto fail1;
	}

	shm_in.size = inDataLen;
	shm_in.flags = TEEC_MEM_INPUT;

	res = TEEC_AllocateSharedMemory(&ctx, &shm_in);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_AllocateSharedMemory failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto fail2;
	}

	memcpy(shm_in.buffer, inData, shm_in.size);

	shm_out.size = *outDataLen;
	shm_out.flags = TEEC_MEM_OUTPUT;

	res = TEEC_AllocateSharedMemory(&ctx, &shm_out);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_AllocateSharedMemory failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto fail3;
	}

	/* Initialize params for the TA call */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_WHOLE,
					 TEEC_MEMREF_WHOLE, TEEC_NONE);
	op.params[0].value.a = hObject;
	op.params[0].value.b = pMechanismType->mechanism;
	op.params[1].memref.parent = &shm_in;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = shm_in.size;
	op.params[2].memref.parent = &shm_out;
	op.params[2].memref.offset = 0;
	op.params[2].memref.size = shm_out.size;

	print_info("Invoking TEE_DECRYPT_DATA\n");
	res = TEEC_InvokeCommand(&sess, TEE_DECRYPT_DATA, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_InvokeCommand failed with code 0x%x", res);
		ret = map_teec_err_to_sk(res, err_origin);
		goto fail4;
	}
	print_info("TEE_DECRYPT_DATA successful\n");

	*outDataLen = op.params[2].memref.size;

	if (outData)
		memcpy(outData, shm_out.buffer, *outDataLen);
fail4:
	TEEC_ReleaseSharedMemory(&shm_out);
fail3:
	TEEC_ReleaseSharedMemory(&shm_in);
fail2:
	TEEC_CloseSession(&sess);
fail1:
	TEEC_FinalizeContext(&ctx);
end:
	return ret;
}

/**
 * @brief: Generates the hash of an input message
 * 
 * @param[in] pMechanismType 	specific hash mechanism
 * @param[in] inData 			Message on which to apply hash
 * @param[in] inDataLen			Length of the message
 * @param[out] outDigest		Hash returned by TA
 * @param[out] outDataLen		Length of the hash returned by TA
 */
SK_RET_CODE SK_Digest(SK_MECHANISM_INFO *pMechanismType, const uint8_t *inData,
		      uint16_t inDataLen, uint8_t *outDigest,
		      uint16_t *outDigestLen)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SECURE_STORAGE_UUID;
	TEEC_SharedMemory shm_in, shm_out;
	uint32_t err_origin;
	SK_RET_CODE ret = SKR_OK;

	if ((pMechanismType == NULL) || (inData == NULL) ||
	    (inDataLen == 0) || ((outDigest == NULL) &&
				 (*outDigestLen != 0))) {
		ret = SKR_ERR_BAD_PARAMETERS;
		goto end;
	}
	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_InitializeContext failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto end;
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_Opensession failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, err_origin);
		goto fail1;
	}

	shm_in.size = inDataLen;
	shm_in.flags = TEEC_MEM_INPUT;

	res = TEEC_AllocateSharedMemory(&ctx, &shm_in);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_AllocateSharedMemory failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto fail2;
	}

	memcpy(shm_in.buffer, inData, shm_in.size);
	
	shm_out.size = *outDigestLen;
	shm_out.flags = TEEC_MEM_OUTPUT;

	res = TEEC_AllocateSharedMemory(&ctx, &shm_out);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_AllocateSharedMemory failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto fail3;
	}

	/* Initialize params for the TA call */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_WHOLE,
					 TEEC_MEMREF_WHOLE, TEEC_NONE);
	op.params[0].value.a = pMechanismType->mechanism;
	op.params[1].memref.parent = &shm_in;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = shm_in.size;
	op.params[2].memref.parent = &shm_out;
	op.params[2].memref.offset = 0;
	op.params[2].memref.size = shm_out.size;

	print_info("Invoking TEE_DIGEST_DATA\n");
	res = TEEC_InvokeCommand(&sess, TEE_DIGEST_DATA, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS) {
		print_error("TEEC_InvokeCommand failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, err_origin);
		goto fail4;
	}
	print_info("TEE_DIGEST_DATA successful\n");

	*outDigestLen = op.params[2].memref.size;

	if (outDigest)
		memcpy(outDigest, shm_out.buffer, *outDigestLen);
fail4:
	TEEC_ReleaseSharedMemory(&shm_out);
fail3:
	TEEC_ReleaseSharedMemory(&shm_in);
fail2:
	TEEC_CloseSession(&sess);
fail1:
	TEEC_FinalizeContext(&ctx);
end:
	return ret;
}

static SK_FUNCTION_LIST global_function_list;

SK_RET_CODE SK_GetFunctionList(SK_FUNCTION_LIST_PTR_PTR  ppFuncList)
{
	if (ppFuncList == NULL)
		return SKR_ERR_BAD_PARAMETERS;

	global_function_list.SK_EnumerateObjects = SK_EnumerateObjects;
	global_function_list.SK_GetObjectAttribute = SK_GetObjectAttribute;
	global_function_list.SK_Sign = SK_Sign;
	global_function_list.SK_Decrypt = SK_Decrypt;
	global_function_list.SK_Digest = SK_Digest;

	*ppFuncList = &global_function_list;

	return SKR_OK;
}
