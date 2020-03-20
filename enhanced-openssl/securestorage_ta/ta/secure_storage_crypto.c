/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "string.h"
#include "secure_storage_common.h"

#define MAX_KEY_PAIR_ATTRS		10

/*
 * @brief Generates Hash of a message
 *
 * Params are:
 * 	@params[0].value.a : SK Digest mechanism
 * 	@params[1].memref : the input data buffer
 * 	@params[2].memref : the output digest buffer
 * 	@param#3 : not used
 */
TEE_Result TA_DigestData(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	TEE_TASessionHandle session;
	TEE_UUID uuid = PTA_HASH_PTA_UUID;
	TEE_Param new_params[4];
	uint32_t algorithm, digest_size = 0;
	uint32_t err_origin;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out2;
	}

	switch (params[0].value.a) {
	case SKM_MD5:
		algorithm = TEE_ALG_MD5;
		digest_size = TEE_MD5_HASH_SIZE;
		break;
	case SKM_SHA1:
		algorithm = TEE_ALG_SHA1;
		digest_size = TEE_SHA1_HASH_SIZE;
		break;
	case SKM_SHA224:
		algorithm = TEE_ALG_SHA224;
		digest_size = TEE_SHA224_HASH_SIZE;
		break;
	case SKM_SHA256:
		algorithm = TEE_ALG_SHA256;
		digest_size = TEE_SHA256_HASH_SIZE;
		break;
	case SKM_SHA384:
		algorithm = TEE_ALG_SHA384;
		digest_size = TEE_SHA384_HASH_SIZE;
		break;
	case SKM_SHA512:
		algorithm = TEE_ALG_SHA512;
		digest_size = TEE_SHA512_HASH_SIZE;
		break;
	default:
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out2;
	}
	DMSG("Trying to digest something: %x\n", res);
	/* Check for output digest buffer */
	if (params[2].memref.buffer == NULL) {
		params[2].memref.size = digest_size;
		DMSG("Digest size: %x\n", digest_size);
		res = TEE_SUCCESS;
		goto out2;
	} else if (params[2].memref.size < digest_size) {
		res = TEE_ERROR_SHORT_BUFFER;
		goto out2;
	}
	DMSG("Open Session:%x\n", res);
	res = TEE_OpenTASession(&uuid, 0, 0, NULL, &session, &err_origin);
	if (res != TEE_SUCCESS) {
		goto out2;
	}
	DMSG("Setup params %x:\n", res);
	/* Update param fileds */
	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_INOUT,
			TEE_PARAM_TYPE_NONE);

	new_params[0].value.a = algorithm;
	new_params[0].value.b = digest_size;
	new_params[1].memref.buffer = params[1].memref.buffer;
	new_params[1].memref.size = params[1].memref.size;
	new_params[2].memref.buffer = params[2].memref.buffer;
	new_params[2].memref.size = params[2].memref.size;
	DMSG("Invoke TA Command %x:\n", res);
	/* Digest in PTA */
	res = TEE_InvokeTACommand(session, 0, PTA_CMD_HASH_DIGEST, exp_param_types,
			new_params, &err_origin);

	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Digest Successful!\n");
out:
	TEE_CloseTASession(session);
out2:
	DMSG("Digest result: %x", res);
	return res;
}

int get_ec_algorithm(size_t obj_size)
{
	switch (obj_size) {
		case 256:
			return TEE_ALG_ECDSA_P256;
		case 384:
			return TEE_ALG_ECDSA_P384;
		default:
			return TEE_ERROR_NOT_SUPPORTED;
	}
}
/*
 * @brief extract key attributes from Persistent Object
 * 
 * @param[in]: obj_id Persistent Object id
 * @param[in]: attr_cnt Number of attributes to extract
 * @param[out]:  attrs SK_ATTRIBUTE id
 */

TEE_Result GetKeyAttributes(uint32_t obj_id, uint32_t attr_cnt, 
			SK_ATTRIBUTE *attrs) 
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle pObject = TEE_HANDLE_NULL;
	TEE_ObjectInfo objectInfo;
	SK_ATTRIBUTE *obj_attrs = NULL, *match_attr = NULL;
	uint8_t *data = NULL;
	uint32_t obj_attr_cnt = 0, data_len = 0, i;

	/* Try to open object */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, (void *)&obj_id,
				       sizeof(uint32_t),
				       TEE_DATA_FLAG_ACCESS_READ |
				       TEE_DATA_FLAG_SHARE_READ,
				       &pObject);
	if (res != TEE_SUCCESS)
		goto out;
		/* Try to get object info */
	res = TEE_GetObjectInfo1(pObject, &objectInfo);
	if (res != TEE_SUCCESS)
		goto out;

	data = TEE_Malloc(objectInfo.dataSize, 0);
	if (!data) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = TEE_ReadObjectData(pObject, data, objectInfo.dataSize,
				 &data_len);
	if ((res != TEE_SUCCESS) || (data_len != objectInfo.dataSize))
		goto out;
	
	obj_attr_cnt = *(uint32_t *)(void *)data;
	obj_attrs = TEE_Malloc(sizeof(SK_ATTRIBUTE) * obj_attr_cnt, 0);
	if (!obj_attrs) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	DMSG("Unpack actual obj attributes!\n");
	res = unpack_sk_attrs(data, data_len, &obj_attrs, &obj_attr_cnt);
	if (res != TEE_SUCCESS)
		goto out;
	
	for (i = 0; i < attr_cnt; ++i) {
		match_attr = TA_GetSKAttr(attrs[i].type, obj_attrs, obj_attr_cnt);
		if (match_attr == NULL) {
			res = TEE_ERROR_BAD_PARAMETERS;
			continue;
		}
		attrs[i].valueLen = match_attr->valueLen;
		attrs[i].value = TEE_Malloc(attrs[i].valueLen, 0);
		memcpy(attrs[i].value, match_attr->value, attrs[i].valueLen);
	}
	
out:
	if (pObject != TEE_HANDLE_NULL)
		TEE_CloseObject(pObject);
	if (data)
		TEE_Free(data);
	if (obj_attrs)
		TEE_Free(obj_attrs);
	return res;
}

/*
 * @brief fills rsa struct key from pObject
 *  
 * @params[in] 	obj_id 		Id of persistent object
 * @params[out] rsa_key		Filled RSA Key struct
 */
TEE_Result fill_rsa_struct(uint32_t obj_id, SK_RSA_KEY *rsa_key)
{
	TEE_Result res = TEE_SUCCESS;
	SK_ATTRIBUTE attrs[MAX_KEY_PAIR_ATTRS] = {0};
	uint32_t attr_count = 3;

	attrs[0].type = SK_ATTR_MODULUS;
	attrs[1].type = SK_ATTR_PUBLIC_EXPONENT;
	attrs[2].type = SK_ATTR_PRIVATE_EXPONENT;
	res = GetKeyAttributes(obj_id, attr_count, attrs) ;

	DMSG("RSA Key Got Attrs: %d", res);
	if (res != TEE_SUCCESS)
		return res;

	rsa_key->modulus = (uint8_t *) attrs[0].value;
	rsa_key->mod_size = attrs[0].valueLen;
	rsa_key->pub_exp = (uint8_t *) attrs[1].value;
	rsa_key->pub_size = attrs[1].valueLen;
	rsa_key->priv_exp = (uint8_t *) attrs[2].value;
	rsa_key->priv_size = attrs[2].valueLen;
	DMSG("Print RSA Key: %d", res);
	return res;
}

TEE_Result free_rsa_struct(SK_RSA_KEY* rsa_key) 
{
	TEE_Result res = TEE_SUCCESS;
	TEE_Free(rsa_key->modulus);
	TEE_Free(rsa_key->priv_exp);
	TEE_Free(rsa_key->pub_exp);
	return res;
}

/*
 * @brief fills ecc struct key from pObject
 *  
 * @params[in] 	obj_id 		Id of persistent object
 * @params[out] ecc_key		Filled ECC Key struct
 */
TEE_Result fill_ecc_struct(uint32_t obj_id, SK_ECC_KEY *ecc_key)
{
	TEE_Result res = TEE_SUCCESS;
	SK_ATTRIBUTE attrs[MAX_KEY_PAIR_ATTRS] = {0};
	uint32_t attr_count = 3;

	attrs[0].type = SK_ATTR_POINT;
	attrs[1].type = SK_ATTR_PRIV_VALUE;
	attrs[2].type = SK_ATTR_PARAMS;

	res = GetKeyAttributes(obj_id, attr_count, attrs) ;
	if (res != TEE_SUCCESS)
		return res;
	
	ecc_key->priv_val = attrs[1].value;
	ecc_key->priv_size = attrs[1].valueLen;
	ecc_key->pub_x = attrs[0].value;
	ecc_key->x_size = attrs[0].valueLen / 2;
	ecc_key->pub_y = (uint8_t *) attrs[0].value + (attrs[0].valueLen / 2);
	ecc_key->y_size = attrs[0].valueLen / 2;
	ecc_key->curve = *((uint32_t *)attrs[2].value);

	return res;
}

TEE_Result free_ecc_struct(SK_ECC_KEY *ecc_key) {
	TEE_Result res = TEE_SUCCESS;
	TEE_Free(ecc_key->pub_x);
	TEE_Free(ecc_key->pub_y);
	TEE_Free(ecc_key->priv_val);
	return res;
}


TEE_Result fill_rsa_buff(uint8_t *key, SK_RSA_KEY *rsa_key) {
	TEE_Result res = TEE_SUCCESS;
	memcpy(key, rsa_key, sizeof(SK_RSA_KEY));
	return res;
}

TEE_Result fill_ecc_buff(uint8_t *key, SK_ECC_KEY *ecc_key) {
	TEE_Result res = TEE_SUCCESS;
	memcpy(key, ecc_key, sizeof(SK_ECC_KEY));
	return res;
}

/*
 * @brief Calls PTA to sign 
 * For ECDSA keys the function signs the message
 * For RSA keys the function encrypts the message
 * Input params:
 * param#0 : object ID and SK sign mechanism
 * param#1 : the input digest buffer
 * param#2 : the output signature buffer
 * param#3 : not used
 */

TEE_Result TA_SignDigest(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle pObject = TEE_HANDLE_NULL;
	TEE_ObjectInfo objectInfo;
	TEE_Param new_params[4];
	TEE_TASessionHandle session;
	TEE_UUID uuid = PTA_SIGN_UUID;
	SK_RSA_KEY rsa_key;
	SK_ECC_KEY ecc_key;
	uint32_t algorithm, obj_id, err_origin;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE);
	uint32_t new_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INOUT);
	uint8_t *key = NULL;

	if (param_types != exp_param_types) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out2;
	}

	obj_id = params[0].value.a;

	/* Try to open object */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, (void *)&obj_id,
				       sizeof(uint32_t),
				       TEE_DATA_FLAG_ACCESS_READ |
				       TEE_DATA_FLAG_SHARE_READ,
				       &pObject);
	
	if (res != TEE_SUCCESS)
		goto out2;

	/* Try to get object info */
	DMSG("Get Object Info!\n");
	res = TEE_GetObjectInfo1(pObject, &objectInfo);
	if (res != TEE_SUCCESS)
		goto out2;

	if (params[2].memref.buffer == NULL) {
		switch (objectInfo.objectType) {
			case TEE_TYPE_RSA_KEYPAIR:
				params[2].memref.size = objectInfo.maxObjectSize;
				break;
			case TEE_TYPE_ECDSA_KEYPAIR:
				params[2].memref.size = 2 * objectInfo.maxObjectSize;
				break;
			default:
				EMSG("Only RSA and EC Private Key object is supported\n");
		}
		goto out2;
	}

	switch (params[0].value.b) {
	case SKM_RSASSA_PKCS1_V1_5_MD5:
		algorithm = TEE_ALG_RSASSA_PKCS1_V1_5_MD5;
		break;
	case SKM_RSASSA_PKCS1_V1_5_SHA1:
		algorithm = TEE_ALG_RSASSA_PKCS1_V1_5_SHA1;
		break;
	case SKM_RSASSA_PKCS1_V1_5_SHA224:
		algorithm = TEE_ALG_RSASSA_PKCS1_V1_5_SHA224;
		break;
	case SKM_RSASSA_PKCS1_V1_5_SHA256:
		algorithm = TEE_ALG_RSASSA_PKCS1_V1_5_SHA256;
		break;
	case SKM_RSASSA_PKCS1_V1_5_SHA384:
		algorithm = TEE_ALG_RSASSA_PKCS1_V1_5_SHA384;
		break;
	case SKM_RSASSA_PKCS1_V1_5_SHA512:
		algorithm = TEE_ALG_RSASSA_PKCS1_V1_5_SHA512;
		break;
	case SKM_ECDSA:
	case SKM_ECDSA_SHA1:
	case SKM_ECDSA_SHA256:
	case SKM_ECDSA_SHA384:
	case SKM_ECDSA_SHA512:
		algorithm = get_ec_algorithm(objectInfo.maxObjectSize);
		break;
	default:
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out2;
	}

	res = TEE_OpenTASession(&uuid, 0, 0, NULL, &session, &err_origin);
	if (res != TEE_SUCCESS) {
		goto out2;
	}
	new_params[0].value.b = algorithm;
	new_params[1].memref.buffer = params[1].memref.buffer;
	new_params[1].memref.size = params[1].memref.size;
	/*reference to signature */
	DMSG("Signature size: %d\n", params[2].memref.size);
	new_params[3].memref.buffer = params[2].memref.buffer;
	new_params[3].memref.size = params[2].memref.size;

	if (params[2].memref.buffer != NULL) {
		switch (objectInfo.objectType) {
			case TEE_TYPE_RSA_KEYPAIR:
				/* fill rsa key struct */
				fill_rsa_struct(obj_id, &rsa_key);
				key = TEE_Malloc(sizeof(SK_RSA_KEY), 0);
				fill_rsa_buff(key, &rsa_key);
				new_params[2].memref.buffer = key;
				new_params[2].memref.size = sizeof(SK_RSA_KEY);
		
				res = TEE_InvokeTACommand(session, 0, PTA_SIGN_RSA_DIGEST, new_param_types,
						new_params, &err_origin);
				params[2].memref.size = new_params[3].memref.size;
			
				if (res != TEE_SUCCESS)
					goto out;
				
				res = free_rsa_struct(&rsa_key);
				if (res != TEE_SUCCESS)
					goto out;
				break;
			case TEE_TYPE_ECDSA_KEYPAIR:
				params[2].memref.size = 2 * objectInfo.maxObjectSize;
				fill_ecc_struct(obj_id, &ecc_key);

				key = TEE_Malloc(sizeof(SK_ECC_KEY), 0);
				fill_ecc_buff(key, &ecc_key);

				new_params[2].memref.buffer = key;
				new_params[2].memref.size = sizeof(SK_ECC_KEY);
			
				res = TEE_InvokeTACommand(session, 0, PTA_SIGN_ECC_DIGEST, new_param_types,
						new_params, &err_origin);
				if (res != TEE_SUCCESS)
					goto out;
				res = free_ecc_struct(&ecc_key);
				if (res != TEE_SUCCESS)
					goto out;
				break;
			default:
				EMSG("Only RSA and EC Private Key object is supported\n");
		}
		goto out;
	}

	DMSG("Sign Digest Successful!\n");
out: 
	TEE_CloseTASession(session);
out2:
	if (pObject != TEE_HANDLE_NULL)
		TEE_CloseObject(pObject);

	if (key)
		TEE_Free(key);

	return res;
}

/* @brief	Decrypts a message using case SKM_RSAES_PKCS1_V1_5
			or SKM_RSA_PKCS_NOPAD algorithm
 * SKM_RSAES_PKCS1_V1_5 is not supported yet
 *	
 * Input params:
 * param#0 : object ID and SK sign mechanism
 * param#1 : the input data buffer
 * 
 * Output params:
 * param#2 : the output data buffer
 * param#3 : not used
 */
TEE_Result TA_DecryptData(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	TEE_ObjectHandle pObject = TEE_HANDLE_NULL;
	TEE_ObjectInfo objectInfo;
	TEE_TASessionHandle session;
	TEE_UUID uuid = PTA_DECRYPT_UUID;
	TEE_Param new_params[4];
	SK_RSA_KEY rsa_key;
	uint32_t algorithm, obj_id, err_origin;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE);
	uint32_t new_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INOUT);
	uint8_t *key = NULL;
	if (param_types != exp_param_types) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out2;
	}

	obj_id = params[0].value.a;

	/* Try to open object */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, (void *)&obj_id,
				       sizeof(uint32_t),
				       TEE_DATA_FLAG_ACCESS_READ |
				       TEE_DATA_FLAG_SHARE_READ,
				       &pObject);
	if (res != TEE_SUCCESS)
		goto out2;

	/* Try to get object info */
	DMSG("Get Object Info!\n");
	res = TEE_GetObjectInfo1(pObject, &objectInfo);

	if (res != TEE_SUCCESS)
		goto out2;

	if (params[2].memref.buffer == NULL) {
		DMSG("Return object size: %x\n", objectInfo.maxObjectSize);
		params[2].memref.size = objectInfo.maxObjectSize;
		goto out2;
	}

	switch (params[0].value.b) {
	case SKM_RSAES_PKCS1_V1_5:
		/* Not supported yet */
		algorithm = TEE_ALG_RSAES_PKCS1_V1_5;
		break;
	case SKM_RSA_PKCS_NOPAD:
		algorithm = TEE_ALG_RSA_NOPAD;
		break;
	default:
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out2;
	}
	res = TEE_OpenTASession(&uuid, 0, 0, NULL, &session, &err_origin);
	if (res != TEE_SUCCESS) {
		goto out2;
	}

	new_params[1].memref.buffer = params[1].memref.buffer;
	new_params[1].memref.size = params[1].memref.size;
	new_params[3].memref.buffer = params[2].memref.buffer;
	new_params[3].memref.size = params[2].memref.size;
	/* fill rsa key struct */
	fill_rsa_struct(obj_id, &rsa_key);
	key = TEE_Malloc(sizeof(SK_RSA_KEY), 0);
	fill_rsa_buff(key, &rsa_key);
	new_params[2].memref.buffer = key;
	new_params[2].memref.size = sizeof(SK_RSA_KEY);

	switch (algorithm) {
		case TEE_ALG_RSA_NOPAD:
				res = TEE_InvokeTACommand(session, 0, PTA_DECRYPT_RSA_NOPAD, new_param_types,
						new_params, &err_origin);
				
				params[2].memref.size = new_params[3].memref.size;
				if (res != TEE_SUCCESS)
					goto out;
				break;
		case TEE_ALG_RSAES_PKCS1_V1_5:
				DMSG("Command not supported yet\n");
				res = TEE_InvokeTACommand(session, 0, PTA_DECRYPT_RSAES, new_param_types,
						new_params, &err_origin);
				
				if (res != TEE_SUCCESS)
					goto out;
				break;
		default:
				break;
	}
	free_rsa_struct(&rsa_key);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Decrypt Data Successful!\n");
out: 
	TEE_CloseTASession(session);
out2:
	if (pObject != TEE_HANDLE_NULL)
		TEE_CloseObject(pObject);

	if (key) 
		TEE_Free(key);

	return res;
}
