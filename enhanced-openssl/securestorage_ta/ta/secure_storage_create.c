/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "string.h"
#include "secure_storage_common.h"

/**
 * @brief  Translates a SK_Attributes array to a TEE_Attributes array
 *		and returns object type and size to populate a Persisten Object		
 * 
 * @param[in]  attrs       	  	Array of Key Attributes
 * @param[in]  attr_count     	Number of attributes
 * @param[out] tee_attrs	  	Array of TEE Attributes
 * @param[out] tee_attr_count   Number of TEE Atributes
 * @param[out] obj_type			      
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_SHORT_BUFFER      Output buffer too short
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result TA_GetTEEObjectTypeAndAttr(SK_ATTRIBUTE *attrs,
					     uint32_t attr_count,
					     TEE_Attribute **tee_attrs,
					     uint32_t *tee_attr_count,
					     uint32_t *obj_type,
					     uint32_t *obj_size)
{
	SK_ATTRIBUTE *attr_obj_type, *attr_key_type;
	SK_OBJECT_TYPE sk_obj_type = SK_ANY_TYPE;
	SK_KEY_TYPE key_type;

	attr_obj_type = TA_GetSKAttr(SK_ATTR_OBJECT_TYPE, attrs, attr_count);
	if (attr_obj_type == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	sk_obj_type = *(SK_OBJECT_TYPE *)attr_obj_type->value;

	switch (sk_obj_type) {
	case SK_KEY_PAIR:
		attr_key_type = TA_GetSKAttr(SK_ATTR_KEY_TYPE, attrs,
					     attr_count);
		if (attr_key_type == NULL)
			return TEE_ERROR_BAD_PARAMETERS;

		key_type = *(SK_KEY_TYPE *)attr_key_type->value;

		if (key_type == SKK_RSA) {
#define MAX_RSA_KEYPAIR_ATTR		8
			SK_ATTRIBUTE *attr_obj_size;

			attr_obj_size = TA_GetSKAttr(SK_ATTR_MODULUS_BITS,
						     attrs, attr_count);
			if (attr_obj_size == NULL)
				return TEE_ERROR_BAD_PARAMETERS;

			*obj_size = *(uint32_t *)attr_obj_size->value;
			*obj_type = TEE_TYPE_RSA_KEYPAIR;
			*tee_attrs = TEE_Malloc(MAX_RSA_KEYPAIR_ATTR *
						sizeof(TEE_Attribute), 0);
			if (!*tee_attrs)
				return TEE_ERROR_OUT_OF_MEMORY;

			fill_rsa_keypair_tee_attr(attrs, attr_count,
						  *tee_attrs, tee_attr_count);

		} else if (key_type == SKK_EC) {
#define MAX_EC_KEYPAIR_ATTR		4
			SK_ATTRIBUTE *attr_ec_curve;
			uint32_t ec_size;

			attr_ec_curve = TA_GetSKAttr(SK_ATTR_PARAMS,
						     attrs, attr_count);
			if (attr_ec_curve == NULL)
				return TEE_ERROR_BAD_PARAMETERS;

			if (!get_ec_obj_size(attr_ec_curve, &ec_size)) {
				*obj_size = ec_size;
			} else {
				EMSG("Algo Not Supported\n");
				return TEE_ERROR_BAD_PARAMETERS;
			}

			*obj_type = TEE_TYPE_ECDSA_KEYPAIR;
			*tee_attrs = TEE_Malloc(MAX_EC_KEYPAIR_ATTR *
						sizeof(TEE_Attribute), 0);
			if (!*tee_attrs)
				return TEE_ERROR_OUT_OF_MEMORY;

			fill_ec_keypair_tee_attr(attrs, attr_count,
				*tee_attrs, tee_attr_count, *obj_size);
		} else {
			return TEE_ERROR_BAD_PARAMETERS;
		}
		break;

	case SK_PUBLIC_KEY:

		attr_key_type = TA_GetSKAttr(SK_ATTR_KEY_TYPE, attrs,
					     attr_count);
		if (attr_key_type == NULL)
			return TEE_ERROR_BAD_PARAMETERS;

		key_type = *(SK_KEY_TYPE *)attr_key_type->value;

		if (key_type == SKK_RSA) {
#define MAX_RSA_PUBLIC_KEY_ATTR		2
			SK_ATTRIBUTE *attr_obj_size;

			attr_obj_size = TA_GetSKAttr(SK_ATTR_MODULUS_BITS,
						     attrs, attr_count);
			if (attr_obj_size == NULL)
				return TEE_ERROR_BAD_PARAMETERS;

			*obj_size = *(uint32_t *)attr_obj_size->value;
			*obj_type = TEE_TYPE_RSA_PUBLIC_KEY;
			*tee_attrs = TEE_Malloc(MAX_RSA_PUBLIC_KEY_ATTR *
						sizeof(TEE_Attribute), 0);
			if (!*tee_attrs)
				return TEE_ERROR_OUT_OF_MEMORY;

			fill_rsa_pubkey_tee_attr(attrs, attr_count,
						 *tee_attrs, tee_attr_count);
		} else if (key_type == SKK_EC) {
#define MAX_EC_PUBLIC_KEY_ATTR		3
			/* TODO: ECC keys not supported */
			SK_ATTRIBUTE *attr_ec_curve;
			uint32_t ec_size;

			attr_ec_curve = TA_GetSKAttr(SK_ATTR_PARAMS,
						     attrs, attr_count);
			if (attr_ec_curve == NULL)
				return TEE_ERROR_BAD_PARAMETERS;

			if (!get_ec_obj_size(attr_ec_curve, &ec_size)) {
				*obj_size = ec_size;
			} else {
				EMSG("Algo Not Supported\n");
				return TEE_ERROR_BAD_PARAMETERS;
			}

			*obj_type = TEE_TYPE_ECDSA_PUBLIC_KEY;
			*tee_attrs = TEE_Malloc(MAX_EC_PUBLIC_KEY_ATTR *
						sizeof(TEE_Attribute), 0);
			if (!*tee_attrs)
				return TEE_ERROR_OUT_OF_MEMORY;

			fill_ec_pubkey_tee_attr(attrs, attr_count,
				*tee_attrs, tee_attr_count, *obj_size);
		} else {
			return TEE_ERROR_BAD_PARAMETERS;
		}
		break;

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

/*
 * @brief Creates a key object form an already generated key.
 * Input params:
 * param#0 : input serialized object attributes buffer
 * param#1 : output object ID
 * param#2 : not used
 * param#3 : not used
 */
TEE_Result TA_CreateObject(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	SK_ATTRIBUTE *attrs = NULL;
	TEE_Attribute *tee_attrs = NULL;
	TEE_ObjectHandle tObject = TEE_HANDLE_NULL;
	uint32_t attr_count = 0, tee_attr_count = 0, next_obj_id = 0;
	uint32_t obj_type, obj_size;
	uint8_t *data = NULL;
	size_t data_len = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	DMSG("Unpack Object attributes!\n");
	res = unpack_sk_attrs(params[0].memref.buffer, params[0].memref.size,
			      &attrs, &attr_count);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Get TEE Attributes from SK Attributes!\n");
	res = TA_GetTEEObjectTypeAndAttr(attrs, attr_count, &tee_attrs,
					 &tee_attr_count, &obj_type,
					 &obj_size);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Allocate Transient Object!\n");
	res = TEE_AllocateTransientObject(obj_type, obj_size, &tObject);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Populate Transient Object!\n");
	res = TEE_PopulateTransientObject(tObject, tee_attrs, tee_attr_count);
	if (res != TEE_SUCCESS)
		goto out;

	/*
	 * Pack SK attributes in data stream of object as follows:
	 * - First 32 bit of buffer -> No of SK attributes.
	 * - Then SK attibute structure array.
	 * - Then SK attributes value buffers whose pointers are
	 *   there in SK attribute structure array.
	 */
	DMSG("Pack SK attributes!\n");
	res = pack_sk_attrs(attrs, attr_count, &data, &data_len);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Get Next Object ID!\n");
	res = TA_GetNextObjectID(&next_obj_id);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Create Persistent Object!\n");
	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &next_obj_id,
					sizeof(next_obj_id),
					TEE_DATA_FLAG_ACCESS_WRITE |
					TEE_DATA_FLAG_ACCESS_READ,
					tObject, data, data_len,
					TEE_HANDLE_NULL);
	if (res != TEE_SUCCESS)
		goto out;

	params[1].value.a = next_obj_id;

	DMSG("Create Persistent Object Successful!\n");
out:
	if (tObject != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(tObject);

	if (attrs)
		TEE_Free(attrs);

	if (tee_attrs)
		TEE_Free(tee_attrs);

	if (data)
		TEE_Free(data);

	return res;
}
