/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "string.h"
#include "secure_storage_common.h"


#define MAX_KEY_PAIR_ATTRS		10
#define MAX_KEY_SIZE_BYTES		512
#define ECC_ATTRS				4
#define RSA_ATTRS				3

static uint8_t modulus[MAX_KEY_SIZE_BYTES];
static uint8_t ec_pub_point[MAX_KEY_SIZE_BYTES];
static uint8_t priv_exp[MAX_KEY_SIZE_BYTES];
static uint8_t priv_val[MAX_KEY_SIZE_BYTES];

/*
 * @brief   Generates an EC Key Pair
 *
 * @param[in]  tObject        Object Handle that should point to the key object
 * @param[in]  in_buffer      Buffer with key attributes
 * @param[in]  size   		  The number of in_buffer attributes
 * @param[out] attrs          Key Attributes in SK_Buffer format
 * @param[out] attr_count	  The number of SK_ATTRIBUTEs
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_SHORT_BUFFER      Output buffer too short
 * @retval TEE_ERROR_GENERIC           Generic error
 */

static TEE_Result TA_GenerateECKeyPair(TEE_ObjectHandle *tObject,
					void *in_buffer, uint32_t size,
					SK_ATTRIBUTE *attrs,
					uint32_t *attr_count)
{
	TEE_Result res;
	TEE_Param params[4];
	TEE_TASessionHandle session;
	TEE_UUID uuid = PTA_GENERATE_PTA_UUID;
	SK_ATTRIBUTE *in_attrs = NULL;
	SK_ATTRIBUTE *get_attr;
	
	uint32_t obj_size;
	uint32_t obj_ret_size, in_attr_cnt = 0;
	uint32_t ec_size, err_origin, priv_val_size, point_y_size;
	const uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_MEMREF_INOUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE);

	ec_pub_point[0] = 0x4;

	DMSG("Unpack Object attributes!\n");
	res = unpack_sk_attrs(in_buffer, size, &in_attrs, &in_attr_cnt);
	if (res != TEE_SUCCESS)
		goto out;

	/* Get EC key size from SK_ATTR_PARAMS attribute */
	get_attr = TA_GetSKAttr(SK_ATTR_PARAMS, in_attrs,
				in_attr_cnt);
	if (get_attr == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!get_ec_obj_size(get_attr, &ec_size)) {
		obj_size = ec_size;
	} else {
		EMSG("Algo Not Supported\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	attrs[*attr_count].type = get_attr->type;
	attrs[*attr_count].value = get_attr->value;
	attrs[*attr_count].valueLen = get_attr->valueLen;
	(*attr_count)++;

	res = TEE_OpenTASession(&uuid, 0, 0, NULL, &session, &err_origin);
	if (res != TEE_SUCCESS) {
		return TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	params[0].value.a = obj_size;
	params[1].memref.buffer = ec_pub_point;
	params[1].memref.size = MAX_KEY_SIZE_BYTES;
	params[2].memref.buffer = priv_val;
	DMSG("Invokes EC PTA Generate function");
	res = TEE_InvokeTACommand(session, 0, PTA_GENERATE_ECKEY_CMD, exp_param_types,
				params, &err_origin);

	if (res != TEE_SUCCESS)
		goto out;

	/* unpack the result and create TransientObject */
	priv_val_size = params[2].memref.size;
	point_y_size = params[0].value.b;
	obj_ret_size = params[1].memref.size;
	
	attrs[*attr_count].type = SK_ATTR_POINT;
	attrs[*attr_count].value = ec_pub_point;
	attrs[*attr_count].valueLen = obj_ret_size + point_y_size + 1;
	(*attr_count)++;

	attrs[*attr_count].type = SK_ATTR_PRIV_VALUE;
	attrs[*attr_count].value = priv_val;
	attrs[*attr_count].valueLen = priv_val_size;
	(*attr_count)++;

	/* Check if EC key object index is passed in input attrs */
	get_attr = TA_GetSKAttr(SK_ATTR_OBJECT_INDEX, in_attrs,
				in_attr_cnt);
	if (get_attr) {
		attrs[*attr_count].type = get_attr->type;
		attrs[*attr_count].value = get_attr->value;
		attrs[*attr_count].valueLen = get_attr->valueLen;
		(*attr_count)++;
	}

	/* Check if EC key object label is passed in input attrs */
	get_attr = TA_GetSKAttr(SK_ATTR_OBJECT_LABEL, in_attrs,
				in_attr_cnt);
	if (get_attr) {
		attrs[*attr_count].type = get_attr->type;
		attrs[*attr_count].value = get_attr->value;
		attrs[*attr_count].valueLen = get_attr->valueLen;
		(*attr_count)++;
	}
	res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, obj_size, tObject);
	if (res != TEE_SUCCESS)
        goto out;


out:
	if (in_attrs)
		TEE_Free(in_attrs);

	if (session)
		TEE_CloseTASession(session);

	return res;
}

/**
 * @brief Generates a RSA Key Pair
 * 
 * @param[in] tObject Handle to the primary key
 * @param[in] in_buffer
 * @param[in] size 
 * @params[out] attrs List of SK attributes
 * @params[out] attr_count Number of attributes from attr
 */

static TEE_Result TA_GenerateRSAKeyPair(TEE_ObjectHandle *tObject,
					void *in_buffer, uint32_t size,
					SK_ATTRIBUTE *attrs,
					uint32_t *attr_count)
{
	TEE_Result res;
	TEE_TASessionHandle session;
	TEE_UUID uuid = PTA_GENERATE_PTA_UUID;
	TEE_Param params[4];
	SK_ATTRIBUTE *in_attrs = NULL;
	SK_ATTRIBUTE *get_attr;
	uint32_t in_attr_cnt = 0;
	uint32_t obj_size, priv_exp_size, err_origin;
	uint32_t mod_size = MAX_KEY_SIZE_BYTES;
	uint32_t pub_exp_size = MAX_KEY_SIZE_BYTES;
	uint8_t *pub_exp = NULL;
	const uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INOUT,
						   TEE_PARAM_TYPE_MEMREF_INOUT,
						   TEE_PARAM_TYPE_MEMREF_INOUT);


	DMSG("Unpack Object attributes!\n");
	res = unpack_sk_attrs(in_buffer, size, &in_attrs, &in_attr_cnt);
	if (res != TEE_SUCCESS)
		goto out;

	/* Get RSA key size from SK_ATTR_MODULUS_BITS attribute */
	get_attr = TA_GetSKAttr(SK_ATTR_MODULUS_BITS, in_attrs,
				in_attr_cnt);
	if (get_attr == NULL)
		return TEE_ERROR_BAD_PARAMETERS;
	obj_size = *(uint32_t *)get_attr->value;

	attrs[*attr_count].type = get_attr->type;
	attrs[*attr_count].value = get_attr->value;
	attrs[*attr_count].valueLen = get_attr->valueLen;
	(*attr_count)++;


/* 	Check if RSA key exponent is passed in input attrs */
	get_attr = TA_GetSKAttr(SK_ATTR_PUBLIC_EXPONENT, in_attrs,
				in_attr_cnt);
	if (get_attr) {
		pub_exp = get_attr->value;
		pub_exp_size = get_attr->valueLen;
	} else {
		DMSG("PUB EXP has to be provided %d:", res);
		goto out;
	}
	
	res = TEE_OpenTASession(&uuid, 0, 0, NULL, &session, &err_origin);
	if (res != TEE_SUCCESS) {
		goto out;
	}

	// Init params and call PTA_GENERATE_RSA

	params[0].value.a = obj_size;
	params[1].memref.buffer = modulus;
	params[1].memref.size = MAX_KEY_SIZE_BYTES;
	params[2].memref.buffer = pub_exp;
	params[2].memref.size = pub_exp_size;
	params[3].memref.buffer = priv_exp;
	params[3].memref.size = MAX_KEY_SIZE_BYTES;

	res = TEE_InvokeTACommand(session, 0, PTA_GENERATE_RSAKEY_CMD, exp_param_types,
				params, &err_origin);
	if (res != TEE_SUCCESS)
		goto out;
	
	mod_size = params[1].memref.size;
	pub_exp_size = params[2].memref.size;
	priv_exp_size = params[3].memref.size;

	attrs[*attr_count].type = SK_ATTR_MODULUS;
	attrs[*attr_count].value = modulus;
	attrs[*attr_count].valueLen = mod_size;
	(*attr_count)++;

	attrs[*attr_count].type = SK_ATTR_PUBLIC_EXPONENT;
	attrs[*attr_count].value = pub_exp;
	attrs[*attr_count].valueLen = pub_exp_size;
	(*attr_count)++;

	attrs[*attr_count].type = SK_ATTR_PRIVATE_EXPONENT;
	attrs[*attr_count].value = priv_exp;
	attrs[*attr_count].valueLen = priv_exp_size;
	(*attr_count)++;

	/* Check if RSA key object index is passed in input attrs */
	get_attr = TA_GetSKAttr(SK_ATTR_OBJECT_INDEX, in_attrs,
				in_attr_cnt);
	if (get_attr) {
		attrs[*attr_count].type = get_attr->type;
		attrs[*attr_count].value = get_attr->value;
		attrs[*attr_count].valueLen = get_attr->valueLen;
		(*attr_count)++;
	}

	/* Check if RSA key object label is passed in input attrs */
	get_attr = TA_GetSKAttr(SK_ATTR_OBJECT_LABEL, in_attrs,
				in_attr_cnt);
	if (get_attr) {
		attrs[*attr_count].type = get_attr->type;
		attrs[*attr_count].value = get_attr->value;
		attrs[*attr_count].valueLen = get_attr->valueLen;
		(*attr_count)++;
	} 

	res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, obj_size, tObject);
	if (res != TEE_SUCCESS)
        goto out;

out:
	if (in_attrs)
		TEE_Free(in_attrs);

	if (session)
		TEE_CloseTASession(session);

	return res;
}

/*
 * @brief Generates a RSA/ECC Key Pair
 * Input params:
 * param#0 : input key pair gen mechanism
 * param#1 : input serialized object attributes buffer
 * param#2 : output object ID
 * param#3 : not used
 */
TEE_Result TA_GenerateKeyPair(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	TEE_ObjectHandle tObject = TEE_HANDLE_NULL;
	SK_ATTRIBUTE attrs[MAX_KEY_PAIR_ATTRS] = {0};
	uint32_t attr_count = 0, next_obj_id = 0;
	SK_OBJECT_TYPE sk_obj_type;
	SK_KEY_TYPE sk_key_type;
	uint8_t *data = NULL;
	size_t data_len = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	DMSG("TA_GenerateKeyPair started!\n");

	switch (params[0].value.a) {
	case SKM_RSA_PKCS_KEY_PAIR_GEN:
		/* Fill SK attributes with obj type */
		sk_obj_type = SK_KEY_PAIR;
		attrs[attr_count].type = SK_ATTR_OBJECT_TYPE;
		attrs[attr_count].value = &sk_obj_type;
		attrs[attr_count].valueLen = sizeof(SK_OBJECT_TYPE);
		attr_count++;
		/* Fill SK attributes with key type */
		sk_key_type = SKK_RSA;
		attrs[attr_count].type = SK_ATTR_KEY_TYPE;
		attrs[attr_count].value = &sk_key_type;
		attrs[attr_count].valueLen = sizeof(SK_KEY_TYPE);
		attr_count++;

		/* Generate RSA key pair */
		res = TA_GenerateRSAKeyPair(&tObject, params[1].memref.buffer,
					    params[1].memref.size, attrs,
					    &attr_count);
		if (res != TEE_SUCCESS)
			goto out;
		break;
	case SKM_EC_PKCS_KEY_PAIR_GEN:
		/* Fill SK attributes with obj type */
		sk_obj_type = SK_KEY_PAIR;
		attrs[attr_count].type = SK_ATTR_OBJECT_TYPE;
		attrs[attr_count].value = &sk_obj_type;
		attrs[attr_count].valueLen = sizeof(SK_OBJECT_TYPE);
		attr_count++;

		/* Fill SK attributes with key type */
		sk_key_type = SKK_EC;
		attrs[attr_count].type = SK_ATTR_KEY_TYPE;
		attrs[attr_count].value = &sk_key_type;
		attrs[attr_count].valueLen = sizeof(SK_KEY_TYPE);
		attr_count++;

		/* Generate EC key pair */
		res = TA_GenerateECKeyPair(&tObject, params[1].memref.buffer,
					    params[1].memref.size, attrs,
					    &attr_count);
		if (res != TEE_SUCCESS)
			goto out;
		break;
	default:
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

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

	DMSG("Create Persistent Object 1 !\n");
	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &next_obj_id,
					sizeof(next_obj_id),
					TEE_DATA_FLAG_ACCESS_WRITE |
					TEE_DATA_FLAG_ACCESS_READ,
					tObject, data, data_len,
					TEE_HANDLE_NULL);
	if (res != TEE_SUCCESS)
		goto out;

	params[2].value.a = next_obj_id;

	DMSG("TA_GenerateKeyPair Successful!\n");
out:
	if (tObject != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(tObject);

	if (data)
		TEE_Free(data);

	return res;
}
