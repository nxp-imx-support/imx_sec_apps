/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "string.h"
#include "secure_storage_common.h"

/*
 * @brief:	Erases and Secure Key Object from Trusted Application
 * Input params:
 * param#0 : object ID to be erased
 * param#1 : not used
 * param#2 : not used
 * param#3 : not used
 */
TEE_Result TA_EraseObject(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle pObject = TEE_HANDLE_NULL;
	uint32_t obj_id = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	obj_id = params[0].value.a;

	/* Try to open object */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, (void *)&obj_id,
				       sizeof(uint32_t),
				       TEE_DATA_FLAG_ACCESS_WRITE_META,
				       &pObject);
	if (res != TEE_SUCCESS)
		goto out;

	/* Try to erase object */
	TEE_CloseAndDeletePersistentObject(pObject);

	DMSG("Called TA_EraseObject, obj_id: %d!\n", obj_id);

out:
	return res;
}

/*
 * @brief: Fills an array with specific attributes from Secure Object
 * Input params:
 * param#0 : object ID
 * param#1 : inout serialized attributes buffer to be filled
 * param#2 : not used
 * param#3 : not used
 */
TEE_Result TA_GetObjectAttributes(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res, res_attr = TEE_SUCCESS;
	TEE_ObjectHandle pObject = TEE_HANDLE_NULL;
	TEE_ObjectInfo objectInfo;
	SK_ATTRIBUTE *attrs = NULL, *obj_attrs = NULL, *match_attr = NULL;
	uint32_t attr_cnt = 0, obj_attr_cnt = 0, obj_id = 0, n;
	uint8_t *data = NULL, *data_out = NULL;
	uint32_t data_len = 0;
	size_t data_out_len = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	DMSG("Unpack requested obj attributes!\n");
	res = unpack_sk_attrs(params[1].memref.buffer, params[1].memref.size,
			      &attrs, &attr_cnt);
	if (res != TEE_SUCCESS)
		goto out;

	obj_id = params[0].value.a;

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

	/* Try to read object */
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

	for (n = 0; n < attr_cnt; n++) {
		match_attr = TA_GetSKAttr(attrs[n].type, obj_attrs,
					  obj_attr_cnt);
		if (match_attr == NULL) {
			res_attr = TEE_ERROR_BAD_PARAMETERS;
			continue;
		}
		/*
		 * In case no buffer is passed for the attribute and
		 * attribute is found, valuelen would be filled with
		 * the length of buffer required for value.
		 */
		if (attrs[n].value == NULL) {
			attrs[n].valueLen = match_attr->valueLen;
			continue;
		}
		if (attrs[n].valueLen < match_attr->valueLen) {
			attrs[n].valueLen = -1;
			res_attr = TEE_ERROR_SHORT_BUFFER;
			continue;
		}
		attrs[n].valueLen = match_attr->valueLen;
		memcpy(attrs[n].value, match_attr->value, attrs[n].valueLen);
	}

	DMSG("Pack SK attributes!\n");
	res = pack_sk_attrs(attrs, attr_cnt, &data_out, &data_out_len);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Copy out data to shared memory!\n");
	if (data_out_len > params[1].memref.size) {
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}
	memcpy(params[1].memref.buffer, data_out, data_out_len);

	DMSG("Called TA_GetObjectAttributes: %d!\n", attr_cnt);

	if (res_attr != TEE_SUCCESS)
		res = res_attr;

out:
	if (pObject != TEE_HANDLE_NULL)
		TEE_CloseObject(pObject);
	if (attrs)
		TEE_Free(attrs);
	if (data)
		TEE_Free(data);
	if (obj_attrs)
		TEE_Free(obj_attrs);
	if (data_out)
		TEE_Free(data_out);

	return res;
}
