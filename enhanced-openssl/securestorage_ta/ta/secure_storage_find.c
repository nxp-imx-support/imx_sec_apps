/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "string.h"
#include "secure_storage_common.h"
/**
 * @brief   Returns all key objects stored
 *
 * @param[out]  obj       		Array of key objects
 * @param[out]  obj_cnt         Number of keys stored
 * @param[in]   max_obj_cnt     Max Object to be returned
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_SHORT_BUFFER      Output buffer too short
 * @retval TEE_ERROR_GENERIC           Generic error
 */

static TEE_Result TA_FindAllObjects(SK_OBJECT_HANDLE *obj, uint32_t *obj_cnt,
				    uint32_t max_obj_cnt)
{
	TEE_Result res;
	TEE_ObjectEnumHandle ehandle = TEE_HANDLE_NULL;
	uint8_t obj_id[TEE_OBJECT_ID_MAX_LEN] = {0};
	uint32_t obj_id_len = TEE_OBJECT_ID_MAX_LEN;
	uint32_t cnt = 0;

	res = TEE_AllocatePersistentObjectEnumerator(&ehandle);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_StartPersistentObjectEnumerator(ehandle,
						  TEE_STORAGE_PRIVATE);
	if (res != TEE_SUCCESS)
		goto out;

	while (1) {
		res = TEE_GetNextPersistentObject(ehandle, NULL, obj_id,
						  &obj_id_len);
		if (res != TEE_SUCCESS)
			break;

		DMSG("obj_id_len: %d!\n", obj_id_len);
		/* Skip database object type */
		if (obj_id_len != sizeof(uint32_t))
			continue;

		memcpy(&obj[cnt], obj_id, sizeof(uint32_t));

		cnt++;
		if (cnt >= max_obj_cnt)
			break;
	}

	if (res == TEE_ERROR_ITEM_NOT_FOUND)
		res = TEE_SUCCESS;
	else if (res != TEE_SUCCESS)
		goto out;

	*obj_cnt = cnt;

out:
	if (ehandle != TEE_HANDLE_NULL)
		TEE_FreePersistentObjectEnumerator(ehandle);

	return res;
}

/**
 * @brief   Checks if an object matches specific attributes
 *
 * @param[in]	attrs			Array of attributes to be matched
 * @param[in]   attr_count		Number of attributes to be matched
 * @param[in]  obj_id      		Specific object that has to be checked
 * @param[in]  objectInfo      	Object data
 * @param[out]  match     		0 if object isn't a match for specific attributes
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_SHORT_BUFFER      Output buffer too short
 * @retval TEE_ERROR_GENERIC           Generic error
 */

static TEE_Result match_attr_obj(SK_ATTRIBUTE *attrs, uint32_t attr_count,
			       void *obj_id, TEE_ObjectInfo *objectInfo,
			       uint32_t *match)
{
	TEE_Result res;
	TEE_ObjectHandle hObject = TEE_HANDLE_NULL;
	SK_ATTRIBUTE *obj_attrs = NULL, *match_attr = NULL;
	uint8_t *data = NULL;
	uint32_t data_len = 0, obj_attr_cnt = 0, n;

	*match = 0;

	/* Try to open object */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, (void *)obj_id,
				       sizeof(uint32_t),
				       TEE_DATA_FLAG_ACCESS_READ |
				       TEE_DATA_FLAG_SHARE_READ, &hObject);
	if (res != TEE_SUCCESS)
		goto out;

	data = TEE_Malloc(objectInfo->dataSize, 0);
	if (!data) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* Try to read object */
	res = TEE_ReadObjectData(hObject, data, objectInfo->dataSize,
				 &data_len);
	if ((res != TEE_SUCCESS) && (data_len != objectInfo->dataSize))
		goto out;

	obj_attr_cnt = *(uint32_t *)(void *)data;
	obj_attrs = TEE_Malloc(sizeof(SK_ATTRIBUTE) * obj_attr_cnt, 0);
	if (!obj_attrs) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = unpack_sk_attrs(data, data_len, &obj_attrs, &obj_attr_cnt);
	if (res != TEE_SUCCESS)
		goto out;

	for (n = 0; n < attr_count; n++) {
		match_attr = TA_GetSKAttr(attrs[n].type, obj_attrs,
					  obj_attr_cnt);
		if (match_attr == NULL)	{
			*match = 0;
			break;
		}

		*match = TA_CompareSKAttr(&attrs[n], match_attr);
		if (*match == 0)
			break;
	}

	if (*match == 1)
		DMSG("Object match successfull, id: %d!\n",
				 *(uint32_t *)obj_id);

out:
	if (hObject != TEE_HANDLE_NULL)
		TEE_CloseObject(hObject);
	if (data)
		TEE_Free(data);
	if (obj_attrs)
		TEE_Free(obj_attrs);

	return res;
}

/**
 * @brief   Returns an array of keys that contains specific attributes 
 *
 * @param[in]	attrs			Array of attributes to be matched
 * @param[in]   attr_count		Number of attributes to be matched
 * @param[out]  obj       		Array of key objects
 * @param[out]  obj_cnt         Number of keys stored
 * @param[in]   max_obj_cnt     Max Object to be returned
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_SHORT_BUFFER      Output buffer too short
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result TA_FindAttrMatchObjects(SK_ATTRIBUTE *attrs,
					  uint32_t attr_count,
					  SK_OBJECT_HANDLE *obj,
					  uint32_t *obj_cnt,
					  uint32_t max_obj_cnt)
{
	TEE_Result res;
	TEE_ObjectEnumHandle ehandle = TEE_HANDLE_NULL;
	TEE_ObjectInfo objectInfo;
	uint8_t obj_id[TEE_OBJECT_ID_MAX_LEN] = {0};
	uint32_t obj_id_len = TEE_OBJECT_ID_MAX_LEN;
	uint32_t cnt = 0, match = 0;

	res = TEE_AllocatePersistentObjectEnumerator(&ehandle);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_StartPersistentObjectEnumerator(ehandle,
						  TEE_STORAGE_PRIVATE);
	if (res != TEE_SUCCESS)
		goto out;

	while (1) {
		res = TEE_GetNextPersistentObject(ehandle, &objectInfo, obj_id,
						  &obj_id_len);
		if (res != TEE_SUCCESS)
			break;

		DMSG("obj_id_len: %d!\n", obj_id_len);
		/* Skip database object type */
		if (obj_id_len == get_obj_db_id_size())
			continue;

		/* Check for object match with attributes */
		res = match_attr_obj(attrs, attr_count,
				     obj_id, &objectInfo, &match);
		if (res != TEE_SUCCESS)
			break;
		/* If object didn't match, continue */
		if (match == 0)
			continue;

		memcpy(&obj[cnt], obj_id, sizeof(uint32_t));

		cnt++;
		if (cnt >= max_obj_cnt)
			break;
	}

	if (res == TEE_ERROR_ITEM_NOT_FOUND)
		res = TEE_SUCCESS;
	else if (res != TEE_SUCCESS)
		goto out;

	*obj_cnt = cnt;

out:
	if (ehandle != TEE_HANDLE_NULL)
		TEE_FreePersistentObjectEnumerator(ehandle);

	return res;
}

/*
 * Input params:
 * param#0 : input serialized attributes template used for find
 * param#1 : output object IDs buffer
 * param#2 : output object IDs count
 * param#3 : not used
 */
TEE_Result TA_FindObjects(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	SK_ATTRIBUTE *attrs = NULL;
	uint32_t attr_count = 0;
	SK_OBJECT_HANDLE *obj = NULL;
	uint32_t obj_cnt = 0, max_obj_cnt = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	obj = (SK_OBJECT_HANDLE *)params[1].memref.buffer;
	max_obj_cnt = params[1].memref.size / sizeof(SK_OBJECT_HANDLE);

	DMSG("Unpack Object attributes!\n");
	res = unpack_sk_attrs(params[0].memref.buffer, params[0].memref.size,
			      &attrs, &attr_count);
	if (res != TEE_SUCCESS)
		goto out;

	if (attr_count == 0) {
		DMSG("Enumerate all TA persistent objects!\n");
		res = TA_FindAllObjects(obj, &obj_cnt, max_obj_cnt);
		if (res != TEE_SUCCESS)
			goto out;
	} else {
		DMSG("Enumerate match TA persistent objects!\n");
		res = TA_FindAttrMatchObjects(attrs, attr_count, obj,
					      &obj_cnt, max_obj_cnt);
		if (res != TEE_SUCCESS)
			goto out;
	}

	params[2].value.a = obj_cnt;

	DMSG("Called TA_FindObjects, obj_cnt: %d!\n", params[2].value.a);

out:
	if (attrs)
		TEE_Free(attrs);

	return res;
}
