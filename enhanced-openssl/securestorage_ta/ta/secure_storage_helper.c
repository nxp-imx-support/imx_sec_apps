/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#define STR_TRACE_USER_TA "SECURE_STORAGE"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "string.h"
#include "secure_storage_common.h"

/* Round up the even multiple of size, size has to be a multiple of 2 */
#define ROUNDUP(v, size) (((v) + (size - 1)) & ~(size - 1))

struct attr_packed {
	uint32_t id;
	uint32_t a;
	uint32_t b;
};
/** 
 * @brief Transform SK_ATTRIBUTE list to uint8_t buffer
 * 
 * @params[in] attrs Attribute list
 * @params[in] attr_count Number of attributes
 * @params[out] buf The resulted buffer
 * @params[out] blen Buffer length
 */
TEE_Result pack_sk_attrs(const SK_ATTRIBUTE *attrs, uint32_t attr_count,
			 uint8_t **buf, size_t *blen)
{
	struct attr_packed *a;
	uint8_t *b;
	size_t bl;
	size_t n;
	uint32_t attr_pack = 0;

	*buf = NULL;
	*blen = 0;
	if (attr_count == 0)
		return TEE_SUCCESS;

	bl = sizeof(uint32_t);
	for (n = 0; n < attr_count; n++) {
		switch (attrs[n].type) {
		/* General Purpose Object Attributes */
		case SK_ATTR_OBJECT_TYPE:
		case SK_ATTR_OBJECT_INDEX:
		case SK_ATTR_KEY_TYPE:
		case SK_ATTR_OBJECT_LABEL:
		/* RSA Object Attributes */
		case SK_ATTR_MODULUS_BITS:
		case SK_ATTR_MODULUS:
		case SK_ATTR_PUBLIC_EXPONENT:
		case SK_ATTR_PRIVATE_EXPONENT:
		/* EC Object Attributes */
		case SK_ATTR_PRIV_VALUE:
		case SK_ATTR_PARAMS:
		case SK_ATTR_POINT:
			bl += sizeof(struct attr_packed);
			if (attrs[n].value != NULL &&
			    ((int16_t)attrs[n].valueLen) > 0)
				/* Make room for padding */
				bl += ROUNDUP(attrs[n].valueLen, 4);
			attr_pack++;
			break;
		default:
			break;
		}
	}

	b = TEE_Malloc(bl, 0);
	if (!b)
		return TEE_ERROR_OUT_OF_MEMORY;

	*buf = b;
	*blen = bl;

	*(uint32_t *)(void *)b = attr_pack;
	b += sizeof(uint32_t);
	a = (struct attr_packed *)(void *)b;
	b += sizeof(struct attr_packed) * attr_pack;
	DMSG("SK Attributes number %d\n", attr_count);
	for (n = 0; n < attr_count; n++) {
		switch (attrs[n].type) {
		/* General Purpose Object Attributes */
		case SK_ATTR_OBJECT_TYPE:
		case SK_ATTR_OBJECT_INDEX:
		case SK_ATTR_KEY_TYPE:
		case SK_ATTR_OBJECT_LABEL:
		/* RSA Object Attributes */
		case SK_ATTR_MODULUS_BITS:
		case SK_ATTR_MODULUS:
		case SK_ATTR_PUBLIC_EXPONENT:
		case SK_ATTR_PRIV_VALUE:
		case SK_ATTR_PRIVATE_EXPONENT:
		/* EC Object Attributes */
		case SK_ATTR_PARAMS:
		case SK_ATTR_POINT:
			a[n].id = attrs[n].type;
			a[n].b = attrs[n].valueLen;

			if ((((int16_t)attrs[n].valueLen) <= 0) ||
			    (attrs[n].value == NULL)) {
				a[n].a = 0;
				continue;
			}

			memcpy(b, attrs[n].value, attrs[n].valueLen);

			/* Make buffer pointer relative to *buf */
			a[n].a = (uint32_t)(uintptr_t)(b - *buf);

			/* Round up to good alignment */
			b += ROUNDUP(attrs[n].valueLen, 4);
			DMSG("SK Attribute - id: %lu, type: %d, value: %p, valueLen: %08x!\n",
				n, attrs[n].type, attrs[n].value, attrs[n].valueLen);
			break;
		default:
			break;
		}
	}

	return TEE_SUCCESS;
}
/** 
 * @brief Transforms uint8_t buffer to SK_ATTRIBUTE list 
 * 
 * @params[out] buf The resulted buffer
 * @params[out] blen Buffer length
 * @params[in] attrs Attribute list
 * @params[in] attr_count Number of attributes
 * 
 */

TEE_Result unpack_sk_attrs(const uint8_t *buf, size_t blen,
			   SK_ATTRIBUTE **attrs, uint32_t *attr_count)
{
	TEE_Result res = TEE_SUCCESS;
	SK_ATTRIBUTE *a = NULL;
	const struct attr_packed *ap;
	size_t num_attrs = 0;
	const size_t num_attrs_size = sizeof(uint32_t);

	if (blen == 0)
		goto out;

	if (((uintptr_t)buf & 0x3) != 0 || blen < num_attrs_size)
		return TEE_ERROR_BAD_PARAMETERS;
	num_attrs = *(uint32_t *) (void *)buf;
	if ((blen - num_attrs_size) < (num_attrs * sizeof(*ap)))
		return TEE_ERROR_BAD_PARAMETERS;
	ap = (const struct attr_packed *)(const void *)(buf + num_attrs_size);

	if (num_attrs > 0) {
		size_t n;

		a = TEE_Malloc(num_attrs * sizeof(SK_ATTRIBUTE), 0);
		if (!a)
			return TEE_ERROR_OUT_OF_MEMORY;
		for (n = 0; n < num_attrs; n++) {
			uintptr_t p;

			a[n].type = ap[n].id;
			a[n].valueLen = ap[n].b;
			p = (uintptr_t)ap[n].a;
			if (p) {
				if ((p + a[n].valueLen) > blen) {
					res = TEE_ERROR_BAD_PARAMETERS;
					goto out;
				}
				p += (uintptr_t)buf;
			}
			a[n].value = (void *)p;
			DMSG("SK Attribute - type: %d, value: %p, valueLen: %08x!\n",
				a[n].type, a[n].value, a[n].valueLen);
		}
	}

	res = TEE_SUCCESS;
out:
	if (res == TEE_SUCCESS) {
		*attrs = a;
		*attr_count = num_attrs;
	} else {
		TEE_Free(a);
	}
	return res;
}

/**
	* @brief Searches for a specific SK_ATTRIBUTE_TYPE in SK_ATTRIBUTE list
	* 
	* @param[in] type SK_ATTRIBUTE_TYPE
	* @param[in] attrs A list of attributes
	* @param[in] attr_count attributes number

	* @retval SK_ATTRIBUTE The specific attribute found
 */

SK_ATTRIBUTE *TA_GetSKAttr(SK_ATTRIBUTE_TYPE type, SK_ATTRIBUTE *attrs,
			   uint32_t attr_count)
{
	size_t i;
	SK_ATTRIBUTE *match_attr = NULL;

	for (i = 0; i < attr_count; i++) {
		if (type == attrs[i].type) {
			match_attr = &attrs[i];
			break;
		}
	}

	if (match_attr)
		DMSG("Match Attribute - type: %d value: %p, valueLen: %08x!\n",
			match_attr->type, match_attr->value, match_attr->valueLen);

	return match_attr;
}

/* Returns 1 if attributes match else 0 */
uint32_t TA_CompareSKAttr(SK_ATTRIBUTE *a1, SK_ATTRIBUTE *a2)
{
	if (a1->type != a2->type)
		return 0;

	if (a1->valueLen != a2->valueLen)
		return 0;

	if (memcmp(a1->value, a2->value, a1->valueLen))
		return 0;

	return 1;
}
