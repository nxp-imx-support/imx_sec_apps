/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "secure_storage_common.h"
/*
* @brief  Fills a TEE_Object data from a SK_RSA_KEY
*		
* @param[in]      attrs  		 SK_RSA_KEY attributes
* @param[in]      attr_count	 number of SK_RSA_KEY attributes
* @param[in/out]  tee_attrs      TEE Attributes to be filled
* @param[out]     tee_attr_count Number of TEE Attributes that has ben filled
*/
void fill_rsa_keypair_tee_attr(SK_ATTRIBUTE *attrs, uint32_t attr_count,
			       TEE_Attribute *tee_attrs,
			       uint32_t *tee_attr_count)
{
	uint32_t attr_cnt = 0;
	SK_ATTRIBUTE *attr_key;

	attr_key = TA_GetSKAttr(SK_ATTR_MODULUS, attrs,	attr_count);
	if (attr_key != NULL) {
		TEE_InitRefAttribute(&tee_attrs[0], TEE_ATTR_RSA_MODULUS,
				     attr_key->value, attr_key->valueLen);
		attr_cnt++;
	}
	attr_key = TA_GetSKAttr(SK_ATTR_PUBLIC_EXPONENT, attrs,	attr_count);
	if (attr_key != NULL) {
		TEE_InitRefAttribute(&tee_attrs[1],
				     TEE_ATTR_RSA_PUBLIC_EXPONENT,
				     attr_key->value, attr_key->valueLen);
		attr_cnt++;
	}
	attr_key = TA_GetSKAttr(SK_ATTR_PRIVATE_EXPONENT, attrs, attr_count);
	if (attr_key != NULL) {
		TEE_InitRefAttribute(&tee_attrs[2],
				     TEE_ATTR_RSA_PRIVATE_EXPONENT,
				     attr_key->value, attr_key->valueLen);
		attr_cnt++;
	}
	attr_key = TA_GetSKAttr(SK_ATTR_PRIME_1, attrs, attr_count);
	if (attr_key != NULL) {
		TEE_InitRefAttribute(&tee_attrs[3], TEE_ATTR_RSA_PRIME1,
				     attr_key->value, attr_key->valueLen);
		attr_cnt++;
	}
	attr_key = TA_GetSKAttr(SK_ATTR_PRIME_2, attrs, attr_count);
	if (attr_key != NULL) {
		TEE_InitRefAttribute(&tee_attrs[4], TEE_ATTR_RSA_PRIME2,
				     attr_key->value, attr_key->valueLen);
		attr_cnt++;
	}
	attr_key = TA_GetSKAttr(SK_ATTR_EXPONENT_1, attrs, attr_count);
	if (attr_key != NULL) {
		TEE_InitRefAttribute(&tee_attrs[5], TEE_ATTR_RSA_EXPONENT1,
				     attr_key->value, attr_key->valueLen);
		attr_cnt++;
	}
	attr_key = TA_GetSKAttr(SK_ATTR_EXPONENT_2, attrs, attr_count);
	if (attr_key != NULL) {
		TEE_InitRefAttribute(&tee_attrs[6], TEE_ATTR_RSA_EXPONENT2,
				     attr_key->value, attr_key->valueLen);
		attr_cnt++;
	}
	attr_key = TA_GetSKAttr(SK_ATTR_COEFFICIENT, attrs, attr_count);
	if (attr_key != NULL) {
		TEE_InitRefAttribute(&tee_attrs[7], TEE_ATTR_RSA_COEFFICIENT,
				     attr_key->value, attr_key->valueLen);
		attr_cnt++;
	}

	*tee_attr_count = attr_cnt;
}

/*
* @brief  Fills a TEE_Object public data from a SK_RSA_KEY
*		
* @param[in]      attrs  		 SK_RSA_KEY attributes
* @param[in]      attr_count	 number of SK_RSA_KEY attributes
* @param[in/out]  tee_attrs      TEE Attributes to be filled
* @param[out]     tee_attr_count Number of TEE Attributes that has ben filled
*/
void fill_rsa_pubkey_tee_attr(SK_ATTRIBUTE *attrs, uint32_t attr_count,
			      TEE_Attribute *tee_attrs,
			      uint32_t *tee_attr_count)
{
	uint32_t attr_cnt = 0;
	SK_ATTRIBUTE *attr_key;

	attr_key = TA_GetSKAttr(SK_ATTR_MODULUS, attrs, attr_count);
	if (attr_key != NULL) {
		TEE_InitRefAttribute(&tee_attrs[0], TEE_ATTR_RSA_MODULUS,
				     attr_key->value, attr_key->valueLen);
		attr_cnt++;
	}
	attr_key = TA_GetSKAttr(SK_ATTR_PUBLIC_EXPONENT, attrs, attr_count);
	if (attr_key != NULL) {
		TEE_InitRefAttribute(&tee_attrs[1],
				     TEE_ATTR_RSA_PUBLIC_EXPONENT,
				     attr_key->value, attr_key->valueLen);
		attr_cnt++;
	}

	*tee_attr_count = attr_cnt;
}
