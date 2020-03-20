/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#ifndef SECURE_STORAGE_COMMON_H
#define SECURE_STORAGE_COMMON_H

#include "securekey_api_types.h"

/* Database API's declaration */
TEE_Result TA_OpenDatabase(void);
TEE_Result TA_GetNextObjectID(uint32_t *next_obj_id);
uint32_t get_obj_db_id_size(void);

/* Create Object API */
TEE_Result TA_CreateObject(uint32_t param_types, TEE_Param params[4]);

/* Generate Key Pair API */
TEE_Result TA_GenerateKeyPair(uint32_t param_types, TEE_Param params[4]);

/* Erase Object API */
TEE_Result TA_EraseObject(uint32_t param_types, TEE_Param params[4]);

/* Find Object API */
TEE_Result TA_FindObjects(uint32_t param_types, TEE_Param params[4]);

/* Get Attribute Object API */
TEE_Result TA_GetObjectAttributes(uint32_t param_types, TEE_Param params[4]);

/* Generate Digest API */
TEE_Result TA_DigestData(uint32_t param_types, TEE_Param params[4]);

/* Sign Digest API */
TEE_Result TA_SignDigest(uint32_t param_types, TEE_Param params[4]);

/* Decrypt Data API */
TEE_Result TA_DecryptData(uint32_t param_types, TEE_Param params[4]);

/* Helper API's declaration */
TEE_Result pack_sk_attrs(const SK_ATTRIBUTE *attrs, uint32_t attr_count,
			 uint8_t **buf, size_t *blen);
TEE_Result unpack_sk_attrs(const uint8_t *buf, size_t blen,
			   SK_ATTRIBUTE **attrs, uint32_t *attr_count);
SK_ATTRIBUTE *TA_GetSKAttr(SK_ATTRIBUTE_TYPE type, SK_ATTRIBUTE *attrs,
			   uint32_t attr_count);
uint32_t TA_CompareSKAttr(SK_ATTRIBUTE *a1, SK_ATTRIBUTE *a2);

/* RSA Specific API's declaration */
void fill_rsa_keypair_tee_attr(SK_ATTRIBUTE *attrs, uint32_t attr_count,
			       TEE_Attribute *tee_attrs,
			       uint32_t *tee_attr_count);
void fill_rsa_pubkey_tee_attr(SK_ATTRIBUTE *attrs, uint32_t attr_count,
			      TEE_Attribute *tee_attrs,
			      uint32_t *tee_attr_count);

/* RSA Specific API's declaration */
void fill_ec_keypair_tee_attr(SK_ATTRIBUTE *attrs, uint32_t attr_count,
			       TEE_Attribute *tee_attrs,
			       uint32_t *tee_attr_count, uint32_t obj_size);
void fill_ec_pubkey_tee_attr(SK_ATTRIBUTE *attrs, uint32_t attr_count,
			      TEE_Attribute *tee_attrs,
			      uint32_t *tee_attr_count, uint32_t obj_size);
int get_ec_obj_size(SK_ATTRIBUTE *attr, uint32_t *obj_size);

int get_ec_algorithm(size_t obj_size);

TEE_Result fill_rsa_struct(uint32_t obj_id, SK_RSA_KEY *rsa_key);

TEE_Result GetKeyAttributes(uint32_t obj_id, uint32_t attr_cnt, SK_ATTRIBUTE *attrs) ;

TEE_Result fill_ecc_struct(uint32_t obj_id, SK_ECC_KEY *ecc_key);

TEE_Result free_rsa_struct(SK_RSA_KEY* rsa_key) ;

TEE_Result free_ecc_struct(SK_ECC_KEY *ecc_key);

TEE_Result fill_rsa_buff(uint8_t *key, SK_RSA_KEY *rsa_key);

TEE_Result fill_ecc_buff(uint8_t *key, SK_ECC_KEY *ecc_key);

#endif /*SECURE_STORAGE_COMMON_H*/
