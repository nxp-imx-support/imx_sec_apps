/*
 * Copyright 2017 NXP
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <securekey_api.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <unistd.h>
#include "utils.h"
#include "rsa_data.h"

#define	SOBJ_KEY_ID	0xE1E2E3E4

struct getOptValue {
	uint32_t main_option;
	uint32_t numOfMainOpt;
	uint8_t *data;
	uint8_t *signed_data;
	uint8_t *importPrvFile;
	uint32_t key_len;
	SK_OBJECT_HANDLE hObj;
	uint32_t hObjc;
	SK_OBJECT_TYPE obj_type;
	uint32_t obj_id;
	SK_KEY_TYPE key_type;
	SK_MECHANISM_TYPE mech_type;
	char *label;
	int findCritCount;
	char *write_to_file;
	char *curve;
};

int import_ec_key(char *ec_file, ec_key_t **ec_key_ret)
{
	EVP_PKEY *ec_evp_pkey;
	EC_KEY *eckey;
	const EC_POINT *ec_pub_key;
	const BIGNUM *ec_priv_key;
	BIGNUM *bn_order = BN_new();
	ASN1_OBJECT *asn1_obj;
	const EC_GROUP *ec_group;
	ec_key_t *ec_key_st;
	int ec_key_len, ec_priv_len, der_enc_size;
	const char *sname;
	unsigned char *pubkey_oct = NULL, *ec_params_der, *ec_params_der_temp;
	int curve_nid = 0;
	int total_len, pubkey_oct_len, octet_len;

	FILE *fptr;
	int ret = APP_OK;

	fptr = fopen(ec_file, "rb");
	if (!fptr) {
		printf("Failure Opening Key File.\n");
		ret = APP_PEM_READ_ERROR;
		goto cleanup;
	}

	ec_evp_pkey = PEM_read_PrivateKey(fptr, NULL, NULL, NULL);
	if (ec_evp_pkey == NULL) {
		printf("Key with Label %s not found.\n", ec_file);
		ret = APP_PEM_READ_ERROR;
		goto cleanup;
	}

	eckey = EVP_PKEY_get1_EC_KEY(ec_evp_pkey);
	if (!eckey) {
		ret = APP_OPSSL_ERR;
		goto cleanup;
	}

	ec_priv_key = EC_KEY_get0_private_key(eckey);
	if (!ec_priv_key) {
		ret = APP_OPSSL_ERR;
		goto cleanup;
	}

	ec_pub_key = EC_KEY_get0_public_key(eckey);
	if (!ec_pub_key) {
		ret = APP_OPSSL_ERR;
		goto cleanup;
	}

	ec_group = EC_KEY_get0_group(eckey);
	if (!ec_group) {
		ret = APP_OPSSL_ERR;
		goto cleanup;
	}

	der_enc_size = i2d_ECPKParameters(ec_group, NULL);
	ec_params_der = malloc(der_enc_size);
	if (ec_params_der == NULL) {
		ret = APP_MALLOC_FAIL;
		goto cleanup;
	}
	ec_params_der_temp = ec_params_der;

	i2d_ECPKParameters(ec_group, &ec_params_der);

	EC_GROUP_get_order(ec_group, bn_order, NULL);

	ec_key_len = BN_num_bytes(bn_order);
	if (validate_ec_key_len(ec_key_len) == U32_INVALID) {
		ret = APP_SKR_ERR;
		goto cleanup;
	}

	pubkey_oct_len = (2 * ec_key_len) + 1;

	pubkey_oct = malloc(pubkey_oct_len);
	if (!pubkey_oct) {
		ret = APP_MALLOC_FAIL;
		goto cleanup;
	}

	octet_len = EC_POINT_point2oct(ec_group, ec_pub_key,
		POINT_CONVERSION_UNCOMPRESSED, pubkey_oct,
		pubkey_oct_len, NULL);
	if (pubkey_oct_len != octet_len) {
		ret = APP_PEM_READ_ERROR;
		goto cleanup;
	}

	ec_priv_len = BN_num_bytes(ec_priv_key);
	total_len = octet_len + ec_priv_len + der_enc_size;
	ec_key_st = malloc(total_len + sizeof(ec_key_t));
	if (!ec_key_st) {
		ret = APP_MALLOC_FAIL;
		goto cleanup;
	}

	ec_key_st->curve_nid = EC_GROUP_get_curve_name(ec_group);
	ec_key_st->params = (uint8_t *)ec_key_st + (sizeof(ec_key_t));
	ec_key_st->params_len = der_enc_size;
	ec_key_st->public_point = (uint8_t *)ec_key_st->params + ec_key_st->params_len;
	ec_key_st->public_point_len = octet_len;
	ec_key_st->priv_value = (uint8_t *)ec_key_st->public_point + ec_key_st->public_point_len;
	ec_key_st->priv_value_len = ec_priv_len;

	memcpy(ec_key_st->params, ec_params_der_temp, der_enc_size);
	memcpy(ec_key_st->public_point, pubkey_oct, ec_key_st->public_point_len);
	BN_bn2bin(ec_priv_key, ec_key_st->priv_value);

	*ec_key_ret = ec_key_st;

cleanup:
	if (pubkey_oct)
		free(pubkey_oct);
	if (fptr)
		fclose(fptr);

	return ret;
}

int generate_rsa_key(rsa_3form_key_t *rsa_3form_key, struct getOptValue *getOptVal)
{
	int             ret = APP_OK;
	BIGNUM          *bne = NULL;
	BIO             *bp_public = NULL, *bp_private = NULL;

	int             bits;
	unsigned long   e;
	RSA *rsa = NULL;

	if (getOptVal->importPrvFile) {
		printf("Import Key from %s\n", getOptVal->importPrvFile);
		bp_private = BIO_new(BIO_s_file());
		if (bp_private == NULL) {
			printf("Failure Opening BIO Object.\n");
			ret = APP_PEM_READ_ERROR;
			goto cleanup;
		}
		ret = BIO_read_filename(bp_private, getOptVal->importPrvFile);
		if (ret != 1) {
			printf("Reading Private Key Pem file Failed.\n");
			ret = APP_PEM_READ_ERROR;
			goto cleanup;
		}

		ret = APP_OK;

		rsa = PEM_read_bio_RSAPrivateKey(bp_private, &rsa, NULL, NULL);
		if (rsa == NULL) {
			printf("Fetching RSA Key from Pem file Failed.\n");
			ret = APP_PEM_READ_ERROR;
			goto cleanup;
		}
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		getOptVal->key_len = BN_num_bits(rsa->n);
#else
		getOptVal->key_len = RSA_bits(rsa);
#endif
		printf("Key Length = %d\n", getOptVal->key_len);

	} else {
		rsa = RSA_new();
		e = RSA_F4;
		bits = getOptVal->key_len;
		bne = BN_new();
		ret = BN_set_word(bne, e);
		if (ret != 1) {
			ret = APP_OPSSL_ERR;
			goto cleanup;
		}
		ret = APP_OK;
		ret = RSA_generate_key_ex(rsa, bits, bne, NULL);
		if (ret != 1) {
			ret = APP_OPSSL_ERR;
			goto cleanup;
		}
		ret = APP_OK;
		bp_public = BIO_new_file("sk_public.pem", "w+");
		ret = PEM_write_bio_RSAPublicKey(bp_public, rsa);
		if (ret != 1) {
			printf("Creating Public Key Pem file Failed.\n");
			ret = APP_OPSSL_ERR;
			goto cleanup;
		}

		ret = APP_OK;
		bp_private = BIO_new_file("sk_private.pem", "w+");
		ret = PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL);
		if (ret != 1) {
			printf("Creating Private Key Pem file Failed.\n");
			ret = APP_OPSSL_ERR;
			goto cleanup;
		}
		ret = APP_OK;
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	BN_bn2bin(rsa->n, rsa_3form_key->rsa_modulus);
	BN_bn2bin(rsa->e, rsa_3form_key->rsa_pub_exp);
	BN_bn2bin(rsa->d, rsa_3form_key->rsa_priv_exp);
	BN_bn2bin(rsa->p, rsa_3form_key->rsa_prime1);
	BN_bn2bin(rsa->q, rsa_3form_key->rsa_prime2);
	BN_bn2bin(rsa->dmp1, rsa_3form_key->rsa_exp1);
	BN_bn2bin(rsa->dmq1, rsa_3form_key->rsa_exp2);
	BN_bn2bin(rsa->iqmp, rsa_3form_key->rsa_coeff);
#else
	const BIGNUM *bn_n, *bn_e, *bn_d, *bn_p, *bn_q, *bn_dmp1, *bn_dmq1, *bn_iqmp;
	RSA_get0_key(rsa, &bn_n, &bn_e, &bn_d);
	RSA_get0_factors(rsa, &bn_p, &bn_q);
	RSA_get0_crt_params(rsa, &bn_dmp1, &bn_dmq1, &bn_iqmp);
	BN_bn2bin(bn_n, rsa_3form_key->rsa_modulus);
	BN_bn2bin(bn_e, rsa_3form_key->rsa_pub_exp);
	BN_bn2bin(bn_d, rsa_3form_key->rsa_priv_exp);
	BN_bn2bin(bn_p, rsa_3form_key->rsa_prime1);
	BN_bn2bin(bn_q, rsa_3form_key->rsa_prime2);
	BN_bn2bin(bn_dmp1, rsa_3form_key->rsa_exp1);
	BN_bn2bin(bn_dmq1, rsa_3form_key->rsa_exp2);
	BN_bn2bin(bn_iqmp, rsa_3form_key->rsa_coeff);
#endif
cleanup:
	if (bp_public)
		BIO_free_all(bp_public);

	if (bp_private)
		BIO_free_all(bp_private);

	if (bne)
		BN_free(bne);

	if (rsa)
		RSA_free(rsa);

	return ret;
}

static void populate_attrs(SK_ATTRIBUTE *attrs, void *key, struct getOptValue *getOptVal)
{
	rsa_3form_key_t *rsa_3form_key;
	ec_key_t *ec_key;

	attrs[0].type = SK_ATTR_OBJECT_TYPE;
	attrs[0].value = &(getOptVal->obj_type);
	attrs[0].valueLen = sizeof(SK_OBJECT_TYPE);

	attrs[1].type = SK_ATTR_OBJECT_INDEX;
	attrs[1].value = &(getOptVal->obj_id);
	attrs[1].valueLen = sizeof(uint32_t);

	attrs[2].type = SK_ATTR_KEY_TYPE;
	attrs[2].value = &(getOptVal->key_type);
	attrs[2].valueLen = sizeof(SK_KEY_TYPE);

	attrs[3].type = SK_ATTR_OBJECT_LABEL;
	attrs[3].value = getOptVal->label;
	attrs[3].valueLen = strlen(getOptVal->label);

	switch (getOptVal->key_type) {
		case SKK_RSA:
			rsa_3form_key = (rsa_3form_key_t *) key;

			attrs[4].type = SK_ATTR_MODULUS_BITS;
			attrs[4].value = &(getOptVal->key_len);
			attrs[4].valueLen = sizeof(uint32_t);

			attrs[5].type = SK_ATTR_MODULUS;
			attrs[5].value = (void *)(rsa_3form_key->rsa_modulus);
			attrs[5].valueLen = ((getOptVal->key_len + 7) >> 3);

			attrs[6].type = SK_ATTR_PUBLIC_EXPONENT;
			attrs[6].value = (void *)(rsa_3form_key->rsa_pub_exp);
			attrs[6].valueLen = 3;

			attrs[7].type = SK_ATTR_PRIVATE_EXPONENT;
			attrs[7].value = (void *)(rsa_3form_key->rsa_priv_exp);
			attrs[7].valueLen = ((getOptVal->key_len + 7) >> 3);

			attrs[8].type = SK_ATTR_PRIME_1;
			attrs[8].value = (void *)(rsa_3form_key->rsa_prime1);
			attrs[8].valueLen = ((getOptVal->key_len + 7) >> 3)/2;

			attrs[9].type = SK_ATTR_PRIME_2;
			attrs[9].value = (void *)(rsa_3form_key->rsa_prime2);
			attrs[9].valueLen = ((getOptVal->key_len + 7) >> 3)/2;

			attrs[10].type = SK_ATTR_EXPONENT_1;
			attrs[10].value = (void *)(rsa_3form_key->rsa_exp1);
			attrs[10].valueLen = ((getOptVal->key_len + 7) >> 3)/2;

			attrs[11].type = SK_ATTR_EXPONENT_2;
			attrs[11].value = (void *)(rsa_3form_key->rsa_exp2);
			attrs[11].valueLen = ((getOptVal->key_len + 7) >> 3)/2;

			attrs[12].type = SK_ATTR_COEFFICIENT;
			attrs[12].value = (void *)(rsa_3form_key->rsa_coeff);
			attrs[12].valueLen = ((getOptVal->key_len + 7) >> 3)/2;
			break;
		case SKK_EC:
			ec_key = (ec_key_t *)key;;
			attrs[4].type = SK_ATTR_PARAMS;
			attrs[4].value = ec_key->params;
			attrs[4].valueLen = ec_key->params_len;

			attrs[5].type = SK_ATTR_POINT;
			attrs[5].value = ec_key->public_point;
			attrs[5].valueLen = ec_key->public_point_len;

			attrs[6].type = SK_ATTR_PRIV_VALUE;
			attrs[6].value = ec_key->priv_value;
			attrs[6].valueLen = ec_key->priv_value_len;

			break;
		default:
			printf("Un-Supported Key Format\n");
			break;
	}
}

unsigned char *copy_bio_data(BIO *out, int *data_lenp)
{
	unsigned char *data, *tdata;
	int data_len;

	data_len = BIO_get_mem_data(out, &tdata);
	data = malloc(data_len+1);
	if (data) {
		memcpy(data, tdata, data_len);
		data[data_len]='\0';  // Make sure it's \0 terminated, in case used as string
		if (data_lenp) {
			*data_lenp = data_len;
		}
	} else {
		printf("malloc failed");
	}
	return data;
}

char *generate_fake_private_ec_key (int curve, uint32_t obj_id,
		void *ec_pub_point, uint16_t ec_point_len,
		void *ec_params, uint16_t ec_param_len)
{
	char *key_data = NULL;
	uint32_t *priv_key = NULL, priv_key_len  = 0;
	unsigned char *priv_key_temp = NULL;
	EC_KEY		*ec_key  = NULL;
	EC_POINT	*ec_point = NULL;
	const BIGNUM 	*ec_priv_key = NULL;
	int ec_curve_nid;
	int i = 0, j = 0;
	FILE *fptr;

	ec_curve_nid = curve;
	ec_key = EC_KEY_new_by_curve_name(ec_curve_nid);

	if (!(EC_KEY_generate_key(ec_key))) {
		printf("Error generating the ECC key.\n");
		goto end;
	}

	EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);

	ec_point = EC_POINT_new(EC_KEY_get0_group(ec_key));
	EC_POINT_oct2point(EC_KEY_get0_group(ec_key), ec_point,
			ec_pub_point, ec_point_len, NULL);
	EC_KEY_set_public_key(ec_key, ec_point);

	ec_priv_key = EC_KEY_get0_private_key(ec_key);
	if (!ec_priv_key) {
		printf("EC_KEY_get0_private_key failed\n");
		goto end;
	}

	priv_key_len = BN_num_bytes(ec_priv_key);
	priv_key_temp = (char *)malloc(priv_key_len);
	if (!priv_key_temp) {
		printf("malloc failed for priv_key_exp_temp\n");
		goto end;
	}

	priv_key_temp[0] = 0x10;

	priv_key_temp[priv_key_len - 1] = obj_id;
	for (j=0; j < 2; j++) {
		for (i=5; i<9; i++) {
			priv_key_temp[priv_key_len-i-(j*4)] = (uint8_t)(SOBJ_KEY_ID>> 8*(i-5));
		}
	}

#if 0
	for (i = 0; i < priv_key_len; i++) {
		printf("%02x:", priv_key_temp[i]);
		if (((i+1) %16) == 0)
			printf("\n");
	}
#endif

	if (!EC_KEY_set_private_key(ec_key,
		BN_bin2bn(priv_key_temp, priv_key_len, NULL))) {
		printf("EC_KEY_set_private_key failed\n");
		goto end;
	}

	BIO *out = BIO_new(BIO_s_mem());
	if (!out) {
		printf("BIO_new failed\n");
		goto end;
	}

	if (!PEM_write_bio_ECPrivateKey(out, ec_key, NULL, NULL, 0, NULL, NULL)) {
		printf("PEM_write_bio_ECPrivateKey failed\n");
		goto end;
	}

	key_data = (char *)copy_bio_data(out, NULL);

end:
	if (out)
		BIO_free(out);
	if (ec_key)
		EC_KEY_free(ec_key);

	return (key_data);
}

char *generate_fake_private_RSA_key (int key_size, uint32_t obj_id,
		void *pub_exp, uint16_t pub_exp_len, void *modulus, uint16_t modulus_len)
{
	char *key_data = NULL, *priv_key_exp_temp = NULL;
	uint32_t *priv_key_exp = NULL, priv_key_len  = 0;
	BIGNUM *bn_n = NULL, *bn_e = NULL, *bn_d_temp = NULL, *bn_d = NULL;
	int i = 0, j = 0;

	RSA *rsa = RSA_new();
	if (!rsa) {
		printf("RSA_new failed\n");
		goto end;
	}

	BIGNUM *bn = BN_new();
	if (!bn) {
		printf("BN_new failed\n");
		goto end;
	}

	BN_set_word(bn, 0x10001);
	RSA_generate_key_ex(rsa, key_size, bn, NULL);

	bn_e = BN_bin2bn(pub_exp, pub_exp_len, bn_e);
	if (!bn_e) {
		printf("BN_bin2bn failed for pub exp\n");
		goto end;
	}

	bn_n = BN_bin2bn(modulus, modulus_len, bn_n);
	if (!bn_n) {
		printf("BN_bin2bn failed for modulus\n");
		goto end;
	}

	priv_key_len = RSA_size(rsa);
	priv_key_exp_temp = (char *)malloc(priv_key_len);
	if (!priv_key_exp_temp) {
		printf("malloc failed for priv_key_exp_temp\n");
		goto end;
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	bn_d_temp = rsa->d;
#else
	RSA_get0_key(rsa, NULL, NULL, (const BIGNUM **)&bn_d_temp);
#endif
	BN_bn2bin(bn_d_temp, priv_key_exp_temp);

	priv_key_exp_temp[0] = 0x10;
	priv_key_exp = (uint32_t *)priv_key_exp_temp;

#if 0
	for (i = 1; i < priv_key_len; i++) {
		priv_key_exp_temp[i] = 0x00;
	}
#endif

	priv_key_exp_temp[priv_key_len - 1] = obj_id;
	for (j=0; j<2; j++) {
		for (i=5; i<9; i++) {
			priv_key_exp_temp[priv_key_len-i-(j*4)] = (uint8_t)(SOBJ_KEY_ID>> 8*(i-5));
		}
	}

#if 0
	for (i = 0; i < priv_key_len; i++) {
		printf("%02x:", priv_key_exp_temp[i]);
		if (((i+1) %16) == 0)
			printf("\n");
	}
#endif

	bn_d = BN_bin2bn((char *)priv_key_exp, priv_key_len, bn_d);
	if (!bn_d) {
		printf("BN_bin2bn failed for priv exp\n");
		goto end;
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	rsa->e = bn_e;
	rsa->n = bn_n;
	rsa->d = bn_d;
#else
	if (!RSA_set0_key(rsa, bn_n, bn_e, bn_d)) {
		printf("RSA_set0_key failed\n");
		goto end;
	}
#endif
	BIO *out = BIO_new(BIO_s_mem());
	if (!out) {
		printf("BIO_new failed\n");
		goto end;
	}

	if (!PEM_write_bio_RSAPrivateKey(out, rsa, NULL, NULL, 0, NULL, NULL)) {
		printf("PEM_write_bio_RSAPrivateKey failed\n");
		goto end;
	}

	key_data = (char *)copy_bio_data(out, NULL);
end:
	if (out)
		BIO_free(out);
	if (bn)
		BN_free(bn);
	if (rsa) {
		RSA_free(rsa);
		bn_n= NULL;
		bn_e = NULL;
		bn_d = NULL;
	}
	if (bn_n)
		BN_free(bn_n);
	if (bn_e)
		BN_free(bn_e);
	if (bn_d)
		BN_free(bn_d);
	if (priv_key_exp)
		free(priv_key_exp);
	return (key_data);
}

int get_der_enc_from_curve(char *curve_name, char **der_encoding,
			int *der_encoding_size)
{
	int nid, der_enc_size;
	unsigned char *ec_params_der, *ec_params_der_temp;

	EC_GROUP *group;

	nid = OBJ_sn2nid(curve_name);
	group = EC_GROUP_new_by_curve_name(nid);
	if (group == NULL) {
		printf("unable to create curve (%s)\n", curve_name);
		return APP_OPSSL_ERR;
	}

	EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
	EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_UNCOMPRESSED);

	der_enc_size = i2d_ECPKParameters(group, NULL);
	ec_params_der = malloc(der_enc_size);
	if (ec_params_der == NULL)
		return APP_MALLOC_FAIL;

	ec_params_der_temp = ec_params_der;

	i2d_ECPKParameters(group, &ec_params_der);

	*der_encoding = ec_params_der_temp;
	*der_encoding_size = der_enc_size;

	return APP_OK;
}

static int do_CreateObject(struct getOptValue *getOptVal)
{
	int ret = APP_OK, i = 0;;
	SK_ATTRIBUTE *attrs = NULL;
	SK_RET_CODE sk_ret;
	uint16_t attrCount = 0;
	SK_OBJECT_HANDLE hObject;
	uint32_t obj_id;
	FILE *fptr = NULL;
	char *key_data = NULL, *file_name = NULL;
	rsa_3form_key_t rsa_3form_key;
	ec_key_t *ec_key = NULL;

	switch (getOptVal->key_type) {
		case SKK_RSA:
			rsa_3form_key.rsa_modulus =
				(uint8_t *) malloc(5*((getOptVal->key_len + 7) >> 3));
			if (!rsa_3form_key.rsa_modulus) {
				printf("Failure in allocating memory.\n");
				ret = APP_MALLOC_FAIL;
				goto cleanup;
			}

			rsa_3form_key.rsa_pub_exp = rsa_3form_key.rsa_modulus + ((getOptVal->key_len + 7) >> 3);
			rsa_3form_key.rsa_priv_exp = rsa_3form_key.rsa_pub_exp + sizeof(RSA_F4);
			rsa_3form_key.rsa_prime1 = rsa_3form_key.rsa_priv_exp + ((getOptVal->key_len + 7) >> 3);
			rsa_3form_key.rsa_prime2 = rsa_3form_key.rsa_prime1 + ((getOptVal->key_len + 7) >> 3)/2;
			rsa_3form_key.rsa_exp1 = rsa_3form_key.rsa_prime2 + ((getOptVal->key_len + 7) >> 3)/2;
			rsa_3form_key.rsa_exp2 = rsa_3form_key.rsa_exp1 + ((getOptVal->key_len + 7) >> 3)/2;
			rsa_3form_key.rsa_coeff = rsa_3form_key.rsa_exp2 + ((getOptVal->key_len + 7) >> 3)/2;

			ret = generate_rsa_key(&rsa_3form_key, getOptVal);
			if (ret != APP_OK) {
				printf("Failure Generating RSA Key.\n");
				goto cleanup;
			}
			/*printRSA_key(&rsa_3form_key, getOptVal->key_len);*/

			attrCount = MAX_RSA_ATTRIBUTES;
			attrs = (SK_ATTRIBUTE *)malloc(sizeof(SK_ATTRIBUTE) * attrCount);
			if (attrs == NULL) {
				printf("malloc failed\n");
				ret = APP_MALLOC_FAIL;
				goto cleanup;
			}

			populate_attrs(attrs, &rsa_3form_key, getOptVal);
			break;
		case SKK_EC:
			if (getOptVal->importPrvFile) {
				ret = import_ec_key(getOptVal->importPrvFile, &ec_key);
				if (ret != APP_OK) {
					printf("Failure Generating RSA Key.\n");
					goto cleanup;
				}

				attrCount = MAX_EC_ATTRIBUTES;
				attrs = (SK_ATTRIBUTE *)malloc(sizeof(SK_ATTRIBUTE) * attrCount);
				if (attrs == NULL) {
					printf("malloc failed\n");
					ret = APP_MALLOC_FAIL;
					goto cleanup;
				}

				populate_attrs(attrs, ec_key, getOptVal);
			} else {
				ret = APP_PEM_READ_ERROR;
				goto cleanup;
			}
			break;
		default:
			goto cleanup;
			break;
	}

	ret = SK_CreateObject(attrs, attrCount, &hObject);
	if (ret != SKR_OK) {
		printf("SK_CreateObject failed wit err code = 0x%x\n", ret);
		ret = APP_SKR_ERR;
		goto cleanup;
	} else {
		ret = APP_OK;
		printf("Object created successfully handle = %u\n", hObject);
	}

	memset(attrs, 0, sizeof(SK_ATTRIBUTE) * attrCount);

	if (getOptVal->write_to_file) {
		switch (getOptVal->key_type) {
			case SKK_RSA:
				attrs[0].type = SK_ATTR_PUBLIC_EXPONENT;
				attrs[0].value = NULL;
				attrs[0].valueLen = 0;

				attrs[1].type = SK_ATTR_MODULUS;
				attrs[1].value = NULL;
				attrs[1].valueLen = 0;

				sk_ret = SK_GetObjectAttribute(hObject, attrs, 2);
				if (sk_ret != SKR_OK) {
					if (sk_ret == SKR_ERR_ITEM_NOT_FOUND)
						printf("\nObject Handle[%d] not found.\n", hObject);
					else
						printf("\nSK_GetObjectAttribute failed with code = 0x%x\n", sk_ret);

					ret = APP_SKR_ERR;
					goto cleanup;
				}

				ret = APP_OK;
				for (i = 0; i < 2; i++) {
					if ((int16_t)(attrs[i].valueLen) != -1) {
						attrs[i].value =
							(void *)malloc(attrs[i].valueLen);

						if (!attrs[i].value) {
							printf("malloc failed ATTR[%d].Value\n", i);
							ret = APP_MALLOC_FAIL;
							goto cleanup;
						}
					}
				}

				sk_ret = SK_GetObjectAttribute(hObject, attrs, 2);
				if (sk_ret != SKR_OK) {
					printf("Failed to Get Attribute Values.\n");
					ret = APP_SKR_ERR;
					goto cleanup;
				}

				/* Here we are generating a fake .pem file for satisfying
				   kubernetes/puppet use case */

				obj_id = getOptVal->obj_id;
				file_name = getOptVal->write_to_file;

				key_data = generate_fake_private_RSA_key(getOptVal->key_len, obj_id,
						attrs[0].value, attrs[0].valueLen,
						attrs[1].value, attrs[1].valueLen);
				if (!key_data) {
					printf("generate_fake_private_RSA_key failed \n");
					ret = APP_SKR_ERR;
					goto cleanup;
				}

				fptr = fopen(file_name, "wb");
				if (fptr == NULL) {
					printf("File does not exists\n");
					ret = APP_SKR_ERR;
					goto cleanup;
				}
				fwrite(key_data, sizeof(char), strlen(key_data), fptr);
			break;
			case SKK_EC:
				attrs[0].type = SK_ATTR_POINT;
				attrs[0].value = NULL;
				attrs[0].valueLen = 0;

				sk_ret = SK_GetObjectAttribute(hObject, attrs, 1);
				if (sk_ret != SKR_OK) {
					if (sk_ret == SKR_ERR_ITEM_NOT_FOUND)
						printf("\nObject Handle[%d] not found.\n", hObject);
					else
						printf("\nSK_GetObjectAttribute failed with code = 0x%x\n", sk_ret);

					ret = APP_SKR_ERR;
					goto cleanup;
				}

				ret = APP_OK;
				for (i = 0; i < 1; i++) {
					if ((int16_t)(attrs[i].valueLen) != -1) {
						attrs[i].value =
							(void *)malloc(attrs[i].valueLen);

						if (!attrs[i].value) {
							printf("malloc failed ATTR[%d].Value\n", i);
							ret = APP_MALLOC_FAIL;
							goto cleanup;
						}
					}
				}

				sk_ret = SK_GetObjectAttribute(hObject, attrs, 1);
				if (sk_ret != SKR_OK) {
					printf("Failed to Get Attribute Values.\n");
					ret = APP_SKR_ERR;
					goto cleanup;
				}


				obj_id = getOptVal->obj_id;
				file_name = getOptVal->write_to_file;

				key_data = generate_fake_private_ec_key(ec_key->curve_nid, obj_id,
						attrs[0].value, attrs[0].valueLen,
						attrs[1].value, attrs[1].valueLen);
				if (!key_data) {
					printf("generate_fake_private_ec_key failed \n");
					ret = APP_SKR_ERR;
					goto cleanup;
				}

				fptr = fopen(file_name, "wb");
				if (fptr == NULL) {
					printf("File does not exists\n");
					ret = APP_SKR_ERR;
					goto cleanup;
				}

				fwrite(key_data, sizeof(char), strlen(key_data), fptr);
				break;
			default:
				break;
		}
	}

cleanup:
	if (attrs) {
		for (i = 0; i < 2; i++) {
			if (attrs[i].value)
				free(attrs[i].value);
		}
	}
	free(attrs);

	switch (getOptVal->key_type) {
		case SKK_RSA:
			if (rsa_3form_key.rsa_modulus)
				free(rsa_3form_key.rsa_modulus);
			break;
		case SKK_EC:
			if (ec_key)
				free(ec_key);
		default:
			break;
	}

	if (key_data)
		free(key_data);
	if (fptr)
		fclose(fptr);

	return ret;
}

static int do_GenerateKeyPair(struct getOptValue *getOptVal)
{
#define	MAX_SK_ATTRS	4
	int ret = APP_OK, i = 0, der_enc_size = 0;
	SK_RET_CODE sk_ret;
	SK_ATTRIBUTE attrs[MAX_SK_ATTRS];
	uint16_t attrCount = 0;
	SK_OBJECT_HANDLE hObject;
	SK_MECHANISM_INFO mechanismType = {0};
	FILE *fptr = NULL;
	char *label = NULL, *file_name = NULL;
	char *key_data = NULL, *curve_der_encoding = NULL;
	uint32_t obj_id;
	SK_KEY_TYPE key_type;

	mechanismType.mechanism = getOptVal->mech_type;

	attrs[attrCount].type = SK_ATTR_OBJECT_INDEX;
	attrs[attrCount].value = &(getOptVal->obj_id);
	attrs[attrCount].valueLen = sizeof(uint32_t);
	attrCount++;

	attrs[attrCount].type = SK_ATTR_OBJECT_LABEL;
	attrs[attrCount].value = getOptVal->label;
	attrs[attrCount].valueLen = strlen(getOptVal->label);
	attrCount++;

	switch (mechanismType.mechanism) {
		case SKM_RSA_PKCS_KEY_PAIR_GEN:
			key_type = SKK_RSA;
			attrs[attrCount].type = SK_ATTR_MODULUS_BITS;
			attrs[attrCount].value = &(getOptVal->key_len);
			attrs[attrCount].valueLen = sizeof(uint32_t);
			attrCount++;

			attrs[attrCount].type = SK_ATTR_PUBLIC_EXPONENT;
			attrs[attrCount].value = (void *)rsa_pub_exp;
			attrs[attrCount].valueLen = sizeof(rsa_pub_exp);
			attrCount++;

			break;

		case SKM_EC_PKCS_KEY_PAIR_GEN:
			key_type = SKK_EC;
			if (strcmp(getOptVal->curve, "prime256v1")
				&& strcmp(getOptVal->curve, "secp384r1")) {
				printf("Invalid/Unsupported Curve.\n");
				memset(attrs, 0, sizeof(SK_ATTRIBUTE) * attrCount);
				ret = APP_IP_ERR;
				goto end;
			}

			ret = get_der_enc_from_curve(getOptVal->curve,
						&curve_der_encoding,
						&der_enc_size);
			if (ret != APP_OK)
				goto end;

			attrs[attrCount].type = SK_ATTR_PARAMS;
			attrs[attrCount].value = curve_der_encoding;
			attrs[attrCount].valueLen = der_enc_size;
			attrCount++;
			break;
		default:
			ret = APP_IP_ERR;
			goto end;
	}

	sk_ret = SK_GenerateKeyPair(&mechanismType, attrs, attrCount, &hObject);
	if (sk_ret != SKR_OK) {
		printf("SK_GenerateKeyPair failed wit err code = 0x%x\n", sk_ret);
		ret = APP_SKR_ERR;
		goto end;
	} else {
		ret = APP_OK;
		printf("Object generated successfully handle = %u\n", hObject);
	}

	if (mechanismType.mechanism == SKM_EC_PKCS_KEY_PAIR_GEN)
		free(curve_der_encoding);

	memset(attrs, 0, sizeof(SK_ATTRIBUTE) * attrCount);

	/* Here we are generating a fake .pem file for satisfying
	   kubernetes/puppet use case */
	if (getOptVal->write_to_file) {
		switch (key_type) {
			case SKK_RSA:
				attrs[0].type = SK_ATTR_PUBLIC_EXPONENT;
				attrs[0].value = NULL;
				attrs[0].valueLen = 0;

				attrs[1].type = SK_ATTR_MODULUS;
				attrs[1].value = NULL;
				attrs[1].valueLen = 0;

				sk_ret = SK_GetObjectAttribute(hObject, attrs, 2);
				if (sk_ret != SKR_OK) {
					if (sk_ret == SKR_ERR_ITEM_NOT_FOUND)
						printf("\nObject Handle[%d] not found.\n", hObject);
					else
						printf("\nSK_GetObjectAttribute failed with code = 0x%x\n", sk_ret);

					ret = APP_SKR_ERR;
					goto end;
				}

				ret = APP_OK;
				for (i = 0; i < 2; i++) {
					if ((int16_t)(attrs[i].valueLen) != -1) {
						attrs[i].value =
							(void *)malloc(attrs[i].valueLen);

						if (!attrs[i].value) {
							printf("malloc failed ATTR[%d].Value\n", i);
							ret = APP_MALLOC_FAIL;
							goto end;
						}
					}
				}

				sk_ret = SK_GetObjectAttribute(hObject, attrs, 2);
				if (sk_ret != SKR_OK) {
					printf("Failed to Get Attribute Values.\n");
					ret = APP_SKR_ERR;
					goto end;
				}


				obj_id = getOptVal->obj_id;
				file_name = getOptVal->write_to_file;

				key_data = generate_fake_private_RSA_key(getOptVal->key_len, obj_id,
						attrs[0].value, attrs[0].valueLen,
						attrs[1].value, attrs[1].valueLen);
				if (!key_data) {
					printf("generate_fake_private_RSA_key failed \n");
					ret = APP_SKR_ERR;
					goto end;
				}

				fptr = fopen(file_name, "wb");
				if (fptr == NULL) {
					printf("File does not exists\n");
					ret = APP_SKR_ERR;
					goto end;
				}
				fwrite(key_data, sizeof(char), strlen(key_data), fptr);
				break;
			case SKK_EC:
				attrs[0].type = SK_ATTR_POINT;
				attrs[0].value = NULL;
				attrs[0].valueLen = 0;

				sk_ret = SK_GetObjectAttribute(hObject, attrs, 1);
				if (sk_ret != SKR_OK) {
					if (sk_ret == SKR_ERR_ITEM_NOT_FOUND)
						printf("\nObject Handle[%d] not found.\n", hObject);
					else
						printf("\nSK_GetObjectAttribute failed with code = 0x%x\n", sk_ret);

					ret = APP_SKR_ERR;
					goto end;
				}

				ret = APP_OK;
				for (i = 0; i < 1; i++) {
					if ((int16_t)(attrs[i].valueLen) != -1) {
						attrs[i].value =
							(void *)malloc(attrs[i].valueLen);

						if (!attrs[i].value) {
							printf("malloc failed ATTR[%d].Value\n", i);
							ret = APP_MALLOC_FAIL;
							goto end;
						}
					}
				}

				sk_ret = SK_GetObjectAttribute(hObject, attrs, 1);
				if (sk_ret != SKR_OK) {
					printf("Failed to Get Attribute Values.\n");
					ret = APP_SKR_ERR;
					goto end;
				}


				obj_id = getOptVal->obj_id;
				file_name = getOptVal->write_to_file;

				key_data = generate_fake_private_ec_key(OBJ_sn2nid(getOptVal->curve), obj_id,
						attrs[0].value, attrs[0].valueLen,
						attrs[1].value, attrs[1].valueLen);
				if (!key_data) {
					printf("generate_fake_private_ec_key failed \n");
					ret = APP_SKR_ERR;
					goto end;
				}

				fptr = fopen(file_name, "wb");
				if (fptr == NULL) {
					printf("File does not exists\n");
					ret = APP_SKR_ERR;
					goto end;
				}

				fwrite(key_data, sizeof(char), strlen(key_data), fptr);
				break;
			default:
				printf("Unsupported Key type\n");
		}
	}
end:
	for (i = 0; i < attrCount; i++) {
		if (attrs[i].value)
			free(attrs[i].value);
	}

	if (key_data)
		free(key_data);
	if (fptr)
		fclose(fptr);

	return ret;
}

static int do_EraseObject(SK_OBJECT_HANDLE hObject)
{
	int ret = APP_OK, i = 0;

	ret = SK_EraseObject(hObject);

	if (ret != SKR_OK) {
		printf("SK_EraseObject failed with code = 0x%x\n", ret);
		ret = APP_SKR_ERR;
	} else {
		ret = APP_OK;
		printf("SK_EraseObject successful\n");
	}

	return ret;
}

static int do_EnumerateObject(struct getOptValue *getOptVal)
{
	int ret = APP_OK, i = 0;
	SK_ATTRIBUTE *attrs = NULL;
	SK_OBJECT_HANDLE hObject[getOptVal->hObjc];
	uint32_t objCount;

	if (getOptVal->findCritCount) {
		attrs = (SK_ATTRIBUTE *)malloc(sizeof(SK_ATTRIBUTE) * getOptVal->findCritCount);
		if (attrs == NULL) {
			printf("Malloc Failed. Not Applying searching attributes.\n");
			goto enumerate;
		}
		if (getOptVal->obj_type != U32_UNINTZD) {
			attrs[i].type = SK_ATTR_OBJECT_TYPE;
			attrs[i].value = &(getOptVal->obj_type);
			attrs[i].valueLen = sizeof(SK_OBJECT_TYPE);
			i++;
		}
		if (getOptVal->obj_id != U32_UNINTZD) {
			attrs[i].type = SK_ATTR_OBJECT_INDEX;
			attrs[i].value = &(getOptVal->obj_id);
			attrs[i].valueLen = sizeof(SK_OBJECT_TYPE);
			i++;
		}
		if (getOptVal->key_type != U32_UNINTZD) {
			attrs[i].type = SK_ATTR_KEY_TYPE;
			attrs[i].value = &(getOptVal->key_type);
			attrs[i].valueLen = sizeof(SK_KEY_TYPE);
			i++;
		}
		if (getOptVal->label) {
			attrs[i].type = SK_ATTR_OBJECT_LABEL;
			attrs[i].value = getOptVal->label;
			attrs[i].valueLen = strlen(getOptVal->label);
			i++;
		}
		if (getOptVal->key_len != U32_UNINTZD) {
			/*
			 * Since only RSA keys are supported.
			 * Hence, setting type SK_ATTR_MODULUS_BITS
			 */
			attrs[i].type = SK_ATTR_MODULUS_BITS;
			attrs[i].value = &(getOptVal->key_len);
			attrs[i].valueLen = sizeof(uint32_t);
			i++;
		}
	}

enumerate:
	ret = SK_EnumerateObjects(attrs, i, hObject, getOptVal->hObjc,
			&objCount);
	if (ret != SKR_OK) {
		printf("SK_EnumerateObjects failed with code = 0x%x\n", ret);
		ret = APP_SKR_ERR;
	} else {
		ret = APP_OK;
		if (!objCount)
			printf("No Object Found.\n\n");
		printf("Following objects found:\n");
		for (i = 0; i < objCount; i++)
			printf("Object[%u] handle = %u\n", i, hObject[i]);
	}

	if (attrs)
		free(attrs);

	return ret;
}

static int do_GetObjectAttributes(SK_OBJECT_HANDLE hObject)
{
	int ret = APP_OK, i = 0, j = 0;
	int attrCount = 4;
	SK_ATTRIBUTE attrs[attrCount];
	SK_OBJECT_TYPE obj_type;
	SK_KEY_TYPE key_type;

	attrs[i].type = SK_ATTR_OBJECT_LABEL;
	attrs[i].value = NULL;
	attrs[i].valueLen = 0;
	i++;

	attrs[i].type = SK_ATTR_OBJECT_INDEX;
	attrs[i].value = NULL;
	attrs[i].valueLen = 0;
	i++;

	attrs[i].type = SK_ATTR_OBJECT_TYPE;
	attrs[i].value = NULL;
	attrs[i].valueLen = 0;
	i++;

	attrs[i].type = SK_ATTR_KEY_TYPE;
	attrs[i].value = NULL;
	attrs[i].valueLen = 0;
	i++;

	ret = SK_GetObjectAttribute(hObject, attrs, i);
	if (ret != SKR_OK) {
		if (ret == SKR_ERR_ITEM_NOT_FOUND)
			printf("\nObject Handle[%d] not found.\n", hObject);
		else
			printf("\nSK_GetObjectAttribute failed with code = 0x%x\n", ret);

		ret = APP_SKR_ERR;
		goto cleanup;
	}
	ret = APP_OK;
	for (j = 0; j < i; j++) {
		if ((int16_t)(attrs[j].valueLen) != -1) {
			attrs[j].value =
				(void *)malloc(attrs[j].valueLen);

			if (!attrs[j].value) {
				printf("malloc failed ATTR[%d].Value\n", j);
				ret = APP_MALLOC_FAIL;
				goto cleanup;
			}
		}
	}
	ret = SK_GetObjectAttribute(hObject, attrs, i);
	if (ret != SKR_OK) {
		printf("Failed to Get Attribute Values.\n");
		ret = APP_SKR_ERR;
		goto cleanup;
	}
	ret = APP_OK;

	printf("Attributes of Object Handle: %u\n", hObject);
	i = 0;
	printf("\tObject Label: %s\n", ((char *)(attrs[i].value)));

	i++;
	printf("\tObject Id: %u\n", *((char *)(attrs[i].value)));

	i++;
	printf("\tObject Type: %s[0x%x]\n", getObjTypeStr(*(SK_OBJECT_TYPE *)(attrs[i].value)),
			*(SK_OBJECT_TYPE *)(attrs[i].value));

	i++;
	printf("\tObject Key Type: %s[0x%x]\n", getKeyTypeStr(*(SK_KEY_TYPE *)(attrs[i].value)),
			*(SK_KEY_TYPE *)(attrs[i].value));

cleanup:
	for (j = 0; j < i; j++) {
		if (!attrs[j].value)
			free(attrs[j].value);
	}

	return ret;
}

void print_usage(void)
{
	printf("    Only one of the below options are allowed per execution:-\n\n");
	printf("\t -C - Create Object\n");
	printf("\t -G - Generate Object\n");
	printf("\t -A - Attributes of the Object\n");
	printf("\t -L - List Object\n");
	printf("\t -R - Remove/Erase Object\n\n");
	printf("\t Use below Sub options along with Main options:-\n");
	printf("\t\t -o - Object Type (Supported: pair, pub)\n");
	printf("\t\t -k - Key Type (Supported: rsa, ec)\n");
	printf("\t\t -s - RSA Key Size/Length (Supported: 1024, 2048).\n");
	printf("\t\t -c - EC Curve (Supported: prime256v1, secp384r1).\n");
	printf("\t\t -f - File Name (.pem) (Private Key).\n");
	printf("\t\t -l - Object Label\n");
	printf("\t\t -i - Object Id. (In Decimal)\n");
	printf("\t\t -h - Object Handle (In Decimal)\n");
	printf("\t\t -n - Number of Objects (Default = 5)\n");
	printf("\t\t -m - Mechanism Id (Supported: rsa-pair, ec-pair)\n");
	printf("\t\t -w - Fake .pem file.(Optional command while generating/creating RSA, ECDSA key-pair).\n\n");
	printf("\tUsage:\n");
	printf("\t\tCreation:\n");
	printf("\t\tsobj_app -C -f <private.pem> -k <key-type> -o <obj-type> -s <key-size> -l <obj-label> -i <obj-ID> [-w <file.pem>]\n");
	printf("\t\tsobj_app -C -f sk_private.pem -k rsa -o pair -s 2048 -l \"Device_Key\" -i 1\n");
	printf("\t\tsobj_app -C -f sk_private.pem -k ec -o pair -l \"Device_Key\" -i 1\n");
	printf("\t\tsobj_app -C -f sk_private.pem -k rsa -o pair -s 2048 -l \"Device_Key\" -i 1 -w dev_key.pem\n\n");
	printf("\t\tGeneration:\n");
	printf("\t\tsobj_app -G -m <mechanism-ID> -s <key-size> -l <key-label> -i <key-ID> [-w <file.pem>]\n");
	printf("\t\tsobj_app -G -m rsa-pair -s 2048 -l \"Device_Key\" -i 1\n");
	printf("\t\tsobj_app -G -m ec-pair -c prime256v1 -l \"Device_Key\" -i 1\n");
	printf("\t\tsobj_app -G -m rsa-pair -s 2048 -l \"Device_Key\" -i 1 -w dev_key.pem\n\n");
	printf("\t\tAttributes:\n");
	printf("\t\tsobj_app -A -h <obj-handle>\n");
	printf("\t\tsobj_app -A -h 1\n\n");
	printf("\t\tList:\n");
	printf("\t\tsobj_app -L [-n <num-of-obj> -k <key-type> -l <obj-label> -s <key-size> -i <obj-id>]\n");
	printf("\t\t Objects can be listed based on combination of any above criteria.\n\n");
	printf("\t\tRemove\n");
	printf("\t\tsobj_app -R -h <obj-handle>\n");
	printf("\t\tsobj_app -R -h 1\n\n");
}

int process_sub_option(int option, char *optarg, struct getOptValue *getOptVal)
{
	int ret = APP_OK;
	FILE *file;

	switch (option) {
		case 'f':
			getOptVal->importPrvFile = optarg;
			file = fopen(getOptVal->importPrvFile, "r");
			if (!file) {
				ret = APP_IP_ERR;
				printf("Error Opening the File.\n");
			}
			if (file)
				fclose(file);
			break;
		case 's':
			getOptVal->key_len = atoi(optarg);
			if (U32_INVALID == validate_key_len(getOptVal->key_len))
				ret = APP_IP_ERR;
			getOptVal->findCritCount++;
			break;
		case 'k':
			getOptVal->key_type = getKeyType(optarg);
			if (U32_INVALID == getOptVal->key_type)
				ret = APP_IP_ERR;
			getOptVal->findCritCount++;
			break;
		case 'l':
			getOptVal->label = optarg;
			getOptVal->findCritCount++;
			break;
		case 'o':
			getOptVal->obj_type = getObjectType(optarg);
			if (U32_INVALID == getOptVal->obj_type)
				ret = APP_IP_ERR;
			getOptVal->findCritCount++;
			break;
		case 'i':
			getOptVal->obj_id = atoi(optarg);
			getOptVal->findCritCount++;
			break;
		case 'h':
			getOptVal->hObj = atoi(optarg);
			break;
		case 'n':
			getOptVal->hObjc = atoi(optarg);
			break;
		case 'm':
			getOptVal->mech_type = getMechType(optarg);
			if (U32_INVALID == getOptVal->mech_type)
				ret = APP_IP_ERR;
			break;
		case 'w':
			getOptVal->write_to_file = optarg;
			break;
		case 'c':
			getOptVal->curve = optarg;
			break;
	}
	return ret;
}

int process_main_option(int operation,
		int option,
		char *optarg,
		struct getOptValue *getOptVal)
{
	int ret = APP_OK;

	switch (option) {
		case 'C':
			if (operation == PERFORM) {
				printf("Creating the Object.\n");
				if ((getOptVal->key_type != U32_UNINTZD)) {
					switch (getOptVal->key_type) {
						case SKK_RSA:
							if ((getOptVal->obj_type == U32_UNINTZD)
							|| (getOptVal->obj_id == U32_UNINTZD)
							|| (getOptVal->label == NULL)
							|| (getOptVal->key_len == U32_UNINTZD)
							|| (getOptVal->importPrvFile == NULL)) {
								printf("\tAbort: Missing or Invalid Value to the mandatory options [-f -k -o -i -l -s]\n");
								ret = APP_IP_ERR;
							}
						break;
						case SKK_EC:
							if ((getOptVal->obj_type == U32_UNINTZD)
							|| (getOptVal->obj_id == U32_UNINTZD)
							|| (getOptVal->label == NULL)
							|| (getOptVal->importPrvFile == NULL)) {
								printf("\tAbort: Missing or Invalid Value to the mandatory options [-f -k -o -i -l -s]\n");
								ret = APP_IP_ERR;
							}
						break;
					}
					if (ret != APP_OK)
						break;
				} else {
					printf("\tAbort: Missing options -k \n");
					ret = APP_IP_ERR;
					break;
				}
				ret = do_CreateObject(getOptVal);
			} else {
				getOptVal->main_option = option;
				(getOptVal->numOfMainOpt)++;
			}
			break;
		case 'G':
			if (operation == PERFORM) {
				printf("Generating the Object.\n");
				if ((getOptVal->mech_type != U32_UNINTZD)) {
					switch (getOptVal->mech_type) {
						case SKM_RSA_PKCS_KEY_PAIR_GEN:
							if ((getOptVal->obj_id == U32_UNINTZD)
							|| (getOptVal->label == NULL)
							|| (getOptVal->key_len == U32_UNINTZD)) {
								printf("\tAbort: Missing or Invalid Value to the mandatory options [-m -i -l -s]\n");
								ret = APP_IP_ERR;
							}
						break;
						case SKM_EC_PKCS_KEY_PAIR_GEN:
							if ((getOptVal->obj_id == U32_UNINTZD)
							|| (getOptVal->label == NULL)
							|| (getOptVal->curve == NULL)) {
								printf("\tAbort: Missing or Invalid Value to the mandatory options [-m -i -l -c]\n");
								ret = APP_IP_ERR;
							}
						break;
					}
					if (ret != APP_OK)
						break;
				} else {
					printf("\tAbort: Missing options -m \n");
					ret = APP_IP_ERR;
					break;
				}
				ret = do_GenerateKeyPair(getOptVal);
			} else {
				getOptVal->main_option = option;
				(getOptVal->numOfMainOpt)++;
			}
			break;
		case 'R':
			if (operation == PERFORM) {
				if (getOptVal->hObj == U32_UNINTZD) {
					printf("Object Handle is not provided to remove/erase. Missing[-h].\n");
					ret = APP_IP_ERR;
					break;
				}
				ret = do_EraseObject(getOptVal->hObj);
			} else {
				getOptVal->main_option = option;
				(getOptVal->numOfMainOpt)++;
			}
			break;
		case 'L':
			if (operation == PERFORM) {
				if (!getOptVal->findCritCount)
					printf("None of the search option (-i -o -k -s -l) is provided. Listing all Object.\n");
				if (getOptVal->hObjc == U32_UNINTZD) {
					printf("Missing Option [-n]. Listing max of 5 objects.\n");
					getOptVal->hObjc = MAX_FIND_OBJ_SIZE;
				}
				ret = do_EnumerateObject(getOptVal);
			} else {
				getOptVal->main_option = option;
				(getOptVal->numOfMainOpt)++;
			}
			break;
		case 'A':
			if (operation == PERFORM) {
				if (getOptVal->hObj == U32_UNINTZD) {
					printf("Object Handle is not provided for Attribute Listing. Missing[-h].\n");
					ret = APP_IP_ERR;
					break;
				}
				ret = do_GetObjectAttributes(getOptVal->hObj);
			} else {
				getOptVal->main_option = option;
				(getOptVal->numOfMainOpt)++;
			}
			break;
		default:
			if (getOptVal->numOfMainOpt) {
				if (option != '?')
					ret = process_sub_option(option, optarg, getOptVal);
			} else {
				print_usage();
				exit(EXIT_FAILURE);
			}
	}
	return ret;
}

int main(int argc, char *argv[])
{
	struct getOptValue getOptVal = {
		.main_option = U32_UNINTZD,
		.numOfMainOpt = 0,
		.data = NULL,
		.signed_data = NULL,
		.importPrvFile = NULL,
		.key_len = U32_UNINTZD,
		.hObj = U32_UNINTZD,
		.hObjc = U32_UNINTZD,
		.label = NULL,
		.key_type = U32_UNINTZD,
		.obj_type = U32_UNINTZD,
		.obj_id = U32_UNINTZD,
		.mech_type = U32_UNINTZD,
		.findCritCount = 0,
		.write_to_file = NULL,
		.curve = NULL,
	};

	int option;
	extern char *optarg; extern int optind;
	int ret = APP_OK;

	while ((option = getopt(argc, argv, "CGRLAf:i:k:gh:l:o:m:n:s:w:c:")) != -1) {
		ret = process_main_option(PARSE, option, optarg, &getOptVal);
		if (ret != APP_OK)
			break;
	}

	if (getOptVal.numOfMainOpt > 1) {
		printf("More than one option is given, Please check below for help.\n");
		print_usage();
		exit(EXIT_FAILURE);
	}

	/* Error Message will be printed during
	 * during parsing itself.
	 */
	if (ret != APP_OK)
		return ret;

	ret = process_main_option(PERFORM, getOptVal.main_option, optarg, &getOptVal);
	if (ret != APP_OK && ret != APP_IP_ERR) {
		if (ret == APP_SKR_ERR)
			printf("Command Failed due to SK Lib Error\n");
		else
			printf("Command Failed due to App: sobj_app error.\n");
	}
	return 0;
}

