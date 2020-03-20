/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>

#include <openssl/objects.h>
#include <openssl/engine.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>

#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/tls1.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#include <openssl/ecdsa.h>
static ECDSA_METHOD *secureobj_ec = NULL;
#else
#include <openssl/ec.h>
static EC_KEY_METHOD *secureobj_ec = NULL;
#endif

#include "securekey_api.h"

#define	SOBJ_KEY_ID	0xE1E2E3E4
#define	PRINT_ERROR

#ifdef PRINT_ERROR
#define print_error(msg, ...) { \
printf("[SECURE_OBJ_ENG:%s, %d] Error: ", __func__, __LINE__); \
printf(msg, ##__VA_ARGS__); \
}
#else
#define print_error(msg, ...)
#endif

#ifdef PRINT_INFO
#define print_info(msg, ...) { \
printf("[SECURE_OBJ_ENG:%s, %d] Info: ", __func__, __LINE__); \
printf(msg, ##__VA_ARGS__); \
}
#else
#define print_info(msg, ...)
#endif

static const char *engine_id = "eng_secure_obj";
static const char *engine_name = "Secure Object OpenSSL Engine.";

static RSA_METHOD *secureobj_rsa = NULL;

#define	MAX_SEC_OBJECTS	50

static int secure_obj_ec_sign_setup (EC_KEY *eckey, BN_CTX *ctx,
			BIGNUM **kinv, BIGNUM **r)
{
	return 1;
}

static ECDSA_SIG *secure_obj_ec_sign_sig (const unsigned char *dgst, int dgst_len,
			const BIGNUM *inv, const BIGNUM *rp,
			EC_KEY *eckey)
{
	print_error("secure_obj_ec_sign_sig\n");
	int i = 0, j = 0, priv_key_len = 0, ret = 0;
	SK_RET_CODE sk_ret = 0;
	SK_MECHANISM_INFO mechType = {0};
	SK_ATTRIBUTE attrs[3];
	SK_OBJECT_HANDLE hObject = 0xFFFF, temp_hObject[MAX_SEC_OBJECTS];
	SK_OBJECT_TYPE obj_type;
	SK_KEY_TYPE key_type;
	uint32_t objCount, key_index;
	const BIGNUM 	*ec_priv_key = NULL;
	uint32_t sobj_key_id[2] = { 0, 0 };
	char *priv_key = NULL;
	char *priv_key_temp = NULL;
	const EC_POINT *ec_pub_key = NULL;
	unsigned char *ec_pub_key_oct = NULL;
	int ec_pub_key_oct_len = 0;
	SK_MECHANISM_INFO signType = {0};
	uint8_t *signature = NULL;
	uint16_t signature_len = 0, signature_len_bytes = 0;;
	ECDSA_SIG *ec_sig = NULL;
	BIGNUM *bn_r = NULL, *bn_s = NULL;
	EC_KEY *dup_eckey = NULL;

	/* Here we are getting the private key to find the object id
	  * which we encoded into private key while creating the key
	  */
	ec_priv_key = EC_KEY_get0_private_key(eckey);
	if (!ec_priv_key) {
		print_error("EC_KEY_get0_private_key failed\n");
		ret = -1;
		goto failure;
	}

	priv_key_len = BN_num_bytes(ec_priv_key);
	priv_key = malloc(priv_key_len);
	if (!priv_key) {
		print_error("malloc failed for priv_key\n");
		ret = -1;
		goto failure;
	}

	priv_key_temp = priv_key;
	BN_bn2bin(ec_priv_key, priv_key);

	for (j = 0; j<2; j++) {
		for (i = 5;i<9;i++) {
			sobj_key_id[j] |=priv_key[priv_key_len - i - (j * 4)] << 8 * (i - 5);
		}
	}

	if (!(((unsigned int)sobj_key_id[0] == (unsigned int)SOBJ_KEY_ID) &&
		((unsigned int)sobj_key_id[1] == (unsigned int)SOBJ_KEY_ID))) {
		print_info("Not a valid Secure Object Key, passing control to OpenSSL Function\n");
		ret = -2;
		goto send_to_openssl;
	}

	key_index = priv_key[priv_key_len - 1];

	/* Getting the EC Public key to match with public key of Secure
	  * key, because there may be the case where more than one
	  * key is having the same key id.
	  */
	ec_pub_key = EC_KEY_get0_public_key(eckey);
	if (!ec_pub_key) {
		print_error("EC_KEY_get0_public_key failed\n");
		ret = -1;
		goto failure;
	}

	ec_pub_key_oct_len = i2o_ECPublicKey(eckey, &ec_pub_key_oct);
	if (ec_pub_key_oct_len <= 0) {
		long err;
		err = ERR_get_error();
		print_error("%s\n",ERR_error_string(err, NULL));
		print_error("EC_KEY_get0_public_key failed\n");
		ret = -1;
		goto failure;
	}

	obj_type = SK_KEY_PAIR;
	key_type = SKK_EC;

	attrs[0].type = SK_ATTR_OBJECT_TYPE;
	attrs[0].value = &obj_type;
	attrs[0].valueLen = sizeof(SK_OBJECT_TYPE);

	attrs[1].type = SK_ATTR_KEY_TYPE;
	attrs[1].value = &key_type;
	attrs[1].valueLen = sizeof(SK_KEY_TYPE);

	attrs[2].type = SK_ATTR_OBJECT_INDEX;
	attrs[2].value = (void *)&key_index;
	attrs[2].valueLen = sizeof(uint32_t);

	sk_ret = SK_EnumerateObjects(attrs, 3, temp_hObject, MAX_SEC_OBJECTS, &objCount);
	if (sk_ret != SKR_OK) {
		print_error("SK_EnumerateObjects failed with code = 0x%x\n", sk_ret);
		ret = -1;
		memset(attrs, 0, 3 * sizeof(SK_ATTRIBUTE));
		goto failure;
	}

	memset(attrs, 0, 3 * sizeof(SK_ATTRIBUTE));
	if (objCount == 0) {
		print_error("No object found\n");
		ret = -1;
		goto failure;
	}

	for (i = 0; i < objCount; i++) {
		memset(attrs, 0, 3 * sizeof(SK_ATTRIBUTE));
		attrs[0].type = SK_ATTR_POINT;
		attrs[0].value = NULL;
		attrs[0].valueLen = 0;

		sk_ret = SK_GetObjectAttribute(temp_hObject[i], attrs, 1);
		if (sk_ret != SKR_OK) {
			print_error("SK_GetObjectAttribute failed for object %u with code = 0x%x\n",
				temp_hObject[i], sk_ret);
			continue;
		}

		if ((int16_t)(attrs[0].valueLen) != -1) {
			attrs[0].value =
				(void *)malloc(attrs[0].valueLen);
			if (!attrs[0].value) {
				print_error("malloc failed ATTR[%d].Value\n", i);
				ret = -1;
				goto failure;
			}
		}

		sk_ret = SK_GetObjectAttribute(temp_hObject[i], attrs, 1);
		if (sk_ret != SKR_OK) {
			print_error("SK_GetObjectAttribute failed for object %u with code = 0x%x\n",
				temp_hObject[i], sk_ret);
			continue;
		}

		if (!memcmp(attrs[0].value, ec_pub_key_oct, ec_pub_key_oct_len)) {
			print_info("got the match\n");
			hObject = temp_hObject[i];
			free(attrs[0].value);
			break;
		}
	}

	if (hObject == 0xFFFF) {
		print_error("Key Correponding to pem passed is not present in HSM\n");
		ret = -1;
		goto failure;
	}

	signType.mechanism = SKM_ECDSA_SHA1;
	sk_ret = SK_Sign(&signType, hObject, dgst, dgst_len,
			NULL, &signature_len);
	if (sk_ret != SKR_OK) {
		print_error("SK_Sign failed with ret code 0x%x\n", ret);
		ret = -1;
		goto failure;
	}

	signature_len_bytes = signature_len/8;
	signature = malloc(2 * signature_len_bytes);
	if (!signature) {
		print_error("malloc failed for signature\n");
		ret = -1;
		goto failure;
	}

	sk_ret = SK_Sign(&signType, hObject, dgst, dgst_len,
			signature, &signature_len);
	if (sk_ret != SKR_OK) {
		print_error("SK_Sign failed with ret code 0x%x\n", ret);
		ret = -1;
		goto failure;
	}

	ec_sig = ECDSA_SIG_new();
	if (!ec_sig) {
		print_error("ECDSA_SIG_new failed\n");
		ret = -1;
		goto failure;
	}

	bn_r = BN_bin2bn(signature, signature_len_bytes/2, bn_r);
	bn_s = BN_bin2bn(signature + (signature_len_bytes/2),
		signature_len_bytes/2, bn_s);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	ec_sig->r = bn_r;
	ec_sig->s = bn_s;
#else
	if (!ECDSA_SIG_set0(ec_sig, bn_r, bn_s)) {
		print_error("ECDSA_SIG_set0 failed\n");
		ret = -1;
		goto failure;
	}
#endif

send_to_openssl:
	if (ret == -2) {
		dup_eckey = EC_KEY_dup(eckey);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	                /* Attach OpenSSL's ECDSA methods to duplicate key */
		ECDSA_set_method(dup_eckey, ECDSA_OpenSSL());
#else
		EC_KEY_set_method(dup_eckey, EC_KEY_OpenSSL());
#endif
	                /* Invoke OpenSSL verify and return result */
		ec_sig = ECDSA_do_sign_ex(dgst, dgst_len, inv, rp,
					dup_eckey);
	                EC_KEY_free(dup_eckey);
	}

failure:
	if (priv_key_temp)
		free(priv_key_temp);

	if (signature)
		free(signature);

	return ec_sig;
}

static int secure_obj_ec_sign (int type, const unsigned char *dgst,
                                        int dlen, unsigned char *sig,
                                        unsigned int *siglen,
                                        const BIGNUM *kinv, const BIGNUM *r,
                                        EC_KEY *eckey)
{
	print_error("secure_obj_ec_sign\n");
	ECDSA_SIG *s;
	s = secure_obj_ec_sign_sig(dgst, dlen, kinv, r, eckey);
	if (s == NULL) {
		*siglen = 0;
		return 0;
	}
	*siglen = i2d_ECDSA_SIG(s, &sig);
	ECDSA_SIG_free(s);
	return 1;
}

static int secure_obj_ec_verify_sig(int type, const unsigned char *dgst, int dgst_len,
			const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)
{
	/* Here verification is done via openssl software implementation
	  * to check the interoperability.
	  */
	EC_KEY *dup_eckey = NULL;
	int ret = 0;

	dup_eckey = EC_KEY_dup(eckey);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
                /* Attach OpenSSL's ECDSA methods to duplicate key */
	if (!ECDSA_set_method(dup_eckey, ECDSA_OpenSSL())) {
		print_error("OpenSSL verify API ECDSA_set_method failure..\n");
		goto done;
	}
#else
	if (!EC_KEY_set_method(dup_eckey, EC_KEY_OpenSSL())) {
		print_error("OpenSSL verify API EC_KEY_set_method failure..\n");
		goto done;
	}
#endif
    /* Invoke OpenSSL verify and return result */
	ret = ECDSA_verify(type, *dgst, dgst_len, *sigbuf,
			sig_len, dup_eckey);
	EC_KEY_free(dup_eckey);

done:
                return ret;
}

static int secure_obj_rsa_priv_enc(int flen, const unsigned char *from,
                         unsigned char *to, RSA *rsa, int padding)
{
	print_error("secure_rsa_priv_enc\n");
	uint8_t *padded_from = NULL;
	uint16_t out_len = 0;
	int ret = 0, i = 0, j = 0;

	SK_RET_CODE sk_ret = SKR_OK;
	SK_MECHANISM_INFO mechType = {0};

	SK_ATTRIBUTE attrs[3];
	SK_OBJECT_HANDLE hObject = 0xFFFF, temp_hObject[MAX_SEC_OBJECTS];
	SK_OBJECT_TYPE obj_type;
	SK_KEY_TYPE key_type;
	uint32_t objCount, key_index;
	uint32_t rsa_key_len = 0;
	char *priv_exp = NULL, *modulus = NULL;
	uint32_t sobj_key_id[2] = { 0, 0 };
	BIGNUM *bn_d = NULL, *bn_n = NULL;

	memset(attrs, 0, 3 * sizeof(SK_ATTRIBUTE));
	memset(temp_hObject, 0, sizeof(SK_OBJECT_HANDLE) * MAX_SEC_OBJECTS);
	rsa_key_len = RSA_size(rsa);

	priv_exp = malloc(rsa_key_len);
	if (!priv_exp) {
		print_error("malloc failed for priv_exp_temp\n");
		ret = -1;
		goto failure;
	}

	modulus = malloc(rsa_key_len);
	if (!modulus) {
		print_error("malloc failed for modulus\n");
		ret = -1;
		goto failure;
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	bn_d = rsa->d;
	bn_n = rsa->n;
#else
	RSA_get0_key(rsa, (const BIGNUM **)&bn_n, NULL, (const BIGNUM **)&bn_d);
#endif
	BN_bn2bin(bn_d, priv_exp);
	BN_bn2bin(bn_n, modulus);

	for (j = 0; j<2; j++) {
		for (i = 5;i<9;i++) {
			sobj_key_id[j] |=priv_exp[rsa_key_len - i - (j * 4)] << 8 * (i - 5);
		}
	}

	if (!(((unsigned int)sobj_key_id[0] == (unsigned int)SOBJ_KEY_ID) &&
		((unsigned int)sobj_key_id[1] == (unsigned int)SOBJ_KEY_ID))) {
		print_info("Not a valid Secure Object Key, passing control to OpenSSL Function\n");
		ret = -2;
		goto failure;
	}

	key_index = priv_exp[rsa_key_len - 1];

	obj_type = SK_KEY_PAIR;
	key_type = SKK_RSA;

	mechType.mechanism = SKM_RSA_PKCS_NOPAD;

	attrs[0].type = SK_ATTR_OBJECT_TYPE;
	attrs[0].value = &obj_type;
	attrs[0].valueLen = sizeof(SK_OBJECT_TYPE);

	attrs[1].type = SK_ATTR_KEY_TYPE;
	attrs[1].value = &key_type;
	attrs[1].valueLen = sizeof(SK_KEY_TYPE);

	attrs[2].type = SK_ATTR_OBJECT_INDEX;
	attrs[2].value = (void *)&key_index;
	attrs[2].valueLen = sizeof(uint32_t);

	sk_ret = SK_EnumerateObjects(attrs, 3, temp_hObject, MAX_SEC_OBJECTS, &objCount);
	if (sk_ret != SKR_OK) {
		print_error("SK_EnumerateObjects failed with code = 0x%x\n", sk_ret);
		ret = -1;
		memset(attrs, 0, 3 * sizeof(SK_ATTRIBUTE));
		goto failure;
	}

	memset(attrs, 0, 3 * sizeof(SK_ATTRIBUTE));
	if (objCount == 0) {
		print_error("No object found\n");
		ret = -1;
		goto failure;
	}

	for (i = 0; i < objCount; i++) {
		memset(attrs, 0, 3 * sizeof(SK_ATTRIBUTE));
		attrs[0].type = SK_ATTR_MODULUS;
		attrs[0].value = NULL;
		attrs[0].valueLen = 0;

		sk_ret = SK_GetObjectAttribute(temp_hObject[i], attrs, 1);
		if (sk_ret != SKR_OK) {
			print_error("SK_GetObjectAttribute failed for object %u with code = 0x%x\n",
				temp_hObject[i], sk_ret);
			continue;
		}

		if ((int16_t)(attrs[0].valueLen) != -1) {
			attrs[0].value =
				(void *)malloc(attrs[0].valueLen);
			if (!attrs[0].value) {
				print_error("malloc failed ATTR[%d].Value\n", i);
				goto failure;
			}
		}

		sk_ret = SK_GetObjectAttribute(temp_hObject[i], attrs, 1);
		if (sk_ret != SKR_OK) {
			print_error("SK_GetObjectAttribute failed for object %u with code = 0x%x\n",
				temp_hObject[i], sk_ret);
			continue;
		}

		if (!memcmp(attrs[0].value, modulus, rsa_key_len)) {
			hObject = temp_hObject[i];
			break;
		}
	}

	if (hObject == 0xFFFF) {
		print_error("Key Correponding to pem passed is not present in HSM\n");
		ret = -1;
		goto failure;
	}

	out_len = rsa_key_len;

	padded_from = (uint8_t *)malloc(rsa_key_len);
	if (!padded_from) {
		print_error("padded_from malloc failed\n");
		ret = -1;
		goto failure;
	}

	switch (padding) {
		case RSA_PKCS1_PADDING:
			ret = RSA_padding_add_PKCS1_type_1(padded_from,
				rsa_key_len, from, flen);
			if (ret == 0) {
				print_error("RSA_padding_add_PKCS1_type_1 failed\n");
				ret = -1;
				goto failure;
			}
			break;
		default:
			print_error("Unsupported padding type, only RSA_PKCS1_PADDING is supported\n");
			ret  = -1;
			goto failure;
	}

	sk_ret = SK_Decrypt(&mechType, hObject, padded_from,
			rsa_key_len, to, &out_len);
	if (sk_ret != SKR_OK) {
		print_error("SK_Decrypt failed with ret code 0x%x\n", sk_ret);
		ret = -1;
		goto failure;
	}

	ret = rsa_key_len;

failure:
	if (padded_from)
		free(padded_from);
	if (modulus)
		free(modulus);
	if (priv_exp)
		free(priv_exp);

	for (i = 0; i < 3; i++) {
		if (attrs[i].value)
			free(attrs[i].value);
	}

	if (ret == -2) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		const RSA_METHOD *rsa_meth = RSA_PKCS1_SSLeay();
		ret = rsa_meth->rsa_priv_enc(flen, from, to, rsa, padding);
#else
		const RSA_METHOD *rsa_meth = RSA_PKCS1_OpenSSL();
		ret = (RSA_meth_get_priv_enc(rsa_meth))(flen, from, to,
					rsa, padding);
#endif
	}

	return ret;
}

static int secure_obj_rsa_priv_dec(int flen, const unsigned char *from,
                         unsigned char *to, RSA *rsa, int padding)
{
	print_error("secure_obj_rsa_priv_dec\n");
	uint8_t *padded_to = NULL;
	uint16_t out_len = 0;
	int ret = 0, i = 0, j = 0;

	SK_RET_CODE sk_ret = SKR_OK;
	SK_MECHANISM_INFO mechType = {0};

	SK_ATTRIBUTE attrs[3];
	SK_OBJECT_HANDLE hObject = 0xFFFF, temp_hObject[MAX_SEC_OBJECTS];
	SK_OBJECT_TYPE obj_type;
	SK_KEY_TYPE key_type;
	uint32_t objCount, key_index;
	uint32_t rsa_key_len = 0;
	char *priv_exp = NULL, *modulus = NULL;
	uint32_t sobj_key_id[2] = { 0, 0 };
	BIGNUM *bn_d = NULL, *bn_n = NULL;

	memset(attrs, 0, 3 * sizeof(SK_ATTRIBUTE));
	memset(temp_hObject, 0, sizeof(SK_OBJECT_HANDLE) * MAX_SEC_OBJECTS);
	rsa_key_len = RSA_size(rsa);

	priv_exp = malloc(rsa_key_len);
	if (!priv_exp) {
		print_error("malloc failed for priv_exp_temp\n");
		ret = -1;
		goto failure;
	}

	modulus = malloc(rsa_key_len);
	if (!modulus) {
		print_error("malloc failed for modulus\n");
		ret = -1;
		goto failure;
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	bn_d = rsa->d;
	bn_n = rsa->n;
#else
	RSA_get0_key(rsa, (const BIGNUM **)&bn_n, NULL, (const BIGNUM **)&bn_d);
#endif
	BN_bn2bin(bn_d, priv_exp);
	BN_bn2bin(bn_n, modulus);

	for (j = 0; j < 2; j++) {
		for (i = 5; i < 9; i++) {
			sobj_key_id[j] |= priv_exp[rsa_key_len - i - (j * 4)] << 8 * (i - 5);
		}
	}

	if (!(((unsigned int)sobj_key_id[0] == (unsigned int)SOBJ_KEY_ID) &&
		((unsigned int)sobj_key_id[1] == (unsigned int)SOBJ_KEY_ID))) {
		print_info("Not a valid Secure Object Key, passing control to OpenSSL Function\n");
		ret = -2;
		goto failure;
	}

	key_index = priv_exp[rsa_key_len - 1];

	obj_type = SK_KEY_PAIR;
	key_type = SKK_RSA;

	print_info("byte_key_size = %d, flen = %d, padding = %d\n",
		rsa_key_len, flen, padding);

	attrs[0].type = SK_ATTR_OBJECT_TYPE;
	attrs[0].value = &obj_type;
	attrs[0].valueLen = sizeof(SK_OBJECT_TYPE);

	attrs[1].type = SK_ATTR_KEY_TYPE;
	attrs[1].value = &key_type;
	attrs[1].valueLen = sizeof(SK_KEY_TYPE);

	attrs[2].type = SK_ATTR_OBJECT_INDEX;
	attrs[2].value = (void *)&key_index;
	attrs[2].valueLen = sizeof(uint32_t);

	sk_ret = SK_EnumerateObjects(attrs, 3, temp_hObject, MAX_SEC_OBJECTS, &objCount);
	if (sk_ret != SKR_OK) {
		print_error("SK_EnumerateObjects failed with code = 0x%x\n", sk_ret);
		ret = -1;
		memset(attrs, 0, 3 * sizeof(SK_ATTRIBUTE));
		goto failure;
	}

	memset(attrs, 0, 3 * sizeof(SK_ATTRIBUTE));
	if (objCount == 0) {
		print_error("No object found\n");
		ret = -1;
		goto failure;
	}

	for (i = 0; i < objCount; i++) {
		memset(attrs, 0, 3 * sizeof(SK_ATTRIBUTE));
		attrs[0].type = SK_ATTR_MODULUS;
		attrs[0].value = NULL;
		attrs[0].valueLen = 0;

		sk_ret = SK_GetObjectAttribute(temp_hObject[i], attrs, 1);
		if (sk_ret != SKR_OK) {
			print_error("SK_GetObjectAttribute failed for object %u with code = 0x%x\n",
				temp_hObject[i], sk_ret);
			continue;
		}

		if ((int16_t)(attrs[0].valueLen) != -1) {
			attrs[0].value =
				(void *)malloc(attrs[0].valueLen);
			if (!attrs[0].value) {
				print_error("malloc failed ATTR[%d].Value\n", i);
				goto failure;
			}
		}

		sk_ret = SK_GetObjectAttribute(temp_hObject[i], attrs, 1);
		if (sk_ret != SKR_OK) {
			print_error("SK_GetObjectAttribute failed for object %u with code = 0x%x\n",
				temp_hObject[i], sk_ret);
			continue;
		}

		if (!memcmp(attrs[0].value, modulus, rsa_key_len)) {
			hObject = temp_hObject[i];
			break;
		}
	}

	if (hObject == 0xFFFF) {
		print_error("Key Correponding to pem passed is not present in HSM\n");
		ret = -1;
		goto failure;
	}

	padded_to = (uint8_t *)malloc(rsa_key_len);
	if (padded_to == NULL) {
		print_error("padded_to malloc  failed\n");
		ret = -1;
		goto failure;
	}

	mechType.mechanism = SKM_RSA_PKCS_NOPAD;

	out_len = rsa_key_len;

	sk_ret = SK_Decrypt(&mechType, hObject, from, flen,
			padded_to, &out_len);
	if (sk_ret != SKR_OK) {
		print_error("SK_Decrypt failed with ret code 0x%x\n", sk_ret);
		ret = -1;
		goto failure;
	}

	print_info("out_len = %u\n", out_len);

	switch (padding) {
		case RSA_PKCS1_PADDING:
			ret = RSA_padding_check_PKCS1_type_2(to,
				rsa_key_len, padded_to, out_len,
				rsa_key_len);
			if (ret == -1) {
				print_error("RSA_padding_check_PKCS1_type_2 failed\n");
				ret = -1;
				goto failure;
			}
			break;
		default:
			print_error("Unsupported padding type, only RSA_PKCS1_PADDING is supported\n");
			ret = -1;
			goto failure;
	}

failure:
	if (padded_to)
		free(padded_to);
	if (modulus)
		free(modulus);
	if (priv_exp)
		free(priv_exp);

	for (i = 0; i < 3; i++) {
		if (attrs[i].value)
			free(attrs[i].value);
	}

	if (ret == -2) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		const RSA_METHOD *rsa_meth = RSA_PKCS1_SSLeay();
		ret = rsa_meth->rsa_priv_dec(flen, from, to, rsa, padding);
#else
		const RSA_METHOD *rsa_meth = RSA_PKCS1_OpenSSL();
		ret = (RSA_meth_get_priv_dec(rsa_meth))(flen, from, to,
						rsa, padding);
#endif
	}

	return ret;
}

static int bind(ENGINE *engine, const char *id)
{
	int ret = 0;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	secureobj_ec = ECDSA_METHOD_new(NULL);
	if (secureobj_ec == NULL)
		goto end;

	ECDSA_METHOD_set_name(secureobj_ec, "Secure Object ECDSA Method");
	ECDSA_METHOD_set_sign(secureobj_ec, secure_obj_ec_sign);
	ECDSA_METHOD_set_sign_setup(secureobj_ec, secure_obj_ec_sign_setup);
	ECDSA_METHOD_set_verify(secureobj_ec, secure_obj_ec_verify_sig);
	ECDSA_METHOD_set_flags(secureobj_ec, 0);
	ECDSA_METHOD_set_app_data(secureobj_ec, NULL);

	if (!ENGINE_set_ECDSA(engine, secureobj_ec)) {
		print_error("ENGINE_set_ECDSA  failed\n");
		goto end;
	}

	secureobj_rsa = malloc(sizeof(RSA_METHOD));
	if (secureobj_rsa == NULL)
		goto end;

	memset(secureobj_rsa, 0, sizeof(RSA_METHOD));
	if (ENGINE_set_RSA(engine, secureobj_rsa)) {
		const RSA_METHOD *rsa_meth = RSA_PKCS1_SSLeay();

		secureobj_rsa->name = "Secure Object RSA Method";
		secureobj_rsa->rsa_pub_enc = rsa_meth->rsa_pub_enc;
		secureobj_rsa->rsa_pub_dec = rsa_meth->rsa_pub_dec;
		secureobj_rsa->rsa_priv_enc = secure_obj_rsa_priv_enc;
		secureobj_rsa->rsa_priv_dec = secure_obj_rsa_priv_dec;
		secureobj_rsa->rsa_mod_exp = rsa_meth->rsa_mod_exp;
		secureobj_rsa->bn_mod_exp = rsa_meth->bn_mod_exp;
		secureobj_rsa->init = NULL;
		secureobj_rsa->finish = NULL;
		secureobj_rsa->flags = 0;
		secureobj_rsa->app_data = NULL;
		secureobj_rsa->rsa_sign = NULL;
		secureobj_rsa->rsa_verify = NULL;
		secureobj_rsa->rsa_keygen = rsa_meth->rsa_keygen;
	} else {
		print_error("ENGINE_set_RSA failed\n");
		goto end;
	}
#else
	secureobj_ec = EC_KEY_METHOD_new(NULL);
	if (secureobj_ec == NULL) {
		print_error("EC_KEY_METHOD_new  failed\n");
		goto end;
	}

	int (*pkeygen)(EC_KEY *key);
	int (*compute_key)(unsigned char **pout, size_t *poutlen,
                       const EC_POINT *pub_key, const EC_KEY *ecdh);
	EC_KEY_METHOD_get_keygen(EC_KEY_OpenSSL(), &pkeygen);
	EC_KEY_METHOD_get_compute_key(EC_KEY_OpenSSL(), &compute_key);

	EC_KEY_METHOD_set_init(secureobj_ec, 0, 0, 0, 0, 0, 0);
	EC_KEY_METHOD_set_keygen(secureobj_ec, pkeygen);
	EC_KEY_METHOD_set_compute_key(secureobj_ec, compute_key);
	EC_KEY_METHOD_set_sign(secureobj_ec, secure_obj_ec_sign,
				secure_obj_ec_sign_setup,
				secure_obj_ec_sign_sig);
	EC_KEY_METHOD_set_verify(secureobj_ec, secure_obj_ec_verify_sig);

	if (!ENGINE_set_EC(engine, secureobj_ec)) {
		print_error("ENGINE_set_ECDSA  failed\n");
		goto end;
	}

	secureobj_rsa = RSA_meth_new("Secure Object RSA Method", 0);
	if (secureobj_rsa == NULL) {
		print_error("RSA_meth_new  failed\n");
		goto end;
	}

	if (ENGINE_set_RSA(engine, secureobj_rsa)) {
		const RSA_METHOD *rsa_meth = RSA_PKCS1_OpenSSL();

		RSA_meth_set_pub_enc(secureobj_rsa, RSA_meth_get_pub_enc(rsa_meth));
		RSA_meth_set_pub_dec(secureobj_rsa, RSA_meth_get_pub_dec(rsa_meth));
		RSA_meth_set_priv_enc(secureobj_rsa, secure_obj_rsa_priv_enc);
		RSA_meth_set_priv_dec(secureobj_rsa, secure_obj_rsa_priv_dec);
		RSA_meth_set_mod_exp(secureobj_rsa, RSA_meth_get_mod_exp(rsa_meth));
		RSA_meth_set_bn_mod_exp(secureobj_rsa, RSA_meth_get_bn_mod_exp(rsa_meth));
		RSA_meth_set_init(secureobj_rsa, NULL);
		RSA_meth_set_finish(secureobj_rsa, NULL);
		RSA_meth_set_sign(secureobj_rsa, NULL);
		RSA_meth_set_verify(secureobj_rsa, NULL);
		RSA_meth_set_keygen(secureobj_rsa, RSA_meth_get_keygen(rsa_meth));
	} else {
		print_error("ENGINE_set_RSA failed\n");
		goto end;
	}
#endif

	if (!ENGINE_set_id(engine, engine_id) ||
		!ENGINE_set_name(engine, engine_name)) {
		print_error("ENGINE_set_id or ENGINE_set_name or ENGINE_set_init_function failed\n");
		goto end;
	}

	if (!ENGINE_set_default_RSA(engine)) {
		print_error("ENGINE_set_default_RSA failed\n");
		goto end;
	}

	ret = 1;
end:
	return ret;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
