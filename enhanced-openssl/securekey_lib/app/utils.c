/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <securekey_api.h>
#include <openssl/pem.h>
#include <unistd.h>
#include "utils.h"



void printKey(uint8_t *key, uint32_t keyLen)
{
	int i = 0;

	for (i = 0; i < keyLen; i++)
		printf("%02x", key[i]);
	printf("\n");
}

void printRSA_key(rsa_3form_key_t *rsa_3form_key, uint32_t key_len)
{
	printf("rsa_modulus\n");
	printKey(rsa_3form_key->rsa_modulus, ((key_len + 7) >> 3));

	printf("rsa_pub_exp\n");
	printKey(rsa_3form_key->rsa_pub_exp, 3);

	printf("rsa_priv_exp\n");
	printKey(rsa_3form_key->rsa_priv_exp, ((key_len + 7) >> 3));

	printf("rsa_prime1\n");
	printKey(rsa_3form_key->rsa_prime1, ((key_len + 7) >> 3)/2);

	printf("rsa_prime2\n");
	printKey(rsa_3form_key->rsa_prime2, ((key_len + 7) >> 3)/2);

	printf("rsa_exp1\n");
	printKey(rsa_3form_key->rsa_exp1, ((key_len + 7) >> 3)/2);

	printf("rsa_exp2\n");
	printKey(rsa_3form_key->rsa_exp2, ((key_len + 7) >> 3)/2);
}

char *getObjTypeStr(SK_OBJECT_TYPE obj_type)
{
	switch (obj_type) {
	case SK_KEY_PAIR:
		return "KEY_PAIR";
	case SK_PUBLIC_KEY:
		return "PUBLIC KEY";
	default:
		return "Not Supported";
	}
}

SK_OBJECT_TYPE getObjectType(char *objTypeStr)
{
	if (objTypeStr == NULL)
		return U32_INVALID;
	else if (strcmp(objTypeStr, "pair") == 0)
		return SK_KEY_PAIR;

	printf("Unsupported Object Type: %s\n", objTypeStr);
	return U32_INVALID;
}

char *getKeyTypeStr(SK_KEY_TYPE key_type)
{
	switch (key_type) {
	case SKK_RSA:
		return "RSA";
	case SKK_EC:
		return "EC";
	default:
		return "TBD";
	}
}

SK_KEY_TYPE getKeyType(char *keyTypeStr)
{
	if (keyTypeStr == NULL)
		return U32_INVALID;
	else if (strcmp(keyTypeStr, "rsa") == 0)
		return SKK_RSA;
	else if (strcmp(keyTypeStr, "ec") == 0)
		return SKK_EC;

	printf("Unsupported Key Type: %s\n", keyTypeStr);
	return U32_INVALID;
}

SK_OBJECT_TYPE getMechType(char *mechTypeStr)
{
	if (mechTypeStr == NULL)
		return U32_INVALID;
	else if (strcmp(mechTypeStr, "rsa-pair") == 0)
		return SKM_RSA_PKCS_KEY_PAIR_GEN;
	else if (strcmp(mechTypeStr, "ec-pair") == 0)
		return SKM_EC_PKCS_KEY_PAIR_GEN;

	printf("Unsupported Mechanism Type: %s\n", mechTypeStr);
	return U32_INVALID;
}

#if 0
SK_OBJECT_TYPE getMechTypeFrmObjKeyT(SK_OBJECT_TYPE obj_type,
		SK_KEY_TYPE key_type)
{
	if ((obj_type == SK_KEY_PAIR) && (key_type == SKK_RSA))
		return SKM_RSA_PKCS_KEY_PAIR_GEN;

	printf("Unsupported Mechanism Type: %s-%s\n",
			getKeyTypeStr(key_type),
			getObjTypeStr(obj_type));
	return U32_INVALID;
}
#endif

int validate_key_len(uint32_t key_len)
{
	switch (key_len) {
	/* For RSA Keys */
	case 1024:
	case 2048:
		return key_len;
	default:
		printf("Unsupported Key Length = %d\n", key_len);
		return U32_INVALID;
	}
}

int validate_ec_key_len(uint32_t key_len)
{
	int key_in_bits = key_len * 8;
	switch (key_in_bits) {
	case 256:
	case 384:
		return key_len;
	default:
		printf("Unsupported Key Length = %d\n", key_in_bits);
		return U32_INVALID;
	}
}
