/*
  * SPDX-License-Identifier:     BSD-3-Clause
  * @copyright 2017 NXP
  * 
  * 
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <securekey_api.h>
#include "rsa_data.h"

#define MAX_RSA_ATTRIBUTES	13
#define MAX_FIND_OBJ_SIZE	50

static void populate_attrs(SK_ATTRIBUTE *attrs)
{
	attrs[0].type = SK_ATTR_OBJECT_TYPE;
	attrs[0].value = &obj;
	attrs[0].valueLen = sizeof(obj);
	attrs[1].type = SK_ATTR_OBJECT_INDEX;
	attrs[1].value = &obj_id;
	attrs[1].valueLen = sizeof(obj_id);
	attrs[2].type = SK_ATTR_KEY_TYPE;
	attrs[2].value = &key;
	attrs[2].valueLen = sizeof(key);
	attrs[3].type = SK_ATTR_OBJECT_LABEL;
	attrs[3].value = label;
	attrs[3].valueLen = sizeof(label);
	attrs[4].type = SK_ATTR_MODULUS_BITS;
	attrs[4].value = &key_len;
	attrs[4].valueLen = sizeof(key_len);
	attrs[5].type = SK_ATTR_MODULUS;
	attrs[5].value = (void *)rsa_modulus;
	attrs[5].valueLen = sizeof(rsa_modulus);
	attrs[6].type = SK_ATTR_PUBLIC_EXPONENT;
	attrs[6].value = (void *)rsa_pub_exp;
	attrs[6].valueLen = sizeof(rsa_pub_exp);
	attrs[7].type = SK_ATTR_PRIVATE_EXPONENT;
	attrs[7].value = (void *)rsa_priv_exp;
	attrs[7].valueLen = sizeof(rsa_priv_exp);
	attrs[8].type = SK_ATTR_PRIME_1;
	attrs[8].value = (void *)rsa_prime1;
	attrs[8].valueLen = sizeof(rsa_prime1);
	attrs[9].type = SK_ATTR_PRIME_2;
	attrs[9].value = (void *)rsa_prime2;
	attrs[9].valueLen = sizeof(rsa_prime2);
	attrs[10].type = SK_ATTR_EXPONENT_1;
	attrs[10].value = (void *)rsa_exp1;
	attrs[10].valueLen = sizeof(rsa_exp1);
	attrs[11].type = SK_ATTR_EXPONENT_2;
	attrs[11].value = (void *)rsa_exp2;
	attrs[11].valueLen = sizeof(rsa_exp2);
	attrs[12].type = SK_ATTR_COEFFICIENT;
	attrs[12].value = (void *)rsa_coeff;
	attrs[12].valueLen = sizeof(rsa_coeff);
}

static SK_OBJECT_HANDLE do_CreateObject(void)
{
	int ret;
	SK_ATTRIBUTE *attrs;
	SK_OBJECT_HANDLE hObject;

	attrs = (SK_ATTRIBUTE *)malloc(sizeof(SK_ATTRIBUTE) * MAX_RSA_ATTRIBUTES);
	if (attrs == NULL) {
		printf("malloc failed\n");
		return SKR_ERR_OBJECT_HANDLE_INVALID;
	}

	populate_attrs(attrs);

	ret = SK_CreateObject(attrs, MAX_RSA_ATTRIBUTES, &hObject);
	if (ret != SKR_OK)
		printf("SK_CreateObject failed wit err code = 0x%x\n", ret);
	else
		printf("SK_CreateObject successful handle = 0x%x\n", hObject);

	free(attrs);
	return hObject;
}

static SK_OBJECT_HANDLE do_GenerateKeyPair(void)
{
	int ret;
	SK_ATTRIBUTE attrs[4];
	SK_OBJECT_HANDLE hObject;
	SK_MECHANISM_INFO mechanismType = {0};

	mechanismType.mechanism = SKM_RSA_PKCS_KEY_PAIR_GEN;

	attrs[0].type = SK_ATTR_OBJECT_INDEX;
	attrs[0].value = &obj_id;
	attrs[0].valueLen = sizeof(obj_id);
	attrs[1].type = SK_ATTR_OBJECT_LABEL;
	attrs[1].value = label;
	attrs[1].valueLen = sizeof(label);
	attrs[2].type = SK_ATTR_MODULUS_BITS;
	attrs[2].value = &key_len;
	attrs[2].valueLen = sizeof(key_len);
	attrs[3].type = SK_ATTR_PUBLIC_EXPONENT;
	attrs[3].value = (void *)rsa_pub_exp;
	attrs[3].valueLen = sizeof(rsa_pub_exp);

	ret = SK_GenerateKeyPair(&mechanismType, attrs, 4, &hObject);
	if (ret != SKR_OK)
		printf("SK_GenerateKeyPair failed wit err code = 0x%x\n", ret);
	else
		printf("SK_GenerateKeyPair successful handle = 0x%x\n", hObject);

	return hObject;
}

static void do_EraseObject(SK_OBJECT_HANDLE hObject)
{
	int ret, i = 0;

	ret = SK_EraseObject(hObject);

	if (ret != SKR_OK)
		printf("SK_EraseObject failed with code = 0x%x\n", ret);
	else
		printf("SK_EraseObject successful\n");
}
static void do_EnumerateObject(void)
{
	int ret, i = 0;
	SK_ATTRIBUTE attrs[2];
	SK_OBJECT_HANDLE hObject[MAX_FIND_OBJ_SIZE];
	uint32_t objCount;

	/* Getting only RSA Keypair objects */
	printf("Getting only RSA Keypair objects\n");
	SK_OBJECT_TYPE key = SK_KEY_PAIR;
	attrs[0].type = SK_ATTR_OBJECT_TYPE;
	attrs[0].value = &key;
	attrs[0].valueLen = sizeof(SK_OBJECT_TYPE);

	SK_KEY_TYPE key_type = SKK_RSA;
	attrs[1].type = SK_ATTR_KEY_TYPE;
	attrs[1].value = &key_type;
	attrs[1].valueLen = sizeof(SK_KEY_TYPE);

	ret = SK_EnumerateObjects(NULL, 0, hObject, MAX_FIND_OBJ_SIZE,
		&objCount);
	if (ret != SKR_OK)
		printf("SK_EnumerateObjects failed with code = 0x%x\n", ret);
	else {
		printf("SK_EnumerateObjects successful\n");
		for (i = 0; i < objCount; i++)
			printf("hObject[%d] = 0x%x\n", i, hObject[i]);
	}
}

static void do_GetObjectAttributes(SK_OBJECT_HANDLE hObject)
{
	int ret, i = 0, n = 0;
	SK_ATTRIBUTE attrs[2];
	uint32_t attrCount = 2;
	SK_OBJECT_TYPE obj_type;
	SK_KEY_TYPE key_type;

	/* Getting only RSA Keypair objects */
	memset(attrs, 0, sizeof(SK_ATTRIBUTE) * 2);

	attrs[0].type = SK_ATTR_OBJECT_LABEL;
	attrs[1].type = SK_ATTR_OBJECT_INDEX;

	ret = SK_GetObjectAttribute(hObject, attrs, attrCount);
	if (ret != SKR_OK)
		printf("SK_GetObjectAttribute failed with code = 0x%x\n", ret);
	else {
		printf("SK_GetObjectAttribute successful\n");
		printf("attrCount = %d\n", attrCount);
		for (n = 0; n < attrCount; n++) {
			printf("Attr[%d].type: 0x%x\n", n, attrs[n].type);
			printf("Attr[%d].valueLen: 0x%x\n", n, attrs[n].valueLen);
#if 0
			printf("Attr[%d].value: 0x", n);
			for (i = 0; i < attrs[n].valueLen; i++)
				printf("%x", *(((uint8_t *)attrs[n].value) + i));
			printf("\n");
#endif
		}
	}
}

static void do_Sign(SK_OBJECT_HANDLE hObject, int mech)
{
	int ret, n = 0;
	SK_MECHANISM_INFO mechanismType = {0};
	uint8_t *signature = NULL;
	uint16_t signatureLen = 0, data_len = 0;
	const uint8_t *data = NULL;

	if (mech == 0) {
		mechanismType.mechanism = SKM_RSASSA_PKCS1_V1_5_SHA1;
		data = rsa_digest_sha1;
		data_len = 160;
	} else if (mech == 1) {
		mechanismType.mechanism = SKM_RSASSA_PKCS1_V1_5_SHA256;
		data = rsa_digest_sha256;
		data_len = 256;
	} else if (mech == 2) {
		mechanismType.mechanism = SKM_RSASSA_PKCS1_V1_5_SHA384;
		data = rsa_digest_sha384;
		data_len = 384;
	} else {
		mechanismType.mechanism = SKM_RSASSA_PKCS1_V1_5_SHA512;
		data = rsa_digest_sha512;
		data_len = 512;
	}

	ret = SK_Sign(&mechanismType, hObject, data,
		      data_len, signature, &signatureLen);
	if (ret != SKR_OK)
		printf("SK_Sign1 failed with code = 0x%x\n", ret);

	/* Convert signature length into bytes */
	signatureLen = signatureLen/8;

	signature = (uint8_t *)malloc(signatureLen);
	printf("Signature len = %d\n", signatureLen);

	ret = SK_Sign(&mechanismType, hObject, rsa_digest_sha256,
		      sizeof(rsa_digest_sha256), signature, &signatureLen);
	if (ret != SKR_OK)
		printf("SK_Sign2 failed with code = 0x%x\n", ret);

	printf("SK_Sign successful\n");
	printf("Signature:\n 0x");
	for (n = 0; n < signatureLen; n++)
		printf("%x", *(signature + n));
	printf("\n");

	free(signature);
}

static void do_Decrypt(SK_OBJECT_HANDLE hObject)
{
	int ret, n = 0;
	SK_MECHANISM_INFO mechanismType = {0};
	uint8_t *decData = NULL;
	uint16_t decDataLen = 0;

	mechanismType.mechanism = SKM_RSA_PKCS_NOPAD;

	ret = SK_Decrypt(&mechanismType, hObject, rsa_data,
			 sizeof(rsa_data), decData, &decDataLen);
	if (ret != SKR_OK)
		printf("SK_Decrypt1 failed with code = 0x%x\n", ret);

	/* Convert signature length into bytes */
	decDataLen = decDataLen/8;

	decData = (uint8_t *)malloc(decDataLen);

	ret = SK_Decrypt(&mechanismType, hObject, rsa_data,
			 sizeof(rsa_data), decData, &decDataLen);
	if (ret != SKR_OK)
		printf("SK_Decrypt2 failed with code = 0x%x\n", ret);

	printf("SK_Decrypt successful\n");
	printf("Decrypted Data:\n 0x");
	for (n = 0; n < decDataLen; n++)
		printf("%x", *(decData + n));
	printf("\n");

	free(decData);
}

static void do_Digest(void)
{
	int ret, n = 0;
	SK_MECHANISM_INFO mechanismType = {0};
	char message[] = "Hello PKCS api";
	uint8_t *digest = NULL;
	uint16_t digestLen = 0;

	mechanismType.mechanism = SKM_SHA256;

	ret = SK_Digest(&mechanismType, message, sizeof(message),
			digest, &digestLen);
	if (ret != SKR_OK)
		printf("SK_Digest1 failed with code = 0x%x\n", ret);

	digest = (uint8_t *)malloc(digestLen);

	ret = SK_Digest(&mechanismType, message, sizeof(message),
			digest, &digestLen);
	if (ret != SKR_OK)
		printf("SK_Digest2 failed with code = 0x%x\n", ret);

	printf("SK_Digest successful\n");
	printf("Digest:\n 0x");
	for (n = 0; n < digestLen; n++)
		printf("%x", *(digest + n));
	printf("\n");

	free(digest);
}

int main(int argc, char *argv[])
{
	//do_Sign(atoi(argv[1]), atoi(argv[2]));

	SK_OBJECT_HANDLE obj1, obj2;

	obj1 = do_CreateObject();
	obj2 = do_GenerateKeyPair();

	//do_EnumerateObject();
	//do_Digest();

	/* Operations with imported object */
	do_GetObjectAttributes(obj2);
	do_GetObjectAttributes(obj1);
	do_Sign(obj1, 1);
	do_Decrypt(obj1);

	/* Operations with generated object */
	
	do_Sign(obj2, 1);
	do_Decrypt(obj2);

	do_EraseObject(obj1);
	do_EraseObject(obj2);

	return 0;
}
