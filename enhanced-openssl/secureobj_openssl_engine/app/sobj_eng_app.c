/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

int padding = RSA_PKCS1_PADDING;

int public_encrypt(unsigned char * data, int data_len, RSA * rsa, unsigned char *encrypted)
{
	int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
	return result;
}

int private_decrypt(unsigned char * enc_data, int enc_data_len, RSA *rsa, unsigned char *decrypted)
{
	int  result = RSA_private_decrypt(enc_data_len, enc_data, decrypted, rsa, padding);
	return result;
}

int private_encrypt(unsigned char * data,int data_len, RSA *rsa, unsigned char *encrypted)
{
	int result = RSA_private_encrypt(data_len, data, encrypted, rsa, padding);
	return result;
}

int public_decrypt(unsigned char * enc_data,int enc_data_len, RSA *rsa, unsigned char *decrypted)
{
	int  result = RSA_public_decrypt(enc_data_len, enc_data, decrypted, rsa, padding);
	return result;
}

#define	MAX_ERR_STR_LEN	130

void printLastError(char *msg)
{
	char * err = malloc(MAX_ERR_STR_LEN);
	if (err != NULL) {
		ERR_error_string(ERR_get_error(), err);
		printf("%s ERROR: %s\n",msg, err);
		free(err);
	}
}

int main(int argc, char *argv[])
{
	char plainText[] = "This is test data to be tested"; //key length : 2048
	const char *engine_id = "dynamic";
	int byte_key_size = 0, plain_text_len = 0;
	int decrypted_length = 0, encrypted_length = 0;
	uint8_t *encrypted = NULL, *decrypted = NULL, ret = 0;
	EVP_PKEY *priv_key = NULL;
	ENGINE *eng = NULL;
	FILE *fptr = NULL;
	RSA *rsa = NULL;

	if (argc <= 1) {
		printf("Please give the label of Private Key to be used\n");
		exit(0);
	}

	printf("Device Key Label = %s\n", argv[1]);

	ENGINE_load_builtin_engines();

	eng = ENGINE_by_id(engine_id);
	if (!eng) {
		printf("ENGINE_by_id failed\n");
		ret = 1;
		goto failure;
	}

	ENGINE_ctrl_cmd_string(eng, "SO_PATH",
		"/usr/lib/aarch64-linux-gnu/openssl-1.0.0/engines/libeng_secure_obj.so", 0);
	ENGINE_ctrl_cmd_string(eng, "ID", "eng_secure_obj", 0);
	ENGINE_ctrl_cmd_string(eng, "LOAD", NULL, 0);

	fptr = fopen(argv[1], "rb");
	if (!fptr) {
		printf("fopen failed.\n");
		ret = 1;
		goto failure;
	}

	priv_key = PEM_read_PrivateKey(fptr, &priv_key, NULL, NULL);
	if (priv_key == NULL) {
		printf("Key with Label %s not found.\n", argv[1]);
		ret = 1;
		goto failure;
	}

#if 0
	/* RSA Key object with label "dev_key" is being genreated by sobj_app */
	priv_key = ENGINE_load_private_key(eng, argv[1], NULL, NULL);
	if (priv_key == NULL) {
		printf("Key with Label %s not found.\n", argv[1]);
		ret = 1;
		goto failure;
	}
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	rsa = priv_key->pkey.rsa;
#else
	rsa = EVP_PKEY_get0_RSA(priv_key);
#endif

	byte_key_size = RSA_size(rsa);

	encrypted = malloc(byte_key_size);
	if (!encrypted) {
		printf("encrypted malloc failed\n");
		ret = 1;
		goto failure;
	}

	plain_text_len = strlen(plainText);
	decrypted = malloc(plain_text_len);
	if (!decrypted) {
		printf("decrypted malloc failed\n");
		ret = 1;
		goto failure;
	}

	memset(encrypted, 0, byte_key_size);
	memset(decrypted, 0, plain_text_len);

	printf("Plain Text = %s\n", plainText);
	printf("Starting RSA Public Encrypt....\n");
	encrypted_length = public_encrypt(plainText, plain_text_len, rsa, encrypted);
	if(encrypted_length == -1) {
		printLastError("Public Encrypt failed ");
		ret = 1;
		goto failure;
	}
	printf("Encryption Complete: Length of Encrypted Data = %d\n\n", encrypted_length);

	printf("Starting RSA Private Decryption....\n");
	decrypted_length = private_decrypt(encrypted, encrypted_length, rsa, decrypted);
	if(decrypted_length == -1) {
		printLastError("Private Decrypt failed ");
		ret = 1;
		goto failure;
	}
	printf("Decryption Complete: Decrypted Text = %s\n\n", decrypted);

	printf("Starting RSA Private Encryption....\n");
	printf("Plain Text = %s\n", plainText);
	encrypted_length = private_encrypt(plainText, plain_text_len, rsa, encrypted);
	if(encrypted_length == -1) {
		printLastError("Private Encrypt failed");
		ret = 1;
		goto failure;
	}
	printf("Encryption Complete: Length of Encrypted Data = %d\n\n", encrypted_length);

	printf("Starting RSA Public Decryption....\n");
	decrypted_length = public_decrypt(encrypted, encrypted_length, rsa, decrypted);
	if(decrypted_length == -1) {
		printLastError("Public Decrypt failed");
		ret = 1;
		goto failure;
	}
	printf("Decryption Complete: Decrypted Text = %s\n\n", decrypted);

	ret = 0;
failure:
	if (encrypted)
		free(encrypted);

	if (decrypted)
		free(decrypted);

	exit(ret);
}
