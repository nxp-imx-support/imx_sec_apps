/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <tee_client_api.h>
#include <tee_api_types.h>
#include <ta_secure_storage.h>
#include <securekey_api_types.h>
#include <rsa_data.h>

#define MAX_RSA_ATTRIBUTES	13
#define MAX_FIND_OBJ_SIZE	50

#define CREATE_OBJ
#define FIND_OBJ
//#define ERASE_OBJ
#define ATTRIBUTE_OBJ

/* Round up the even multiple of size, size has to be a multiple of 2 */
#define ROUNDUP(v, size) (((v) + (size - 1)) & ~(size - 1))

size_t get_attr_size(SK_ATTRIBUTE *attrs, uint32_t attr_cnt);

struct tee_attr_packed {
	uint32_t attr_id;
	uint32_t a;
	uint32_t b;
};

void populate_attrs(SK_ATTRIBUTE *attrs)
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

size_t get_attr_size(SK_ATTRIBUTE *attrs, uint32_t attr_cnt)
{
	size_t size = sizeof(uint32_t);
	uint32_t i;

	if (attr_cnt == 0 || attrs == NULL)
		return size;

	size += sizeof(struct tee_attr_packed) * attr_cnt;
	for (i = 0; i < attr_cnt; i++) {
		if (attrs[i].valueLen == 0)
			continue;

		/* Make room for padding */
		size += ROUNDUP(attrs[i].valueLen, 4);
	}

	return size;
}

uint32_t pack_attrs(uint8_t *buffer, size_t size,
		    SK_ATTRIBUTE *attrs, uint32_t attr_cnt)
{
	uint8_t *b = buffer;
	struct tee_attr_packed *a;
	uint32_t i;

	if (b == NULL || size == 0)
		return TEEC_ERROR_GENERIC;

	*(uint32_t *)(void *)b = attr_cnt;
	b += sizeof(uint32_t);
	a = (struct tee_attr_packed *)(void *)b;
	b += sizeof(struct tee_attr_packed) * attr_cnt;

	for (i = 0; i < attr_cnt; i++) {
		a[i].attr_id = attrs[i].type;

		a[i].b = attrs[i].valueLen;

		if (attrs[i].valueLen == 0) {
			a[i].a = 0;
			continue;
		}

		memcpy(b, attrs[i].value, attrs[i].valueLen);

		/* Make buffer pointer relative to *buf */
		a[i].a = (uint32_t)(uintptr_t)(b - buffer);

		/* Round up to good alignment */
		b += ROUNDUP(attrs[i].valueLen, 4);
	}

	return TEEC_SUCCESS;
}

uint32_t unpack_sk_attrs(const uint8_t *buf, size_t blen,
			 SK_ATTRIBUTE *attrs, uint32_t *attr_count)
{
	uint32_t res = TEEC_SUCCESS;
	SK_ATTRIBUTE *a = NULL;
	const struct tee_attr_packed *ap;
	size_t num_attrs = 0;
	const size_t num_attrs_size = sizeof(uint32_t);

	if (blen == 0)
		goto out;

	if (((uintptr_t)buf & 0x3) != 0 || blen < num_attrs_size)
		return TEEC_ERROR_GENERIC;
	num_attrs = *(uint32_t *) (void *)buf;

	if ((blen - num_attrs_size) < (num_attrs * sizeof(*ap)))
		return TEEC_ERROR_GENERIC;

	ap = (const struct tee_attr_packed *)(buf + num_attrs_size);

	if (num_attrs > 0) {
		size_t n;

		a = attrs;

		for (n = 0; n < num_attrs; n++) {
			uintptr_t p;

			a[n].type = ap[n].attr_id;
			a[n].valueLen = ap[n].b;
			p = (uintptr_t)ap[n].a;
			if (p) {
				if ((p + a[n].valueLen) > blen) {
					res = TEEC_ERROR_GENERIC;
					goto out;
				}
				p += (uintptr_t)buf;
			}
			a[n].value = (void *)p;
		}
	}

	res = TEEC_SUCCESS;
out:
	if (res == TEEC_SUCCESS)
		*attr_count = num_attrs;

	return res;
}

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SECURE_STORAGE_UUID;
	TEEC_SharedMemory shm_in;
	SK_ATTRIBUTE attrs[MAX_RSA_ATTRIBUTES] = {0};
	uint32_t err_origin;
#ifdef FIND_OBJ
	TEEC_SharedMemory shm_out;
	uint32_t no_of_objects = 0;
#endif

#if defined(CREATE_OBJ) || defined(ERASE_OBJ)
	uint32_t obj_idx = 0;
#endif
#ifdef ATTRIBUTE_OBJ
	uint32_t attr_count = 0, n, i;
#endif

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed with code 0x%x", res);
		exit(0);
	}

	/*
	 * Open a session to the "Secure Storage" TA, the TA will print "hello!"
	 * in the log when the session is created.
	 */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_Opensession failed with code 0x%x", res);
		goto fail1;
	}

#ifdef CREATE_OBJ
	/*
	 * Execute a function in the TA by invoking it, in this case
	 * we're creating a SK key pair object.
	 *
	 * The value of command ID part and how the parameters are
	 * interpreted is part of the interface provided by the TA.
	 */

	populate_attrs(attrs);

	shm_in.size = get_attr_size(attrs, MAX_RSA_ATTRIBUTES);
	shm_in.flags = TEEC_MEM_INPUT;

	res = TEEC_AllocateSharedMemory(&ctx, &shm_in);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_AllocateSharedMemory failed with code 0x%x", res);
		goto fail2;
	}

	res = pack_attrs(shm_in.buffer, shm_in.size, attrs, MAX_RSA_ATTRIBUTES);
	if (res != TEEC_SUCCESS) {
		printf("pack_attrs failed with code 0x%x", res);
		goto fail3;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_VALUE_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].memref.parent = &shm_in;
	op.params[0].memref.offset = 0;
	op.params[0].memref.size = shm_in.size;

	printf("Invoking TEE_CREATE_OBJECT\n");
	res = TEEC_InvokeCommand(&sess, TEE_CREATE_OBJECT, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed with code 0x%x", res);
		goto fail3;
	}

	obj_idx = op.params[1].value.a;

	printf("TEE_CREATE_OBJECT successful\n");
#endif

#ifdef ERASE_OBJ
	/*
	 * Execute a function in the TA by invoking it, in this case
	 * we're erasing a SK key pair object.
	 *
	 * The value of command ID part and how the parameters are
	 * interpreted is part of the interface provided by the TA.
	 */

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = obj_idx;

	printf("Invoking TEE_ERASE_OBJECT\n");
	res = TEEC_InvokeCommand(&sess, TEE_ERASE_OBJECT, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed with code 0x%x", res);
		goto fail2;
	}
	printf("TEE_ERASE_OBJECT successful\n");
#endif

#ifdef FIND_OBJ
	/*
	 * Execute a function in the TA by invoking it, in this case
	 * we're creating a SK key pair object.
	 *
	 * The value of command ID part and how the parameters are
	 * interpreted is part of the interface provided by the TA.
	 */

	populate_attrs(attrs);

	shm_in.size = get_attr_size(attrs, 5);
	shm_in.flags = TEEC_MEM_INPUT;

	res = TEEC_AllocateSharedMemory(&ctx, &shm_in);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_AllocateSharedMemory failed with code 0x%x", res);
		goto fail2;
	}

	res = pack_attrs(shm_in.buffer, shm_in.size, attrs, 5);
	if (res != TEEC_SUCCESS) {
		printf("pack_attrs failed with code 0x%x", res);
		goto fail3;
	}

	shm_out.size = sizeof(SK_OBJECT_HANDLE) * MAX_FIND_OBJ_SIZE;
	shm_out.flags = TEEC_MEM_OUTPUT;

	res = TEEC_AllocateSharedMemory(&ctx, &shm_out);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_AllocateSharedMemory failed with code 0x%x", res);
		goto fail3;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE,
					 TEEC_VALUE_OUTPUT, TEEC_NONE);
	op.params[0].memref.parent = &shm_in;
	op.params[0].memref.offset = 0;
	op.params[0].memref.size = shm_in.size;
	op.params[1].memref.parent = &shm_out;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = shm_out.size;

	printf("Invoking TEE_FIND_OBJECTS\n");
	res = TEEC_InvokeCommand(&sess, TEE_FIND_OBJECTS, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed with code 0x%x", res);
		goto fail3;
	}

	no_of_objects = op.params[2].value.a;

	printf("No of objects returned: %d\n", no_of_objects);

	printf("TEE_FIND_OBJECTS successful\n");
#endif

#ifdef ATTRIBUTE_OBJ
	/*
	 * Execute a function in the TA by invoking it, in this case
	 * to get SK key pair object attributes.
	 *
	 * The value of command ID part and how the parameters are
	 * interpreted is part of the interface provided by the TA.
	 */

	memset(attrs, 0, sizeof(attrs));

	attrs[0].type = SK_ATTR_OBJECT_TYPE;
	attrs[1].type = SK_ATTR_OBJECT_LABEL;
	attrs[2].type = SK_ATTR_MODULUS;

	shm_in.size = get_attr_size(attrs, 3);
	shm_in.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

	res = TEEC_AllocateSharedMemory(&ctx, &shm_in);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_AllocateSharedMemory failed with code 0x%x", res);
		goto fail2;
	}

	res = pack_attrs(shm_in.buffer, shm_in.size, attrs, 3);
	if (res != TEEC_SUCCESS) {
		printf("pack_attrs failed with code 0x%x", res);
		goto fail3;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_WHOLE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = obj_idx;
	op.params[1].memref.parent = &shm_in;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = shm_in.size;

	printf("Invoking TEE_GET_OBJ_ATTRIBUTES\n");
	res = TEEC_InvokeCommand(&sess, TEE_GET_OBJ_ATTRIBUTES, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed with code 0x%x", res);
		goto fail3;
	}

	unpack_sk_attrs((void *)shm_in.buffer, shm_in.size, attrs,
			&attr_count);

	printf("No of attributes returned: %d\n", attr_count);
	for (n = 0; n < attr_count; n++) {
		printf("Attr[%d].type: 0x%x\n", n, attrs[n].type);
		printf("Attr[%d].valueLen: 0x%x\n", n, attrs[n].valueLen);
		attrs[n].value = malloc(attrs[n].valueLen);
	}

	TEEC_ReleaseSharedMemory(&shm_in);
	shm_in.size = get_attr_size(attrs, 3);

	res = TEEC_AllocateSharedMemory(&ctx, &shm_in);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_AllocateSharedMemory failed with code 0x%x", res);
		goto fail2;
	}

	res = pack_attrs(shm_in.buffer, shm_in.size, attrs, 3);
	if (res != TEEC_SUCCESS) {
		printf("pack_attrs failed with code 0x%x", res);
		goto fail3;
	}

	res = TEEC_InvokeCommand(&sess, TEE_GET_OBJ_ATTRIBUTES, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed with code 0x%x", res);
		goto fail3;
	}

	unpack_sk_attrs((void *)shm_in.buffer, shm_in.size, attrs,
			&attr_count);

	for (n = 0; n < attr_count; n++) {
		printf("Attr[%d].type: 0x%x\n", n, attrs[n].type);
		printf("Attr[%d].valueLen: 0x%x\n", n, attrs[n].valueLen);
		printf("Attr[%d].value: 0x", n);
		for (i = 0; i < attrs[n].valueLen; i++)
			printf("%x", *((uint8_t *)attrs[n].value + i));
		printf("\n");
	}

	printf("TEE_GET_OBJ_ATTRIBUTES successful\n");
#endif

	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */
fail3:
	TEEC_ReleaseSharedMemory(&shm_in);
#ifdef FIND_OBJ
	TEEC_ReleaseSharedMemory(&shm_out);
#endif

fail2:
	TEEC_CloseSession(&sess);

fail1:
	TEEC_FinalizeContext(&ctx);

	return 0;
}
