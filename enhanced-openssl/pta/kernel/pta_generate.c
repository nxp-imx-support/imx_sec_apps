// SPDX-License-Identifier: BSD-2-Clause
/**
* @copyright 2019 NXP
*
* @file    pta_generate_mx.c
*
* @brief   Pseudo Trusted Application.
*			RSA/ECC Key generation functionality
*/

#include <kernel/pseudo_ta.h>

/* Standard includes */
#include <stdlib.h>
#include <string.h>
#include <trace.h>

/* Library kernel includes */
#include <kernel/pseudo_ta.h>

/* Library libutee includes */
#include <pta_sign.h>
#include <pta_generate.h>

/* Library tee includes */
#include <tee_api_types.h>

/* Library crypto includes */
#include <crypto_extension.h>
#include <libimxcrypt_acipher.h>

/* Library crypto includes */
#include <crypto/crypto.h>

/* Global includes */
#include <tee_api_defines.h>

/* PTA Name */
#define GENERATE_PTA_NAME "generate.pta"


/**
 * @brief  Generates an EC key using libimxcrypt
 *          
 *
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 * In/Out params:
 * param#0 : value a : size of the key in bits
 * param#0 : value b : size of the priv value Y in bytes
 * param#1 : memref to ecc pub point
 * param#2 : memref to ecc private value
 * 
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_ACCESS_DENIED     PTA access is denied
 */
static TEE_Result generate_ec_key(uint32_t param_types,
	TEE_Param params[TEE_NUM_PARAMS]) {
	TEE_Result res = TEE_SUCCESS;
	struct ecc_keypair key;
	struct ecc_public_key ecc_pub_key;
	uint32_t exp_param_types;
	size_t key_size, pub_valx_size;
	uint8_t *ec_pub_point;
	DMSG("PTA Generate EC function %x", res);

	exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_VALUE_INOUT,
		TEE_PARAM_TYPE_MEMREF_INOUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE);
	
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	key_size = params[0].value.a;
	ec_pub_point = params[1].memref.buffer;

	res = crypto_acipher_alloc_ecc_public_key(&ecc_pub_key, key_size);
	if (res != TEE_SUCCESS)
		return res;

	if (key_size == 256) {
		ecc_pub_key.curve = TEE_ECC_CURVE_NIST_P256;
	} else if (key_size == 384) {
		ecc_pub_key.curve = TEE_ECC_CURVE_NIST_P384;
	}

	DMSG("Alloc EC %x with size %x", res, key_size);
	res = crypto_acipher_alloc_ecc_keypair(&key, key_size);
	if (res != TEE_SUCCESS)
		return res;

	key.curve = ecc_pub_key.curve;
	key.x = ecc_pub_key.x;
	key.y = ecc_pub_key.y;
	DMSG("Generate EC %d with size %x", ecc_pub_key.curve, key_size);

	res = crypto_acipher_gen_ecc_key(&key);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_ACCESS_CONFLICT;

	DMSG("Generated EC %x with size %x", res, key_size);
	// copy ec pub point from key to TA buffer

	pub_valx_size = crypto_bignum_num_bytes(key.x);
	crypto_bignum_bn2bin(key.x, ec_pub_point + 1);
	crypto_bignum_bn2bin(key.y, ec_pub_point + pub_valx_size + 1);
	crypto_bignum_bn2bin(key.d, params[2].memref.buffer);

	params[1].memref.size = pub_valx_size;
	params[0].value.b = crypto_bignum_num_bytes(key.y);
	params[2].memref.size = crypto_bignum_num_bytes(key.d);

	
	crypto_acipher_free_ecc_public_key(&ecc_pub_key);
	crypto_bignum_free(key.d);

	return res;
}

/**
 * @brief  Generates a RSA key pair using libimxcrypt
 *          
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 * Input params:
 * param#0 : value a : size of the key in bits
 * In/Out params:
 * param#1 : memref to modulus
 * param#2 : memref to public exponent
 * param#3: memref to RSA private exponent
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_ACCESS_DENIED     PTA access is denied
 */

static TEE_Result generate_rsa_key(uint32_t param_types,
	TEE_Param params[TEE_NUM_PARAMS]) {
	TEE_Result res = TEE_SUCCESS;
	struct rsa_keypair key;
	struct rsa_public_key rsa_key_pub;
	uint32_t key_size, pub_key_size;
	uint32_t exp_param_types;
	uint8_t *pub_key;

	exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_VALUE_INPUT,
		TEE_PARAM_TYPE_MEMREF_INOUT,
		TEE_PARAM_TYPE_MEMREF_INOUT,
		TEE_PARAM_TYPE_MEMREF_INOUT);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	key_size = params[0].value.a;
	pub_key_size = params[2].memref.size * 8;
	pub_key = params[2].memref.buffer;
	/* CRYPTO API */
	res = crypto_acipher_alloc_rsa_keypair(&key, key_size);
	if (res != TEE_SUCCESS)
		return res;

	res = crypto_acipher_alloc_rsa_public_key(&rsa_key_pub, pub_key_size);
	DMSG("RES: %x", res);
	if (res != TEE_SUCCESS)
		return res;
	
	res = crypto_bignum_bin2bn(pub_key, pub_key_size / 8, rsa_key_pub.e);
	DMSG("RES: %x", res);
	if (res != TEE_SUCCESS)
		return res;

	key.e = rsa_key_pub.e;
	res = crypto_acipher_gen_rsa_key(&key, key_size);
	DMSG("RES: %x", res);
	if (res != TEE_SUCCESS)
		return res;

	/*modulus */
	crypto_bignum_bn2bin(key.n, params[1].memref.buffer);
	params[1].memref.size = crypto_bignum_num_bytes(key.n);
	/*private exponent */
	crypto_bignum_bn2bin(key.d, params[3].memref.buffer);
	params[3].memref.size = crypto_bignum_num_bytes(key.d);
	
	//free key
	crypto_acipher_free_rsa_public_key(&rsa_key_pub);
	crypto_bignum_free(key.n);
	crypto_bignum_free(key.d);

	return res;
}

/**
 * @brief   Open Session function verifying that only a TA opened
 *          the current PTA
 *
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 * @param[in]  sess_ctx       Session Identifier
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_ACCESS_DENIED     PTA access is denied
 */
static TEE_Result open_session(uint32_t param_types __unused,
		TEE_Param pParams[TEE_NUM_PARAMS] __unused,
		void **sess_ctx)
{
	struct tee_ta_session *sess;

	/* Check if the session is opened by a TA */
	sess = tee_ta_get_calling_session();
	if (!sess)
		return TEE_ERROR_ACCESS_DENIED;

	*sess_ctx = (void *)(vaddr_t)sess->ctx->ops->get_instance_id(sess->ctx);

	return TEE_SUCCESS;
}

/**
 * @brief   Called when a pseudo TA is invoked.
 *
 * @param[in]  sess_ctx       Session Identifier
 * @param[in]  cmd_id         Command ID
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_SHORT_BUFFER      Output buffer too short
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result invokeCommandEntryPoint(void *sess_ctx __unused,
        uint32_t cmd_id, uint32_t param_types,
        TEE_Param params[TEE_NUM_PARAMS])
{
    switch (cmd_id) {
    case PTA_GENERATE_RSAKEY_CMD:
		DMSG("RES: %d", cmd_id);
        return generate_rsa_key(param_types, params);
	case PTA_GENERATE_ECKEY_CMD:
		DMSG("RES: %d", cmd_id);
        return generate_ec_key(param_types, params);
    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}


pseudo_ta_register(
		.uuid = PTA_GENERATE_PTA_UUID,
		.name = GENERATE_PTA_NAME,
		.flags = PTA_DEFAULT_FLAGS,
		.open_session_entry_point = open_session,
		.invoke_command_entry_point = invokeCommandEntryPoint);
