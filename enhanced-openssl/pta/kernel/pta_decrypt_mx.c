// SPDX-License-Identifier: BSD-2-Clause
/**
* @copyright 2019 NXP
*
* @file    pta_decrypt_mx.c
*
* @brief   Pseudo Trusted Application.
*			RSA Decrypt functionality
*/

#include <kernel/pseudo_ta.h>

/* Standard includes */
#include <stdlib.h>
#include <string.h>

/* Library kernel includes */
#include <kernel/pseudo_ta.h>

/* Library libutee includes */
#include <pta_decrypt.h>
#include <pta_help.h>

/* Library tee includes */
#include <tee_api_types.h>

/* Library crypto includes */
#include <crypto_extension.h>
#include <libimxcrypt_acipher.h>

/* Library crypto includes */
#include <crypto/crypto.h>

/* Global includes */
#include <tee_api_defines.h>

/**
 * @brief   Call the Cryptographic Extension API to decrypt
 *          data using RSA key and rsa_nopad algorithm
 *
 *  Params are:
 *    Input:
 *     params[0].value.a = NoNe
 *     params[1].memref  = Encrypted message
 *     params[2].memref  = Reference to RSA key
 *    Output:
 *     params[3].memref  = Decrypted message
 *
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_SHORT_BUFFER      Output buffer too short
 * @retval TEE_ERROR_GENERIC           Generic error
 * 
 */

static TEE_Result decrypt_rsa_nopad(uint32_t param_types,
        TEE_Param params[4])
{
    TEE_Result res = TEE_SUCCESS;
    SK_RSA_KEY *rsa_key;
    size_t msg_len, decr_msg_len;
    struct rsa_keypair key;
	uint8_t *msg, *decr_msg;
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INOUT);

	if (param_types != exp_param_types) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

    /*Call the iMX Crypto API for RSA Decrypt*/
    msg = params[1].memref.buffer;
    msg_len = params[1].memref.size;
    decr_msg = params[3].memref.buffer;

    rsa_key = malloc(sizeof(SK_RSA_KEY));
    if (rsa_key == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    memcpy(rsa_key, params[2].memref.buffer, params[2].memref.size);

    key.e = crypto_bignum_allocate(rsa_key->pub_size * 8);
    key.d = crypto_bignum_allocate(rsa_key->priv_size * 8);
    key.n = crypto_bignum_allocate(rsa_key->mod_size * 8);

    res = crypto_bignum_bin2bn(rsa_key->pub_exp, rsa_key->pub_size,
                key.e);
    if (res != TEE_SUCCESS)
		  goto out;
    res = crypto_bignum_bin2bn(rsa_key->priv_exp, rsa_key->priv_size,
                key.d);
    if (res != TEE_SUCCESS)
		  goto out;
    res = crypto_bignum_bin2bn(rsa_key->modulus, rsa_key->mod_size,
                key.n);
    if (res != TEE_SUCCESS)
	  	goto out;
    res = crypto_acipher_rsanopad_decrypt(&key, msg, msg_len, decr_msg,
                &decr_msg_len);
    DMSG("Print rsa decr %x:\n", res);
    if (res != TEE_SUCCESS)
		  goto out;

    params[3].memref.buffer = decr_msg;
    params[3].memref.size = decr_msg_len;
out:
    crypto_bignum_free(key.e);
    crypto_bignum_free(key.d);
    crypto_bignum_free(key.n);
    return res;
}

/**
 * @brief   Call the Cryptographic Extension API to decrypt
 *          data using RSA key and rsaes_pkcs algorithm
 *
 *  Params are:
 *    Inputs:
 *     params[0]         = NoNe
 *     params[1].memref  = Message to Decrypt
 *     params[2].memref  = Refference to ECC key
 *     params[3].memref  = Decrypted message
 *
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

static TEE_Result decrypt_rsaes(uint32_t param_types,
        TEE_Param params[4])
{
    /* Not supported yet */
      TEE_Result res = TEE_SUCCESS;
    SK_RSA_KEY *rsa_key;
    size_t msg_len, decr_msg_len;
    struct rsa_keypair key;
	uint8_t *msg, *decr_msg;
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INOUT);

	if (param_types != exp_param_types) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

    /*Call the iMX Crypto API for RSA Decryption*/
    msg = params[1].memref.buffer;
    msg_len = params[1].memref.size;
    decr_msg = params[3].memref.buffer;

    rsa_key = malloc(sizeof(SK_RSA_KEY));
    memcpy(rsa_key, params[2].memref.buffer, params[2].memref.size);

    key.e = crypto_bignum_allocate(rsa_key->pub_size * 8);
    key.d = crypto_bignum_allocate(rsa_key->priv_size * 8);
    key.n = crypto_bignum_allocate(rsa_key->mod_size * 8);

    res = crypto_bignum_bin2bn(rsa_key->pub_exp, rsa_key->pub_size,
                key.e);
    if (res != TEE_SUCCESS)
		  goto out;
    res = crypto_bignum_bin2bn(rsa_key->priv_exp, rsa_key->priv_size,
                key.d);
    if (res != TEE_SUCCESS)
		  goto out;
    res = crypto_bignum_bin2bn(rsa_key->modulus, rsa_key->mod_size,
                key.n);
    if (res != TEE_SUCCESS)
	  	goto out;
    res = crypto_acipher_rsanopad_decrypt(&key, msg, msg_len, decr_msg,
                &decr_msg_len);
    DMSG("Print rsa decr %x:\n", res);
    if (res != TEE_SUCCESS)
		  goto out;

    params[3].memref.buffer = decr_msg;
    params[3].memref.size = decr_msg_len;
    
out:
    crypto_bignum_free(key.e);
    crypto_bignum_free(key.d);
    crypto_bignum_free(key.n);
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
    case PTA_DECRYPT_RSA_NOPAD:
        return decrypt_rsa_nopad(param_types, params);
    case PTA_DECRYPT_RSAES:
        return decrypt_rsaes(param_types, params);
    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}

pseudo_ta_register(
        .uuid = PTA_DECRYPT_UUID,
        .name = DECRYPT_PTA_NAME,
        .flags = PTA_DEFAULT_FLAGS,
        .open_session_entry_point = open_session,
        .invoke_command_entry_point = invokeCommandEntryPoint);