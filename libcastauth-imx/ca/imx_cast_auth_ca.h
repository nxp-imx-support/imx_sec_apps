/* SPDX-License-Identifier: BSD-2-Clause*/
/**
 * @copyright 2019 NXP
 *
 * @file    imx_cast_auth_imx.h
 *
 * @brief   Client Application for Cast Authentication
 *          aspects implementation on i.MX.
 */

#ifndef IMX_CAST_AUTH_IMX_CA_H
#define IMX_CAST_AUTH_IMX_CA_H

/**
 * @brief Retrieve the model certificate chain.
 *
 *  This function retrieves the certificate chain linking
 *  the device certificate template through the model RSA key up to the Cast
 *  Root CA. The chain is a series of concatenated X.509 certificates in PEM
 *  format, starting with the device certificate template and ending with Cast
 *  audio root.
 *  The path to the certificate is defined
 *  by CASTAUTH_MODEL_CRT_ENV environment variable.
 *  Output Cert is in PEM format.
 *
 * @return pointer to model cert chain if success, NULL if error.
 */
char *castauth_GetModelCertChain();

/**
 * @brief Sign a Hash.
 *
 *  This function signs a hash using the wrapped client private key.
 *  The supplied hash should be encoded, have the ASN.1 DER prefix
 *  that identifies the hash type pretended.
 *  This function is responsible for padding the supplied hash uisng PKCS1 type1
 *  padding.
 *  Output signature is 256 byte value.
 *
 * @param wrapped_device_key Black RSA device key in PEM format.
 * @param hash Input hash to sign.
 * @param hash_len Input hash length.
 * @param sig Output signature buffer.
 * @param sig_len Output signature buffer length.
 * @return 0 if success other value if error.
 */
int castauth_SignHash(const char *wrapped_device_key, uint8_t *hash,
		uint32_t hash_len, uint8_t *sig, uint32_t sig_len);

/**
 * @brief Generate device key and certificate.
 *
 * @param bss_id Device MAC address.
 * @param bss_id_len Device MAC address length.
 * @param cert_temp Input certificate template(DER format).
 * @param cert_temp_len Length of certificate template.
 * @param key Output device key.
 * @return 0 if success other value if error.
 */
int castauth_GenDevKeyCert(const char *bss_id, uint32_t bss_id_len,
uint8_t *cert_temp, uint32_t cert_temp_len, char **key);

/**
 *  @brief Import a Black RSA Blob.
 *
 *  This function imports a RSA black key blob to a RSA black key.
 *  Key configuration which was used to generate the blob is not
 *  included in the key.
 *  The API exported the key should be used to import it.
 *	The result is a black key in PEM format.
 *
 * @param blob_pem Input RSA black blob in PEM format.
 * @return pointer to black key if success, NULL if error.
 */
char *castauth_ImportKey(const char *key_pem);

/**
 *  @brief Export a Black RSA Key.
 *
 *  This function exports a RSA black key to a RSA black blob.
 *  Key configuration which was used to generate the blob is not included in the
 *  output blob.
 *  The API importing the blob should be used to import back the key.
 *	The result is a RSA black blob in PEM format.
 *
 * @param key_pem Input RSA black key.
 * @return pointer to blob. NULL if error.
 */
char *castauth_ExportKey(const char *key_pem);

/**
 *  @brief Wraps a plain RSA Key into a Black RSA key.
 *
 *  This function wraps a RSA plain key to an RSA black key.
 *  Key configuration which was used to generate the black key is not included
 *  in the output black key.
 *
 *	The result is a RSA black key in PEM format.
 *
 * @param key_pem Input RSA plain key.
 * @return pointer to black key if success, NULL if error.
 */
char *castauth_WrapKey(const char *key_pem);

/**
 * @brief Generate an RSA key-pair.
 *
 *  This function generates an RSA key-pair.
 *  The output key is PEM encoded.
 *
 * @return pointer to key if success, NULL if error.
 */
char *castauth_GenKeyPair(void);

/**
 * @brief Retrieve the wrapped model key.
 *
 *  This function retrieves the wrapped model key
 *  from the file system. Th path to the key is defined
 *  by CAST_MODEL_PRIVKEY environment variable.
 *  Output Key is in PEM format.
 *
 * @return pointer to key if success, NULL if error.
 */
char *castauth_GetModelKey();

/**
 * @brief Provision a Device key.
 *
 *  This function takes an encrypted RSA plain key generated on a host
 *  decrypt it then turns it into a black key which can be stored in
 *  the file system.
 *
 * @param key Encrypted RSA key form a server/host.
 * @return pointer to blob if success, NULL if error.
 */
char *castauth_ProvKey(const char *key);

/** @brief Retrieve Manufacturing Protection Public Key.
 *
 *  This function retrieves the Manufacturing Protection public key.
 *
 * @return pointer to MP public key if success, NULL if error.
 */
char *castauth_GetMPPubkey();

/** @brief Retrieve Hardware Unique Id.
 *
 *  This function retrieves the Hardware Unique Id.
 *
 * @return  HwID as word, 0 if error.
 */
uint64_t castauth_GetHwId(void);
#endif
