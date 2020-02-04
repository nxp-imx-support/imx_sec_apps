/* SPDX-License-Identifier: BSD-2-Clause*/
/**
 * @copyright 2019 NXP
 *
 * @file    ota_ca.h
 *
 * @brief   Client Application for OTA Authentication
 *          aspects implementation on i.MX.
 */

#ifndef OTA_CA_H
#define OTA_CA_H


/** @brief Retrieve Manufacturing Protection Public Key.
 *
 *  This function retrieves the Manufacturing Protection public key.
 *
 * @return pointer to MP public key if success, NULL if error.
 */
char *ota_GetMPPubkey();

/**
 * @brief Sign with Manufacturing Protection Private key.
 *
 *  This function signs data using manufacturing potection private key.
 *  The supplied data should be uint8_t type. 
 *  Output signature is 64 byte value.
 *  Output mpmr is 32 byte value.
 *
 * @param data to be signed.
 * @param data_len Input hash length.
 * @param sig Output signature buffer.
 * @param sig_len Output signature buffer length.
 * @param mpmr Output mpmr buffer.
 * @param mpmr_len Output mpmr buffer length.
 * @return 0 if success other value if error.
 */
int ota_GenMPPRivSignature(uint8_t *data, uint32_t data_len, uint8_t *sig, 
		uint32_t sig_len, uint8_t *mpmr, uint32_t mpmr_len);

#endif
