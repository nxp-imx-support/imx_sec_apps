/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2019 NXP
 *
 * @file    ota_ta.h
 *
 * @brief   Generator of the TA UUID.
 */

#ifndef TA_OTA_H
#define TA_OTA_H

//0527a209-b3cf-4f89-94ab-e01ab7ceaa47
/** @brief  TA UUID generated at http://www.itu.int/ITU-T/asn1/uuid.html */
#define TA_OTA_AUTH_UUID { 0x0527a209, 0xb3cf, 0x4f89, \
		{ 0x94, 0xab, 0xe0, 0x1a, 0xb7, 0xce, 0xaa, 0x47} }

/**
 * @brief  TA CMD ID for generating a wrapped device key
 * and device certificate from model certificate
 */
#define TA_OTA_CMD_GEN_MPPRIV_SIGN 0x03


/** @brief  TA CMD ID retrieving the MP public key as PEM encoded  */
#define TA_OTA_CMD_GET_MP_PUBKEY 0x09


/** @brief  Maximum key size encoded in PEM */
#define TA_OTA_MAX_KEY_PEM_SIZE 2048



#endif /* TA_OTA_H */
