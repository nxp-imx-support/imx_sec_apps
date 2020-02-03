/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2019 NXP
 *
 * @file    imx_cast_auth_ta.h
 *
 * @brief   Generator of the TA UUID.
 */

#ifndef TA_IMX_CAST_AUTH_H
#define TA_IMX_CAST_AUTH_H

//0527a209-b3cf-4f89-94ab-e01ab7ceaa47
/** @brief  TA UUID generated at http://www.itu.int/ITU-T/asn1/uuid.html */
#define TA_CAST_AUTH_UUID { 0x0527a209, 0xb3cf, 0x4f89, \
		{ 0x94, 0xab, 0xe0, 0x1a, 0xb7, 0xce, 0xaa, 0x47} }

/** @brief  TA CMD ID for generating RSA key-pair */
#define TA_CASTAUTH_CMD_GEN_KEYPAIR 0x01

/** @brief  TA CMD ID for signing a hash using a black RSA key */
#define TA_CASTAUTH_CMD_SIGN_HASH 0x02

/**
 * @brief  TA CMD ID for generating a wrapped device key
 * and device certificate from model certificate
 */
#define TA_CASTAUTH_CMD_GEN_DEV_KEY_CERT 0x03

/**
 * @brief  TA CMD ID for retrieving the certificate chain
 * linking the device certificate template through
 * the model RSA key up to the Cast Root CA
 */
#define TA_CASTAUTH_CMD_GET_MODEL_CERT_CHAIN 0x04

/** @brief  TA CMD ID for wrapping a Plain RSA key to a Black RSA key */
#define TA_CASTAUTH_CMD_WRAP_KEY 0x05

/** @brief  TA CMD ID for encapsulating a Black RSA key to a Blob RSA key */
#define TA_CASTAUTH_CMD_EXPORT_KEY 0x06

/** @brief  TA CMD ID for decapsulating a Blob RSA key to a Black RSA key */
#define TA_CASTAUTH_CMD_IMPORT_KEY 0x07

/**
 * @brief  TA CMD ID for provisioning a device with an RSA key generated
 * and encrypted on a host machine
 */
#define TA_CASTAUTH_CMD_PROV_DEV_KEY 0x08

/** @brief  TA CMD ID retrieving the MP public key as PEM encoded  */
#define TA_CASTAUTH_CMD_GET_MP_PUBKEY 0x09

/** @brief  TA CMD ID retrieving the Hardware Unique Id */
#define TA_CASTAUTH_CMD_GET_HW_ID 0x10

/** @brief  Maximum key size encoded in PEM */
#define TA_CASTAUTH_MAX_KEY_PEM_SIZE 2048

/** @brief  Maximum certificate size encoded in PEM */
#define TA_CASTAUTH_MAX_CERT_PEM_SIZE 4096

/** @brief  Plain RSA key PEM anchors */
#define PEM_BEGIN_PRIVATE_KEY_PLAIN  "-----BEGIN RSA PRIVATE KEY-----\n"
#define PEM_END_PRIVATE_KEY_PLAIN    "-----END RSA PRIVATE KEY-----\n"

/** @brief  Black RSA key PEM anchors */
#define PEM_BEGIN_PRIVATE_KEY_BLACK  "-----BEGIN BLACK RSA PRIVATE KEY-----\n"
#define PEM_END_PRIVATE_KEY_BLACK    "-----END BLACK RSA PRIVATE KEY-----\n"

/** @brief  Blob RSA key PEM anchors */
#define PEM_BEGIN_PRIVATE_KEY_BLOB  "-----BEGIN BLOB RSA PRIVATE KEY-----\n"
#define PEM_END_PRIVATE_KEY_BLOB   "-----END BLOB RSA PRIVATE KEY-----\n"

#endif /* TA_IMX_CAST_AUTH_H */
