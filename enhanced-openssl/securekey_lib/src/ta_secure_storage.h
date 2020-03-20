/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#ifndef TA_SECURE_STORAGE_H
#define TA_SECURE_STORAGE_H

/* This UUID is generated with uuidgen
   the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html */
#define TA_SECURE_STORAGE_UUID { 0xb05bcf48, 0x9732, 0x4efa, \
		{ 0xa9, 0xe0, 0x14, 0x1c, 0x7c, 0x88, 0x8c, 0x34} }

#define TEE_CREATE_OBJECT		0x1
#define TEE_FIND_OBJECTS		0x2
#define TEE_GET_OBJ_ATTRIBUTES		0x3
#define TEE_ERASE_OBJECT		0x4
#define TEE_SIGN_DIGEST			0x5
#define TEE_DECRYPT_DATA		0x6
#define TEE_DIGEST_DATA			0x7
#define TEE_GENERATE_KEYPAIR		0x8

#endif /*TA_SECURE_STORAGE_H*/
