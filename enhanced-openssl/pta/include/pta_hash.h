/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2019 NXP
 *
 * @file    pta_hash.h
 *
 * @brief   PTA Hash interface identification.
 */
#ifndef __PTA_HASH_H__
#define __PTA_HASH_H__

/**
 * @brief   PTA UUID generated at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define PTA_HASH_PTA_UUID { \
	0xc45a4022, 0xc8c0, 0x11e9, \
	{0xa3, 0x2f, 0x2a, 0x2a, 0xe2, 0xdb, 0xcc, 0xe4} }

/**
 * @brief   PTA Command IDs
 */
#define PTA_HASH_CMD_DIGEST 1


#endif
