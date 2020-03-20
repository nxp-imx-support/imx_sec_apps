/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2019 NXP
 *
 * @file    pta_generate.h
 *
 * @brief   PTA Generate interface identification.
 */
#ifndef __PTA_GENERATE_H__
#define __PTA_GENERATE_H__

/**
 * @brief   PTA UUID generated at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define PTA_GENERATE_PTA_UUID { \
	0x9ac1086c, 0xc8d0, 0x11e9, \
	{0x2a, 0x2a, 0xe2, 0xdb, 0xcc, 0xe4, 0x26, 0xd6} }

/**
 * @brief   PTA Command IDs
 */
#define PTA_GENERATE_RSAKEY_CMD 1
#define PTA_GENERATE_ECKEY_CMD 2

#endif