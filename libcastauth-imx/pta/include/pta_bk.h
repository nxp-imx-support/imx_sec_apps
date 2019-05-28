/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2019 NXP
 *
 * @file    pta_bk.h
 *
 * @brief   PTA Black key interface identification.
 */
#ifndef __PTA_BK_H__
#define __PTA_BK_H__

/**
 * @brief   PTA UUID generated at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define PTA_BK_PTA_UUID { \
	0xf4557e21, 0xaa4f, 0x4259, \
	{0x90, 0xb6, 0xf9, 0x77, 0x6c, 0xee, 0xba, 0x29} }

/**
 * @brief   Encapsulates a plain key into black key command id
 */
#define PTA_BK_CMD_ENCAPS 1

/**
 * @brief   Sign using black key command id in PTA
 */
#define PTA_BK_CMD_SIGN   2

/**
 * @brief   PTA black key Type
 *          Enumerate must be the same as the bk_type defined in the
 *          crypto_extension.h
 */
enum PTA_BK_TYPE {
	PTA_BK_ECB, ///< Black key mode - key encrypted in AES ECB
	PTA_BK_CCM, ///< Black key mode - key encrypted in AES CCM
};

#endif /* __PTA_BK_H__ */
