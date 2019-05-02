/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2019 NXP
 *
 * @file    pta_ocotp.h
 *
 * @brief   PTA OCOTP interface identification.
 */
#ifndef __PTA_OCOTP_H__
#define __PTA_OCOTP_H__


/**
 * @brief   PTA UUID generated at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define PTA_OCOTP_PTA_UUID { \
	0x9abdf255, 0xd8fa, 0x40de, \
	{0x8f, 0x60, 0x4d, 0x0b, 0x27, 0x92, 0x7b, 0x7d}}

/**
 * @brief   Get Chip Unique Id
 */	
#define PTA_OCOTP_CMD_CHIP_UID 1


#endif /* __PTA_OCOTP_H__ */
