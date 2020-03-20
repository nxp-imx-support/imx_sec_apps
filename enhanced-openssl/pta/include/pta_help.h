/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2019 NXP
 *
 * @file    pta_help.h
 *
 * @brief  
 */

#ifndef __PTA_HELP_H__
#define __PTA_HELP_H__

/**
 * @brief   PTA UUID generated at http://www.itu.int/ITU-T/asn1/uuid.html
 * f4010dbc-a0ed-4f9a-b9c7-dabb503e3838
 */
#define PTA_HELP_PTA_UUID { \
	0xf4010dbc, 0xa0ed, 0x4f9a, \
	{0xb9, 0xc7, 0xda, 0xbb, 0x50, 0x3e, 0x38, 0x38} }

SK_ATTRIBUTE *TA_GetSKAttr(SK_ATTRIBUTE_TYPE type, SK_ATTRIBUTE *attrs,
			   uint32_t attr_count);

#endif
