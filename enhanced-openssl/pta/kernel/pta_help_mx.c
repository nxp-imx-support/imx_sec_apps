// SPDX-License-Identifier: BSD-2-Clause
/**
* @copyright 2019 NXP
*
* @file    pta_help_mx.c
*
* @brief   Pseudo Trusted Application.
*/


/* Standard includes */
#include <stdlib.h>
#include <string.h>

/* Library kernel includes */
#include <kernel/pseudo_ta.h>

/* Library libutee includes */
#include <pta_help.h>

/* Library tee includes */
#include <tee_api_types.h>

/* Library crypto includes */
#include <crypto_extension.h>

/* Library crypto includes */
#include <crypto/crypto.h>

/* Global includes */
#include <tee_api_defines.h>

SK_ATTRIBUTE *TA_GetSKAttr(SK_ATTRIBUTE_TYPE type, SK_ATTRIBUTE *attrs,
			   uint32_t attr_count)
{
	size_t i;
	SK_ATTRIBUTE *match_attr = NULL;

	for (i = 0; i < attr_count; i++) {
		if (type == attrs[i].type) {
			match_attr = &attrs[i];
			break;
		}
	}

	if (match_attr)
		DMSG("Match Attribute - value: %p, valueLen: %08x!\n",
			match_attr->value, match_attr->valueLen);

	return match_attr;
}
