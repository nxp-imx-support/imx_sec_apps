/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    user_ta_header_defines.h
 *
 * @brief   Header defines.
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <ota_ta.h> /* To get the TA_CAST_AUTH_UUID define */

/** @brief  TA UUID */
#define TA_UUID TA_OTA_AUTH_UUID

/** @brief  TA FLAGS */
#define TA_FLAGS                    (TA_FLAG_MULTI_SESSION | TA_FLAG_EXEC_DDR)
/** @brief  TA Stack size */
#define TA_STACK_SIZE               (10 * 1024)
/** @brief  TA Data size */
#define TA_DATA_SIZE                (32 * 1024)

/** @brief  TA properties */
#define TA_CURRENT_TA_EXT_PROPERTIES \
    { "gp.ta.description", USER_TA_PROP_TYPE_STRING, \
	"Cast Authentication aspects implementation on i.MX TA" }, \
    { "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0010 } }

#endif /* USER_TA_HEADER_DEFINES_H */
