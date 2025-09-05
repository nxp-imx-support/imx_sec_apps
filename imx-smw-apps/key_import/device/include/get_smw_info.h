// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef _GET_SMW_INFO_H_
#define _GET_SMW_INFO_H_

typedef enum{
    FEATURE_NOT_SUPPORTED=0,
    FEATURE_SUPPORTED=1,
    FEATURE_UNKNOWN=2
} feature_support_t;

feature_support_t key_import_is_supported(void);
feature_support_t oem_mk_persist_is_supported(void);

#endif