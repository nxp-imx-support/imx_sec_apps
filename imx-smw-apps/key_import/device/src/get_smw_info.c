// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "smw_info.h"
#include "get_smw_info.h"
#include <stdint.h>

// SMW version vs LF release
// 5.0  ->  LF-6.12.20 2025 Q2
// 5.1  ->  LF-6.12.34 2025 Q3

// For key import, SMW 5.0 or later is supported
feature_support_t key_import_is_supported(void)
{
    uint32_t major=0, minor=0;

    if(smw_get_version(&major,&minor)!=SMW_STATUS_OK)
    {
        return FEATURE_UNKNOWN;
    }

    if(major>=5)
    {
        return FEATURE_SUPPORTED;
    }

    return FEATURE_NOT_SUPPORTED;
}

// For OEM MK persist, SMW 5.1 or later is supported
// It's already supported in ELE HSM, but missed in the SMW lib
// If this is not supported, the OEM MK cannot be stored in the key store
// In this case, the key exchange must be performed everytime for key import
// If customer want to use this feature with SMW 5.0, a patch should be applied, related to SSMW-984
feature_support_t oem_mk_persist_is_supported(void)
{
    uint32_t major=0, minor=0;

    if(smw_get_version(&major,&minor)!=SMW_STATUS_OK)
    {
        return FEATURE_UNKNOWN;
    }

    if(major>=5 && minor>=1)
    {
        return FEATURE_SUPPORTED;
    }

    return FEATURE_NOT_SUPPORTED;
}

