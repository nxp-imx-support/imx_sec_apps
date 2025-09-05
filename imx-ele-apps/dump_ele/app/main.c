// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include "hsm_api.h"

int main()
{
    printf("Hello, World! %s:%s\n", __DATE__, __TIME__);
    
    hsm_err_t hsmret = HSM_GENERAL_ERROR;
    hsm_hdl_t hsm_session_hdl;
    open_session_args_t open_session_args = {0};

    open_session_args.mu_type = HSM1;
    hsmret = hsm_open_session(&open_session_args,
                                &hsm_session_hdl);
    
    if (hsmret != HSM_NO_ERROR) {
            printf("hsm_open_session failed err:0x%x\n", hsmret);
            return hsmret;
    } else {
        printf("hsm_open_session success\n");
    }

    dump_firmware_log(hsm_session_hdl);

}