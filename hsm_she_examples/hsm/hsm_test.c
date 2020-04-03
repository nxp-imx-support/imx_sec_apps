/*
  * Copyright 2020 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "hsm_api.h"
#include "seco_nvm.h"


void gen_key_and_cipher_test(hsm_hdl_t key_store_hdl){
    hsm_hdl_t key_mgmt_hdl;
    open_svc_key_management_args_t key_mgmt_args = {0};
    
    op_generate_key_args_t gen_key_args = {0};
    uint32_t key_id;
    hsm_key_group_t key_gr = (hsm_key_group_t) 0x01;
    uint8_t pub_key[256/8] = {0};

    hsm_hdl_t  cipher_hdl;
    open_svc_cipher_args_t cipher_args = {0};
    op_cipher_one_go_args_t cipher_1go_args = {0};
    uint8_t iv[16] = {0xAB, 0xAB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t plaintext[16] = {'a','b','c','d','e','f','g','h','i','l','m','n','o','p','q','r'};
    uint8_t ciphertext[16] = {0};
    uint8_t decrypted[16] = {0};

    
    hsm_err_t err;
    
    
    key_mgmt_args.flags = 0;

    // *** Open the key managment service in order to create/import a key ***
    err = hsm_open_key_management_service(key_store_hdl, &key_mgmt_args, &key_mgmt_hdl);
    printf("hsm_open_key_mgmt_service ret:0x%x \n", err);

    // *** using the key managment service generate a key ***
    gen_key_args.key_identifier = &key_id;
    gen_key_args.out_size = 0;                                 //!< length in bytes of the generated key. It must be 0 in case of symetric keys.
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE | HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;   //!< bitmap specifying the operation properties.
    gen_key_args.key_type = HSM_KEY_TYPE_AES_256;              //!< indicates which type of key must be generated.
    gen_key_args.key_group = key_gr;          //!< Key group of the generated key, relevant only in case of create operation. it must be a value in the range 0-1023. Keys belonging to the same group can be cached in the HSM local memory throug the hsm_manage_key_group API
    gen_key_args.key_info = HSM_KEY_INFO_PERSISTENT;            //!< bitmap specifying the properties of the key.
    gen_key_args.out_key = pub_key;                   //!< pointer to the output area where the generated public key must be written (shouldn't be used for symmetric)

    err = hsm_generate_key(key_mgmt_hdl, &gen_key_args);
    printf("hsm_generate_key ret:0x%x \n", err);
    printf("key ID: %d - stored in group: %d\n", key_id, key_gr);

    // *** Open the cipher service to perform encryption/decrption ***
    err = hsm_open_cipher_service(key_store_hdl, &cipher_args, &cipher_hdl);
    printf("hsm_open_cipher_service ret:0x%x \n", err);

    // *** use the generated key to and the cipher service to do encryption ***
    cipher_1go_args.key_identifier = key_id;                //!< identifier of the key to be used for the operation
    cipher_1go_args.iv = iv;                                //!< pointer to the initialization vector (none in case of AES CCM)
    cipher_1go_args.iv_size = (uint16_t)16;                           //!< length in bytes of the initialization vector\n it must be 0 for algorithms not using the initialization vector.\n It must be 12 for AES in CCM mode
    cipher_1go_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CBC;    //!< algorithm to be used for the operation
    cipher_1go_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;         //!< bitmap specifying the operation attributes
    cipher_1go_args.input = plaintext;                      //!< pointer to the input area\n plaintext for encryption\n ciphertext for decryption (in case of CCM is the purported ciphertext)
    cipher_1go_args.output = ciphertext;                    //!< pointer to the output area\n ciphertext for encryption (in case of CCM is the output of the generation-encryption process)\n plaintext for decryption
    cipher_1go_args.input_size = (uint32_t)16;                        //!< length in bytes of the input
    cipher_1go_args.output_size = (uint32_t)16;                       //!< length in bytes of the output
    err = hsm_cipher_one_go(cipher_hdl, &cipher_1go_args);
    printf("hsm_cipher_one_go ret:0x%x \n", err);

#if DEBUG
    printf("hsm_chiper_one_go output encrypt:\n");
    for (uint32_t i=0; i<16; i++) {
        printf("0x%02x ", ciphertext[i]);
        if (i%8 == 7) {
            printf("\n");
        }
    }
#endif

    // *** use the generated key to and the cipher service to do decryption ***
    cipher_1go_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;         //!< bitmap specifying the operation attributes
    cipher_1go_args.input = ciphertext;                      //!< pointer to the input area\n plaintext for encryption\n ciphertext for decryption (in case of CCM is the purported ciphertext)
    cipher_1go_args.output = decrypted;                    //!< pointer to the output area\n ciphertext for encryption (in case of CCM is the output of the generation-encryption process)\n plaintext for decryption

    err = hsm_cipher_one_go(cipher_hdl, &cipher_1go_args);
    printf("hsm_cipher_one_go ret:0x%x \n", err);

#if DEBUG
    printf("hsm_chiper_one_go output decrypt:\n");
    for (uint32_t i=0; i<16; i++) {
        printf("%c ", decrypted[i]);
        //printf("0x%02x ", decrypted[i]);
        if (i%8 == 7) {
            printf("\n");
        }
    }
#endif   

    // *** close cipher service ***
    err = hsm_close_cipher_service(cipher_hdl);
    printf("hsm_close_cipher_service ret:0x%x \n", err);

    // *** close key management service *** 
    err = hsm_close_key_management_service(key_mgmt_hdl);
    printf("hsm_close_key_mgmt_service ret:0x%x \n", err);

}

static uint32_t nvm_status;

static void *hsm_storage_thread(void *arg)
{
    seco_nvm_manager(NVM_FLAGS_HSM, &nvm_status);
}


/* Test entry function. */
int main(int argc, char *argv[])
{
    uint32_t keystore_id;

    hsm_hdl_t hsm_session_hdl;
    hsm_hdl_t key_store_hdl;
    hsm_svc_key_store_flags_t open_key_store_flags;

    open_session_args_t open_session_args;
    open_svc_key_store_args_t open_svc_key_store_args;

    pthread_t tid;

    hsm_err_t err;

    if (argc > 1){
        if (strcmp(argv[1],"-n") == 0 || strcmp(argv[1],"--no-create") == 0) {
            open_key_store_flags = 0;
            if (argc > 2) {
                keystore_id = strtoul(argv[2], NULL, 16);
            } else {
                keystore_id = 0xABCDABCD;
            }
        } else {
            open_key_store_flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
            keystore_id = strtoul(argv[1], NULL, 16);
        }
    } else {
        open_key_store_flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
        keystore_id = 0xABCDABCD;
    }
    


    do {
        nvm_status = NVM_STATUS_UNDEF;

        (void)pthread_create(&tid, NULL, hsm_storage_thread, NULL);

        /* Wait for the storage manager to be ready to receive commands from SECO. */
        while (nvm_status <= NVM_STATUS_STARTING) {
            usleep(1000);
        }
        /* Check if it ended because of an error. */
        if (nvm_status == NVM_STATUS_STOPPED) {
            printf("nvm manager failed to start\n");
            break;
        }

        open_session_args.session_priority = 0;
        open_session_args.operating_mode = 0;
        err = hsm_open_session(&open_session_args,
                                    &hsm_session_hdl);
        if (err != HSM_NO_ERROR) {
            printf("hsm_open_session failed err:0x%x\n", err);
            break;
        }
        printf("hsm_open_session PASS\n");

        //open_svc_key_store_args.key_store_identifier = 0xABCD;
        open_svc_key_store_args.key_store_identifier = keystore_id;
        printf("Using key store ID 0x%02x, flags 0x%02x%d\n", open_svc_key_store_args.key_store_identifier, open_key_store_flags);
        open_svc_key_store_args.authentication_nonce = 0x5a5a5a5a;
        open_svc_key_store_args.max_updates_number   = 100;
        open_svc_key_store_args.flags                = open_key_store_flags;
        err = hsm_open_key_store_service(hsm_session_hdl, &open_svc_key_store_args, &key_store_hdl);
        printf("hsm_open_key_store_service ret:0x%x\n", err);

        //public_key_test(hsm_session_hdl);

        //ecies_tests(hsm_session_hdl);

        // Launch an example generating a key and using it for cipher operations
        gen_key_and_cipher_test(key_store_hdl);

        err = hsm_close_key_store_service(key_store_hdl);
        printf("hsm_close_key_store_service ret:0x%x\n", err);

        err = hsm_close_session(hsm_session_hdl);
        printf("hsm_close_session ret:0x%x\n", err);

        seco_nvm_close_session();
        printf("Closed nvm session\n");

        if (nvm_status != NVM_STATUS_STOPPED) {
            if (pthread_cancel(tid) != 0) {
                printf("failed to kill nvm storage thread\n");
            }
        }

    } while (0);
    return 0;
}
