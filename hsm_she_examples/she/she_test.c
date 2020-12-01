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

#include "she_api.h"
#include "seco_nvm.h"

static uint32_t nvm_status;

uint8_t m1[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdd};

uint8_t m2[32] = {0x99, 0x34, 0x69, 0x32, 0xe0, 0x23, 0xa1, 0xf0,
                  0xa4, 0xc5, 0x1d, 0x5d, 0x40, 0xbf, 0xdb, 0xfa,
                  0x63, 0xb4, 0xb1, 0xf6, 0xcb, 0xa5, 0x0f, 0x11,
                  0x74, 0x84, 0xa1, 0x9b, 0xcf, 0xff, 0x1e, 0x2a};

uint8_t m3[16] = {0x85, 0x61, 0x0d, 0xbc, 0xbe, 0xe1, 0x00, 0x3c,
                  0xab, 0xde, 0x05, 0x52, 0x86, 0x2e, 0xa7, 0x62};

uint8_t m4[32] = {0};
uint8_t m5[16] = {0};

static void *she_storage_thread(void *arg)
{
    seco_nvm_manager(NVM_FLAGS_SHE, &nvm_status);
}

void encrypt_decrypt_test(struct she_hdl_s *sess_hdl){

    she_err_t err;
    uint8_t iv[16] = {0xAB, 0xAB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t plaintext[16] = {'a','b','c','d','e','f','g','h','i','l','m','n','o','p','q','r'};
    uint8_t ciphertext[16] = {0};
    uint8_t decrypted[16] = {0};

    // Load a key in slot 10, using the SHE protocol which relies on three messages (m1-m3) for sending the encrypted key
    // and 2 messages (m4-m5) to receive confirmation
    err = she_cmd_load_key(sess_hdl, SHE_KEY_DEFAULT, SHE_KEY_10, m1, m2, m3, m4, m5);
    printf("she_cmd_load_key ret:0x%x\n", err);

#if DEBUG
    printf("she_cmd_load_key output m4:\n");
    for (uint32_t i=0; i<32; i++) {
        printf("0x%02x ", m4[i]);
        if (i%8 == 7) {
            printf("\n");
        }
    }
#endif   

    // Use the loaded key to encrypt a plaintext using CBC
    err = she_cmd_enc_cbc(sess_hdl, SHE_KEY_DEFAULT, SHE_KEY_10, 16, iv, plaintext, ciphertext);
    printf("she_cmd_enc_cbc ret:0x%x\n", err); 

#if DEBUG
    printf("she_cmd_enc_cbc output decrypt:\n");
    for (uint32_t i=0; i<16; i++) {
        printf("0x%02x ", ciphertext[i]);
        if (i%8 == 7) {
            printf("\n");
        }
    }
#endif

    // Use the loaded key to decrypt the ciphertext and reobtain the original buffer
    err = she_cmd_dec_cbc(sess_hdl, SHE_KEY_DEFAULT, SHE_KEY_10, 16, iv, ciphertext, decrypted);
    printf("she_cmd_dec_cbc ret:0x%x\n", err); 

#if DEBUG
    printf("she_cmd_enc_cbc output encrypt:\n");
    for (uint32_t i=0; i<16; i++) {
        printf("%c ", decrypted[i]);
        if (i%8 == 7) {
            printf("\n");
        }
    }
#endif

}


/* Test entry function. */
int main(int argc, char *argv[])
{
    pthread_t tid;
    she_err_t err;
    int create_storage = 1;

    // she_stroage_create arguments
    uint32_t key_storage_identifier = 0;
    uint32_t password;
    uint16_t max_updates_number;
    uint32_t signed_message_length;
    uint8_t *signed_message;
    
    // she_open_session arguments
    struct she_hdl_s *sess_hdl = NULL;

    // use command line option "-n" or "--no-create" to avoid requesting SHE to create a new storage
    if (argc > 1){
        if (strcmp(argv[1], "-n") == 0 || strcmp(argv[1], "--no-create") == 0)
            create_storage = 0;
    }

    do {
        nvm_status = NVM_STATUS_UNDEF;

        (void)pthread_create(&tid, NULL, she_storage_thread, NULL);

        /* Wait for the storage manager to be ready to receive commands from SECO. */
        while (nvm_status <= NVM_STATUS_STARTING) {
            usleep(1000);
        }
        /* Check if it ended because of an error. */
        if (nvm_status == NVM_STATUS_STOPPED) {
            printf("nvm manager failed to start\n");
            goto exit;
        }

        key_storage_identifier = 0;     //< key store identifier
        password = 0xbec00001;          //< user defined nonce to be used as authentication proof for accesing the key store.
        max_updates_number = 300;       //< not supported
        signed_message = NULL;          //< pointer to a signed message authorizing the operation (NULL if no signed message to be used)
        signed_message_length = 0;      //< length in bytes of the signed message


        // create an **EMPTY** SHE storage, must be done at least once before using any other SHE api
        if (create_storage == 1){
            err = she_storage_create( key_storage_identifier,
                                password,
                                max_updates_number,
                                signed_message,
                                signed_message_length );
            printf("she_storage_create ret:0x%x\n", err); 
        } 

        // open SHE session and receive a struct containing valid handles for all the SHE services
        sess_hdl = she_open_session(key_storage_identifier, password, NULL, NULL);
        printf("she_open_session handle:0x%x\n", sess_hdl);
        if (sess_hdl == 0)
            goto exit;

        encrypt_decrypt_test(sess_hdl);

        she_close_session(sess_hdl);
        printf("she_close_session\n");

exit:
        if (nvm_status != NVM_STATUS_STOPPED) {
            if (pthread_cancel(tid) != 0) {
                printf("failed to kill nvm storage thread\n");
            }
        }
        seco_nvm_close_session();
        printf("Closed nvm session\n");

    } while (0);
    return 0;
}
