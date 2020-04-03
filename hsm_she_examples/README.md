This repo contains simple examples on how to use HSM and SHE.

# Setup

Before using these examples, a board compliant with HSM or SHE (imx8qxp or imx8dxl) needs to be setup correctly. In particular if using HSM the appropriate SECO FW that support it needs to be included in the flash.bin. Also, the Linux distribution needs to include the correct MU driver to communicate with SECO. Refer to the application note to correctly setup the board. (*LINK to APP NOTE). Finally seco_libs API needs to be installed from https://github.com/NXP/imx-seco-libs, as the example links directly the libraries provided in such repo.

# Build
Inside `Makefile` specify where the `seco_libs` repo is located using the variable `SECO_LIBS_DIR`. By defualt is set to `~/seco_libs`.

```
SECO_LIBS_DIR = ~/seco_libs
```

Then build the example:
```bash
make all [DEBUG=y]
```
Using `DEBUG` enables printing of internal buffer between operations

# Launch
Two binaries are compiled and can be launched to exploit HSM and SHE apis.
```bash
./hsm_test [-n or --no-create] [keystore_identifier]
```
Use `-n` or `--no-create` to launch the example app without creating a new key store, but only trying to open an existing one. Beware that this operation will only succeed if a key store with the same identifier and known nonce has already been created.

Use `keystore_identifier` (express in hex, ex. `./hsm_test 0xABCDABCD`) to change the key store identifier used during key store service opening. 0xABCDABCD is the default used if none is specified. 

```bash
./she_test [-n or --no-create]
```
Use `-n` or `--no-create` to instruct the example not to create a SHE storage as first operation when launched. In case the application tries to create a SHE storage when one already exist, an error is returned by the SHE api, but the correct execution of the program is not affected.

# HSM Example Overview

Inside HSM, services (in blue in the picture below) are used to provide operations (in yellow in the picture below). To access services and the operation that they offered, a handle is always needed. The handle relative to each service is provided upon opening the same service. 
![HSM structure described through dependencies of services and handles](figures/hsm_services.png)

The first handle that always needs to be created is the session handle, which gives access to all the child services of HSM. Using the session handle the user can access the Hash, Signature Verification and RNG services without any authenitcation, as they don't rely upon secrets. Instead, when wanting to work with secret keys, the Key Store service needs to be opened, providing an identifier and a nonce, both user defined upon opening of the same service. The Key Store service bases its authentication mechanism mostly on Domanin ID, which couple the requests to HSM to a specific message unit and core; the user provided identifier and nonce are mostly used to discern different users of HSM. 

The provided HSM example after opening a session and a key store service, uses the key management service to internally generate an AES-256 key. This key is later used in the cipher service to encrypt and decrypt a buffer. The vaule returned by each operation is printed: expect 0x00 indicating the succesfull execution of the related operation.

By compiling with the `DEBUG` flag set, the encrytped and decrypted buffers will also be printed on the screen.

```
$: ./hsm_test
hsm_open_session PASS
Using key store ID 0xabcdabcd
hsm_open_key_store_service ret:0x0
hsm_open_key_mgmt_service ret:0x0 
hsm_generate_key ret:0x0 
key ID: 2145706691 - stored in group: 1
hsm_open_cipher_service ret:0x0 
hsm_cipher_one_go ret:0x0 
hsm_chiper_one_go output encrypt:
0x18 0x1c 0x56 0xd1 0x29 0x8f 0xf5 0x9a 
0x5b 0x5d 0x6b 0x19 0x0c 0x20 0x2f 0x2c 
hsm_cipher_one_go ret:0x0 
hsm_chiper_one_go output decrypt:
a b c d e f g h 
i l m n o p q r 
hsm_close_cipher_service ret:0x0 
hsm_close_key_mgmt_service ret:0x0 
hsm_close_key_store_service ret:0x0
hsm_close_session ret:0x0
Closed nvm session
```

# SHE example overview

She functionalities are much more limited with respect to HSM. Through the API the user is only allowed to:
* Create an empty storage
* Load keys inside the storage
* Use the loaded keys to perform MAC signing/verification, AES cryptography (in CBC or ECB modes) 
* Access the RNG.

To access all the mentioned features a session handle is needed and the user can receive one providing a key storage identifier and a password. Both these value are user-defined when the key storage is created. The session is the only service that needs to be opened and closed in the SHE subsystem, and the related handle is sufficient to obtain all the SHE features. The authentication performed upon opning of a session has the same mechanism of HSM, and is primarily relying on Domain ID (ID of the core or core-cluster requesting the service to SHE) and MU ID (ID of the Messaging Unit used to send the request to SHE); the provided storage identifier and password are security measures that are not sufficient if DID and MU ID are not correct.

In the example an empty storage is created. In case a storage is already present the SHE API will return an error as the key storage need to be unique in the SHE subsystem. Then a session is opened using the same identifier and password provided when creating the storage. The key is at this point empty, therefore a new encryption key is loaded in the key slot #10. This key is then used to encrypt and later decrypt a buffer. 

The error code returned by each SHE command is printed on screen. If the binary is compiled with the `DEBUG` flag set also the buffer involved in SHE operations will be displayed. 

```bash
$: ./she_test 
she_storage_create ret:0x1
she_open_session handle:0x355c9380
she_cmd_load_key ret:0x0
she_cmd_load_key output m4:
0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x16 
0x64 0x96 0x82 0x0e 0x10 0x65 0x97 0xdd 
0x95 0xde 0x42 0xb6 0x5a 0x4b 0x25 0x8d 
0xb7 0x64 0xa9 0x7f 0xa2 0x0b 0xec 0xa2 
she_cmd_enc_cbc ret:0x0
she_cmd_enc_cbc output decrypt:
0xb7 0x74 0x88 0x7c 0xd0 0xb2 0x39 0x08 
0x69 0xdf 0xcc 0xd0 0x09 0x21 0x9f 0xcb 
she_cmd_dec_cbc ret:0x0
she_cmd_enc_cbc output encrypt:
a b c d e f g h 
i l m n o p q r 
she_close_session
Closed nvm session
```