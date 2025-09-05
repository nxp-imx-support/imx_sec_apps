# 1. Intro

This is key import demo project.

It contains 2 seperate folders:
- device/: source code that runs on the device.
- host/: reference code in host side.

## Prepare before key import

1. Install SPSDK on the host.

    The [SPSDK](http://spsdk.nxp.com/examples/_knowledge_base/installation_guide.html) is used to generate signed message for key exchange purpose.

1. Enable secure boot and burn SRKH on the device.

    The signed message is authenticated and verified by OEM SRK.

2. Build the [ELE-AP userspace library](https://github.com/nxp-imx/imx-secure-enclave).

    The project is dynamically linked to the **libele_hsm.so**.


## Supported key type

Since this is preliminary version, only AES and ECC SECP R1 keys are supported.
Details:

| Key type | Key length(bits) | Permitted algo | Usage | Lifetime | Lifecycle |
|:---:|:---:|:---:|:---:|:---:|:---:|
| AES | 128/192/256 | ALL_CIPHER | Encrypt/Decrypt | PERSISTENT | OPEN & CLOSE |
| ECC SECP R1 | 256/384/521 | ECDSA_SHAx | SIGN_HASH/VERIFY_HASH | PERSISTENT | OPEN & CLOSE |
| RSA | 2/3/4K | RSA_PKCS1_V15_SHA_ANY | SIGN_HASH/VERIFY_HASH | PERSISTENT | OPEN & CLOSE |

- Note: OEM keys should be in pem format for ECC/RSA, binary format for AES.
- Note: Below key parameters are temporarily hardcoded in the project, it can be modified by the user on demand:

1. Permitted algo
2. Usage
3. Lifetime
4. Lifecycle

# 2. Device/

In the device side, it's used to do the followings:

1. Export the NXP_PROD_KA_PUK
2. Do key exchange
3. Do key import

## Build

1. Set the **ELE_ROOT** environment which contains the ELE userspace library.
2. Active the cross-compile toolchain.
3. Run `make`

# 3. Host/

In the host(PC server) side, it's used to do the followings:

1. Generate P256 key pair.
2. Do ECDH with NXP_PROD_KA_PUK and get the OEM_IMPORT_CMAC_SK and OEM_IMPORT_WRAP_SK.
3. Generate the TLV blob with OEM key that will be imported.
4. Generate the signed message by [SPSDK](http://spsdk.nxp.com/) which is used for key exchange.

The reference signed message yaml file for SPSDK is under [signed_msg](host/SPSDK/signed_msg/)
The reference code for ECDH, HKDF, generating TLV blob is under host/

## Build

1. Set the **ELE_ROOT** environment which contains the ELE userspace library.
2. Run `make`
- Note: The ELE_ROOT is not for linking library but for seeking header file.

# 4. Quick test

1. Copy `device/bin/ele_key_import` and `device/scripts/run_test_on_board.sh` to the device.
2. Run `run_test_on_board.sh` on the device and send the `nxp_prod_ka_puk.bin` to the `host/scripts`
3. Run `host/scripts/run_on_host.sh` on the host and send the `TLV blob` and `oem_public_key.pem` to the device.
4. Run `host/scripts/calculateHash.py` and repleace the `input_peer_public_key_digest` in the `host/SPSDK/signed_msg/signed_msg.yaml`.
5. Generate signed message with SPSDK and send the `signed_msg.bin` to the device.
6. Run `run_test_on_board.sh` on the device
7. After key import success, try [AES usage](../aes_usage/) for the AES key.

The process can be concluded as below

![1st time Key import](./images/key_import_process_first_time.svg)

![2nd time Key import](./images/key_import_process_second_time.svg)

## Test log

The test log on NXP i.MX hardware can be found under [test](./test/).