# 1. Introduction

This repo contains source code for key import demo on i.MX93. It's based on SMW, ELE library and OpenSSL. It's tested with 2025 Q2 release, lf-6.12.20.

It contains 2 seperate folders:
- device/: source code that runs on the device.
- host/: reference code in host side. It's same with imx-ele-apps/key_import/host

## Prepare before key import

1. (Optional but preferred)Install SPSDK on the host.

    The [SPSDK](http://spsdk.nxp.com/examples/_knowledge_base/installation_guide.html) is used to generate signed message for key exchange purpose.

    CST can be used to do the same, but it requires extra steps including generating unsigned payload, and file transfer between device and host.

1. Enable secure boot and burn SRKH on the device.

    The signed message is authenticated and verified by OEM SRK.

2. Build the [SMW library](https://github.com/nxp-imx/imx-smw).

    The project is dynamically linked to the **libsmw.so**.

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

1. Get the unsigned payload from the OEM public key PEM file.
    - Note: This is necessary for CST but not needed if using SPSDK for signed message
2. Get the NXP_PROD_KA_PUB raw public key.
3. Do key exchange with the signed payload.
4. Import the OEM key with the warpped TLV blob.

## Build

In order to build the project, make sure SMW, ELE and other essential libraries are available. Necessary libraries path are defined in the Makefile.
- SMW
- ELE lib
- SQLite

1. Replace those path or export the variable to your own environment
2. Active the cross toolchain
3. `make`
4. The binary `bin/smw_key_import` is available

# 3. Host/

In the host(PC server) side, it's used to do the followings:

1. Generate P256 key pair for key exchange.
2. Do ECDH with NXP_PROD_KA_PUK and get the OEM_IMPORT_CMAC_SK and OEM_IMPORT_WRAP_SK.
3. Generate the TLV blob with OEM key that will be imported.
4. Generate the signed message by:

    a. [SPSDK](https://spsdk.readthedocs.io/en/latest/index.html).

    b. CST

The reference signed message yaml file for SPSDK is under [signed_msg](host/SPSDK/signed_msg/)

The reference csf file for CST is under [CST](host/CST/)

## Build

1. Set the **ELE_ROOT** environment which contains the ELE userspace library.
    - Note: The app in host side is not linked to the ELE library but some header file are used.
2. Run `make`
3. The binary `bin/gen_tlv_blob` is available

# 4. Usage

1. Build and copy the `device/bin/smw_key_import` and `device/scripts/run_test_on_board.sh` to the target board.
2. Run `./run_test_on_board.sh` on the board.
3. Upload `nxp_prod_ka_puk.bin` to the host.
4. Build `host/bin/gen_tlv_blob` and run `host/scripts/run_on_host.sh` on the host
5. Download `oem_public_key.pem` and TLV blob to the device

If use CST:

6. Run `./run_test_on_board.sh` on the board.
7. Upload `unsigned_msg.bin` to the host.
8. Sign with CST.
9. Download the `signed_msg.bin` to the device.
10. Run `./run_test_on_board.sh` on the board.

If use SPSDK:

6. Run `host/scripts/calculateHash.py` and repleace the `input_peer_public_key_digest` in the `host/SPSDK/signed_msg/signed_msg.yaml`.
7. Generate signed message with SPSDK and send the `signed_msg.bin` to the device.
8. Run `run_test_on_board.sh` on the device

The process with SPSDK can be illustrated as below:

![key impor process](../../imx-ele-apps/key_import/images/key_import_process_first_time.svg)

# 5. Limitation

Due to SMW library, some features are not supported:
1. The key import function is supported with **SMW 5.0 or later**, that's 2025 Q2 **LF-6.12.20** release.
2. For SMW 5.0:
    1. The CKA_ID of imported symmetric key is not set, thus the **Unique ID** in pkcs11-tool is blank. Related to [SSMW-936].
    2. The imported asymmetric keys cannot be retrieved from pkcs11-tool. Related to [SSMW-971].
    3. The OEM_IMPORT_MK_SK is not stored in the HSM key store even we use `args.store_derived_key = true;`, that's because of the **SYNC flag in key exchange** is missing. In this case, the key exchange should be done every time for key import. We cannot do key exchange and key import separately. Related to [SSMW-984].
3. All mentioned issues in SMW 5.0 are resolved in SMW 5.1, that's 2025 Q3 **LF-6.12.34** release.

- Note: If issue 5.2.3 is resolved, please set `OEM_MK_PERSIST_SUPPORTED=true` in [run_test_on_board.sh](./device/scripts/run_test_on_board.sh).