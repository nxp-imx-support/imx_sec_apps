#!/bin/bash

# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright 2025 NXP
#

set -e

OEM_MK_PERSIST_SUPPORTED=false

NXP_PROD_KA_PUK=nxp_prod_ka_puk.bin
OEM_P256_PUBLIC_KEY=oem_public_key.pem
UNSIGNED_PAYLOAD=unsigned_msg.bin
SIGNED_MESSAGE=signed_msg.bin
TLV_BLOB_AES_256=tlv_blob_aes_256.bin
TLV_BLOB_P384=tlv_blob_p384.bin
TLV_BLOB_P521=tlv_blob_p521.bin
TLV_BLOB_RSA_4K=tlv_blob_rsa4k.bin

systemctl start nvm_daemon
systemctl status nvm_daemon

if [ -f $NXP_PROD_KA_PUK ]; then
    echo "$NXP_PROD_KA_PUK exists."
else
    echo "generating $NXP_PROD_KA_PUK..."
    ./smw_key_import export_nxp $NXP_PROD_KA_PUK
    echo "Please:"
    echo "      1. Upload the $NXP_PROD_KA_PUK file to the host."
    echo "      2. Generate TLV blob in host."
    echo "      3. Download TLV blob and $OEM_P256_PUBLIC_KEY from host."
    exit 0
fi

# check the existence of the OEM public key
if [ -f $OEM_P256_PUBLIC_KEY ]; then
    echo "$OEM_P256_PUBLIC_KEY exists."
else
    echo "$OEM_P256_PUBLIC_KEY doesn't exist, please download it from host."
    exit 1
fi

if [ -f $SIGNED_MESSAGE ]; then
    echo "$SIGNED_MESSAGE exists."
else
    echo "generating $UNSIGNED_PAYLOAD..."
    ./smw_key_import get_payload $OEM_P256_PUBLIC_KEY $UNSIGNED_PAYLOAD
    # sign the generated unsigned payload on host
    # need to be done by CST or SPSDK
    echo "Please:"
    echo "a. Use CST:"
    echo "      1. Upload $UNSIGNED_PAYLOAD to the host."
    echo "      2. Sign $UNSIGNED_PAYLOAD in host with CST."
    echo "      3. Download $SIGNED_MESSAGE from host."
    echo "b. Use SPSDK:"
    echo "      1. Calculate hash with calculateHash.py and replace input_peer_public_key_digest in the yaml"
    echo "      2. Generate $SIGNED_MESSAGE with yaml."
    echo "      3. Download $SIGNED_MESSAGE from host."
    exit 0
fi

if [ "$OEM_MK_PERSIST_SUPPORTED" = true ]; then
    echo "OEM MK persist support is enabled"
    # check the existence of the signed msg
    if [ -f $SIGNED_MESSAGE ]; then
        ./smw_key_import key_exchange $SIGNED_MESSAGE $OEM_P256_PUBLIC_KEY
    else
        echo "$SIGNED_MESSAGE doesn't exist, please download it from host."
        exit 1
    fi

    set +e

    # check the existence of the TLV blob
    if [ -f $TLV_BLOB_AES_256 ]; then
        ./smw_key_import do_import $TLV_BLOB_AES_256
    else
        echo "$TLV_BLOB_AES_256 doesn't exist, please download it from host."
    fi

    if [ -f $TLV_BLOB_P384 ]; then
        ./smw_key_import do_import $TLV_BLOB_P384
    else
        echo "$TLV_BLOB_P384 doesn't exist, please download it from host."
    fi

    if [ -f $TLV_BLOB_P521 ]; then
        ./smw_key_import do_import $TLV_BLOB_P521
    else
        echo "$TLV_BLOB_P521 doesn't exist, please download it from host."
    fi

    if [ -f $TLV_BLOB_RSA_4K ]; then
        ./smw_key_import do_import $TLV_BLOB_RSA_4K
    else
        echo "$TLV_BLOB_RSA_4K doesn't exist, please download it from host."
    fi
else
    set +e
    echo "OEM MK persist support is disabled"
    # check the existence of the TLV blob and signed msg
    if [ -f $TLV_BLOB_AES_256 ] && [ -f $SIGNED_MESSAGE ]; then
        ./smw_key_import do_import $SIGNED_MESSAGE $OEM_P256_PUBLIC_KEY $TLV_BLOB_AES_256
    else
        echo "$TLV_BLOB_AES_256 or $SIGNED_MESSAGE doesn't exist, please download it from host."
    fi

    if [ -f $TLV_BLOB_P384 ]; then
        ./smw_key_import do_import $SIGNED_MESSAGE $OEM_P256_PUBLIC_KEY $TLV_BLOB_P384
    else
        echo "$TLV_BLOB_P384 doesn't exist, please download it from host."
    fi

    if [ -f $TLV_BLOB_P521 ]; then
        ./smw_key_import do_import $SIGNED_MESSAGE $OEM_P256_PUBLIC_KEY $TLV_BLOB_P521
    else
        echo "$TLV_BLOB_P521 doesn't exist, please download it from host."
    fi

    if [ -f $TLV_BLOB_RSA_4K ]; then
        ./smw_key_import do_import $SIGNED_MESSAGE $OEM_P256_PUBLIC_KEY $TLV_BLOB_RSA_4K
    else
        echo "$TLV_BLOB_RSA_4K doesn't exist, please download it from host."
    fi
fi

# For SMW 5.0, the asymmetric key cannot be retrieved, and the symmetric key id is not set.
# For SMW 5.1 or later, the above issue is fixed.
# export PKCS11_MODULE_PATH="/usr/lib/libsmw_pkcs11.so.5"
# pkcs11-tool --list-objects --login --module $PKCS11_MODULE_PATH