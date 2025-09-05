#!/bin/bash

# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright 2025 NXP
#

set -e

NXP_PROD_KA_PUK=nxp_prod_ka_puk.bin
OEM_P256_PUBLIC_KEY=oem_public_key.pem
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
    ./ele_key_import export_nxp $NXP_PROD_KA_PUK
    echo "Please:"
    echo "      1. Upload the $NXP_PROD_KA_PUK file to the host."
    echo "      2. Generate $TLV_BLOB_AES_256 $TLV_BLOB_P384 in host."
    echo "      3. Download $TLV_BLOB_AES_256 $TLV_BLOB_P384 from host."
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
    echo "$SIGNED_MESSAGE doesn't exist, please generate it with SPSDK."
    exit 1
fi

./ele_key_import key_exchange $SIGNED_MESSAGE $OEM_P256_PUBLIC_KEY

set +e

# check the existence of the TLV blob
if [ -f $TLV_BLOB_AES_256 ]; then
    echo "$TLV_BLOB_AES_256 exists."
    ./ele_key_import do_import $TLV_BLOB_AES_256
else
    echo "$TLV_BLOB_AES_256 doesn't exist, please download it from host."
fi


if [ -f $TLV_BLOB_P384 ]; then
    echo "$TLV_BLOB_P384 exists."
    ./ele_key_import do_import $TLV_BLOB_P384
else
    echo "$TLV_BLOB_P384 doesn't exist, please download it from host."
fi


if [ -f $TLV_BLOB_P521 ]; then
    echo "$TLV_BLOB_P521 exists."
    ./ele_key_import do_import $TLV_BLOB_P521
else
    echo "$TLV_BLOB_P521 doesn't exist, please download it from host."
fi

if [ -f $TLV_BLOB_RSA_4K ]; then
    echo "$TLV_BLOB_RSA_4K exists."
    ./ele_key_import do_import $TLV_BLOB_RSA_4K
else
    echo "$TLV_BLOB_RSA_4K doesn't exist, please download it from host."
fi