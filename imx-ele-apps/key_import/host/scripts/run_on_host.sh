#!/bin/bash

# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright 2025 NXP
#

set -e

NXP_PROD_KA_PUK=nxp_prod_ka_puk.bin
OEM_P256_PRIVATE_KEY=oem_private_key.pem
OEM_P256_PUBLIC_KEY=oem_public_key.pem

OEM_IMPORT_AES_256_KEY=aes256.bin
OEM_IMPORT_ECC_384_KEY=oem_p384_private.pem
OEM_IMPORT_ECC_521_KEY=oem_p521_private.pem
OEM_IMPORT_RSA_4K_KEY=oem_rsa4k_private.pem

TLV_BLOB_AES_256=tlv_blob_aes_256.bin
TLV_BLOB_P384=tlv_blob_p384.bin
TLV_BLOB_P521=tlv_blob_p521.bin
TLV_BLOB_RSA_4K=tlv_blob_rsa4k.bin

# prepare OEM key pair for key exchange
if [ -e $OEM_P256_PRIVATE_KEY ]; then
    echo "$OEM_P256_PRIVATE_KEY already exists, skipping key generation."
else
    echo "Generating OEM key pair..."
    openssl ecparam -genkey -name prime256v1 -out $OEM_P256_PRIVATE_KEY
    openssl ec -in $OEM_P256_PRIVATE_KEY -pubout -out $OEM_P256_PUBLIC_KEY
fi
# echo "OEM private key for key exchange:"
# openssl ec -in $OEM_P256_PRIVATE_KEY -text -noout

# prepare the AES 256 key to be imported
if [ -e $OEM_IMPORT_AES_256_KEY ]; then
    echo "$OEM_IMPORT_AES_256_KEY already exists, skipping key generation."
else
    echo "Generating AES 256 key..."
    openssl rand -out $OEM_IMPORT_AES_256_KEY 32
fi

# prepare the P384 key to be imported
if [ -e $OEM_IMPORT_ECC_384_KEY ]; then
    echo "$OEM_IMPORT_ECC_384_KEY already exists, skipping key generation."
else
    echo "Generating P521 key..."
    openssl ecparam -genkey -name secp384r1 -out $OEM_IMPORT_ECC_384_KEY
fi
# echo "OEM private key for key import:"
# openssl ec -in $OEM_IMPORT_ECC_384_KEY -text -noout

# prepare the P521 key to be imported
if [ -e $OEM_IMPORT_ECC_521_KEY ]; then
    echo "$OEM_IMPORT_ECC_521_KEY already exists, skipping key generation."
else
    echo "Generating P521 key..."
    openssl ecparam -genkey -name secp521r1 -out $OEM_IMPORT_ECC_521_KEY
fi

# prepare the RSA 4K key to be imported
if [ -e $OEM_IMPORT_RSA_4K_KEY ]; then
    echo "$OEM_IMPORT_RSA_4K_KEY already exists, skipping key generation."
else
    echo "Generating RSA 4K key..."
    openssl genpkey -algorithm RSA -out $OEM_IMPORT_RSA_4K_KEY -pkeyopt rsa_keygen_bits:4096
fi

if [ -e $NXP_PROD_KA_PUK ]; then
    echo "$NXP_PROD_KA_PUK already exists."
else
    echo "$NXP_PROD_KA_PUK doesn't exist, please download it from device."
    exit 1
fi
#hexdump -C $NXP_PROD_KA_PUK

../bin/gen_tlv_blob $NXP_PROD_KA_PUK $OEM_P256_PRIVATE_KEY $OEM_IMPORT_ECC_384_KEY $TLV_BLOB_P384
../bin/gen_tlv_blob $NXP_PROD_KA_PUK $OEM_P256_PRIVATE_KEY $OEM_IMPORT_ECC_521_KEY $TLV_BLOB_P521
../bin/gen_tlv_blob $NXP_PROD_KA_PUK $OEM_P256_PRIVATE_KEY $OEM_IMPORT_AES_256_KEY $TLV_BLOB_AES_256
../bin/gen_tlv_blob $NXP_PROD_KA_PUK $OEM_P256_PRIVATE_KEY $OEM_IMPORT_RSA_4K_KEY $TLV_BLOB_RSA_4K