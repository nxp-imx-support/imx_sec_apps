The purpose of this project is to connect OpenSSL -> OP-TEE -> CAAM.
This file describes how the project is structured and how to build it.

# This repo contains 4 components:

 ## 1. securekey_lib
 **Secure Object Library**

  **sobj_app.c** -> App that uses securekey_lib for RSA Private Key operations

  **test.c** -> Test securekey_lib functions.

 **securekey.c** -> Library that calls a Trusted Application for cryptographic opperations
            -> API is described on securekey_api.h

## 2. secure_storage_ta 
**Trusted application for Secure Object library**

**secure_storage_create** -> encapsulates a key into a private object

**secure_storage_generate** -> generates a key via pta_generate

**secure_storage_crypto** - >performs Digest, Sign, Decryption via CAAM

## 3. secure_obj-openssl-engine 
**OpenSSL Engine based on Secure Object Library offloading RSA Private Key operation.**

**eng_secure_obj.c** ->  maps the openssl functions to new ones that are using securekey_lib

**sobj_end_app.c** ->  test app that uses libeng_secure_obj.so for RSA Encryption / Decryption

## 4. pta
**Pseudo Trusted application**

**pta_decrypt_mx.c** -> Decrypts a message using RSA_nopad decryption

**pta_generate.c** -> Generates RSR and ECC keys

**pta_hash_mx.c** -> Generates digest of a message

**pta_sign_mx.c** -> Signs a message with RSA or ECC 

## Building project:

### How to build OP-TEE OS and enable libimxcrypt:

repo init -u https://source.codeaurora.org/external/imx/imx-manifest -b imx-linux-sumo -m imx-4.14.98-2.0.0_ga.xml

repo sync 

MACHINE=imx8mmevk DISTRO=fsl-imx-xwayland source ./fsl-setup-release.sh -b imx8mmevk

In sources/meta-fsl-bsp-release/imx/meta-bsp/recipes-security/optee-imx/optee-os-imx_git.bb

add: oe_runmake -C ${S} all CFG_TEE_TA_LOG_LEVEL=4 CFG_TEE_CORE_LOG_LEVEL=4 CFG_IMXCRYPT=y

bitbake -f -c compile optee-os-imx

bitbake optee-os-imx

Add cryptodev module and OpenSSL by editing conf/local.conf file and append

CORE_IMAGE_EXTRA_INSTALL+="cryptodev-module cryptodev-linux openssl"

bitbake core-image-minimal

bzip2 -f -dk core-image-minimal-imx8mmddr4evk.sdcard.bz2 

sudo dd if=core-image-minimal-imx8mmddr4evk.sdcard of=/dev/sdg bs=1k; sync

### Add PTA to project:
Apply patch 0001-PTA-file.patch to $YOCTO_BUILD/imx8mmevk/tmp/work/imx8mmevk-poky-linux/optee-os-imx/git-r0/git

bitbake -f -c compile optee-os-imx

bitbake -f core-image-minimal

### To compile TA, Lib & engine:

export OPENSSL_LIB_PATH=/work/iMX8MMD4EVK/build/tmp/work/aarch64-poky-linux/openssl/1.0.2p-r0/image/usr/lib

export OPENSSL_PATH=/work/iMX8MMD4EVK/build/tmp/work/aarch64-poky-linux/openssl/1.0.2p-r0/image/usr/lib/openssl/ptest/

export CROSS_COMPILE=/work/op-tee_build/toolchains/aarch64/bin/aarch64-linux-gnu-
for 64 bits

export TA_DEV_KIT_DIR=/work/iMX8MMD4EVK/build/tmp/work/imx8mmddr4evk-poky-linux/optee-os-imx/git-r0/build.mx8mmevk/export-ta_arm64

### To install TA:

cd securestorage_ta

make

cp /securestorage_ta/*.ta to $ROOTFS/lib/optee_armtz/

### To install library:

cd securekey_lib

make

cp securekey_lib/out/securekey_lib/libsecure_obj.so $ROOTFS/usr/lib

cp securekey_lib/out/export/include/securekey_api.h $ROOTFS/usr/lib

cp securekey_lib_out/export/app/sobj_app $ROOTFS/usr/lib

### To install engine:
cd secureobj_oppenssl_engine

make

cp secureobj_openssl_engine/libeng_secure_obj.so /$ROOTFS/usr/lib

cp secureobj_openssl_engine/app/sobj_eng_app $ROOTFS/homedir/root/

**More details are available in the AN12632 [1].**

[1] https://www.nxp.com.cn/docs/en/application-note/AN12632.pdf
