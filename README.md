

# Google Cast Authentication Library

## Introduction

The google cast authentication aspetcs on i.MX are impelemented in 5 separate compoenents.

 - **Client Application (ca)**: interface to access the TA primitives from normal world.
 
 - **Trusted Application (ta)**: is the main component where most of the authentication aspects is implemented, device key and certification generation, signing etc
 
 - **Static/Pseudo Trusted Application (pta)**:  component is dedicated to enable operations in CAAM driver.
	 - RSA key-pair generation
	 -  Blacken RSA private key
	 - Sign using Black RSA key
	 - Signature verification
	 - Black blob encapsulation
	 - Black blob decapsulation
	 - Get chip unique id
	 - Get manufacturing protection public key
 
 - **CAAM driver for OPTEE** : The CAAM driver: used to enable the hardware cryptographic functions.
 
 - **Libcast authentication library** (libcast_auth.so) Wrapper of CA interfacing with Cast application.

Details and build instructions for each component are described in the following secion.

## Installation 

### Clone the repository

Clone the repository to a your home directory or any other location.

    $ cd ~
    $ git clone ssh://git@bitbucket.sw.nxp.com/micrse/libcastauth-imx.git

### Compile & install CA

Compile 

    $ cd ~/libcastauth-imx/ca
    $ make

 The result is `libcast_auth_imx.so` present in the folder.

Install libcast_auth_imx

     $ cp libcast_auth_imx.so <GVA_Image_rootfs>/usr/lib

 Install header file

     $ cp imx_cast_auth_ca.h <GVA_Image_rootfs>/usr/include/


### Install PTA header file

cd ~/libcastauth-imx/pta/include

    $ cp *.h <GVA_Image_rootfs>/usr/include/optee/export-user_ta_arm64/include/

If 32 bits

    $ cp *.h <GVA_Image_rootfs>/usr/include/optee/export-user_ta_arm32/include


### Compile & install TA

Install dependenices

If you don't have Py Crypto then install it

    $ pip install pycrypto

Set Permission

    $ chmod u+x /usr/include/optee/export-user_ta_arm64/scripts/sign.py

If 32 bits 

    $ chmod u+x /usr/include/optee/export-user_ta_arm32/scripts/sign.py

Compile

    $ cd ~/libcastauth-imx/ta
    $ make TA_DEV_KIT_DIR=/usr/include/optee/export-user_ta_arm64

If 32 bits

    $ make TA_DEV_KIT_DIR=/usr/include/optee/export-user_ta_arm32 CROSS_COMPILE=arm-pokymllib32-linux-gnueabi-
    
Install

    $ cp 0527a209-b3cf-4f89-94ab-e01ab7ceaa47.ta /lib/optee_armtz/


### OPTEE-OS

The work is based on 4.14.98_2.0.0_ga

Edit `meta-fsl-bsp-release/imx/meta-bsp/recipes-security/optee-imx/optee-os-imx_git.bb`
and replace:

    SRCBRANCH = "imx_4.14.78_1.0.0_ga"
    OPTEE_OS_SRC ?= "git://source.codeaurora.org/external/imx/imx-optee-os.git;protocol=https"
    SRC_URI = "${OPTEE_OS_SRC};branch=${SRCBRANCH}"
    SRCREV = "6a52487eb0ff664e4ebbd48497f0d3322844d51d"

With

    SRCBRANCH = "imx_4.14.98_2.0.0_ga"
    OPTEE_OS_SRC ?= "git://source.codeaurora.org/external/imx/imx-optee-os.git;protocol=https"
    SRC_URI = "${OPTEE_OS_SRC};branch=${SRCBRANCH}"
    SRCREV = "      7edb46e0fe60261d06bb2390b716201d6772e16f"

Then you can apply the patch `0001-Enable-CAAM-black-key-blob-mp-and-ocotp-features.patch`  to Yocto BSP 4.14.98 and build again imx-boot.

    $ bitbake -f -c compile imx-boot
    $ bitbake imx-boot
   
Then flash the  imx-boot image. The image is under `/tmp/deploy/images/imx8mmevk/` of your Yocto build.

    $ dd if=imx-boot-imx8mmevk-sd.bin-flash_evk of=/dev/mmcblk1 bs=1k seek=33 conv=fsync
    $ reboot
    

### Test if everything works fine using test tools

To make a tool

    $ cd test/
    $ make

Run without arguments to get required argument

     $ ./castauth

### Compile and install libcast_auth

On host machine

Copy lib folder content to nxp_cast_libs under libcast_auth.

Build

    $ cd nxp_cast_libs
    $ export DIR=$(pwd)

For 32 bits

    $ source armv7a.toolchain.sh

For 64 bits

    $ source aarch64.toolchain.sh

Build

    $ mkdir -p build
    $ cd build
    $ cmake ../
    $ make cast_auth

Install it 

    $ cp -v </your_path/nxp_cast_libs>/build/cast-auth/libcast_auth.so <GVA_Image_rootfs>/usr/lib/


## Device individualisation

Model based provisionning

### Install model key

The Model Key should be wrapped first.
use `castauth wrap` and `castauth export` to do it.

    $ cd libcastauth-imx/assets

Wrap it

    $ ./castauth wrap ../assets/model.key ../assets/model.key.black

Export it to be power-cycle safe

    $ ./castauth export ../assets/model.key.black ../assets/model.key.blob

Install Model key

    $ cp ../assets/model.key.blob /factory/


### Install model certificate

    $ cp ../assets/model.crt /factory/

### Create device key and certificate

    $ export CAST_CLIENT_CERT=/factory/client.crt
    $ export CAST_CLIENT_PRIVKEY=/factory/client.key.blob
    $ export CAST_MODEL_CHAIN=/factory/model.crt
    $ export CAST_MODEL_PRIVKEY=/factory/model.key.blob

Clean previous individusalistion assets

    $ /system/chrome/client_auth_indiv --action=delete

Create new one 

    $ /system/chrome/client_auth_indiv --action=create

Ensure that everything is fine

    $ /system/chrome/client_auth_indiv --action=ensure

This will create new assets if failed.

At this level the device is ready to authenticate.

#  Changelog

**Version 1.0 (2019-05-01)**

-   First release

#  Author

Marouene Boubakri <marouene.boubakri@nxp.com>



