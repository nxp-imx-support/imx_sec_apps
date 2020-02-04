Over-the-air updates demo application

This document provides a step-by-step procedure on how to deploy OTA updates on i.MX8MMDDR4 EVK device.
This prototype implementation is based on Mender, an open source project for updating IoT devices. On top of Mender, 
we have integrated the Manufacturing Protection mechanism for device – server authentication and U-Boot update feature.

1.1 Download application
------------------------------------
	
- The patches and the source code of the application can be downloaded by cloning this
  bitbucket repo, branch master:

  $ git clone ssh://git@bitbucket.sw.nxp.com/imxs/imx_sec_apps.git

1.2 Mender client-server
-------------------------------------
- In order to build an image with mender, please follow this user guide: 
	https://hub.mender.io/t/nxp-i-mx-8m-mini-evaluation-kit/659

- In order to test the device-server connection, please follow the steps described here: 
	https://docs.mender.io/2.2/getting-started
	
  After the demo version is up and running, we can proceed to modifying the mender client and server in order to 
  integrate the Manufacturing Protection mechanism and the secondary U-Boot feature.
  For any problems related to client-server communication, please see the troubleshooting section from the Mender project documentation.
  
1.3 Enable Manufacturing protection
-----------------------------------------
- Edit sources/meta-fsl-bsp-release/imx/meta-bsp/recipes-security/optee-imx/optee-os-imx_git.bb and replace 
	SRCBRANCH = "imx_4.14.78_1.0.0_ga"
	OPTEE_OS_SRC ?= "git://source.codeaurora.org/external/imx/imx-optee-os.git;protocol=https"
	SRC_URI = "${OPTEE_OS_SRC};branch=${SRCBRANCH}"
	SRCREV = "6a52487eb0ff664e4ebbd48497f0d3322844d51d"

	With

	SRCBRANCH = "imx_4.14.98_2.0.0_ga"
	OPTEE_OS_SRC ?= "git://source.codeaurora.org/external/imx/imx-optee-os.git;protocol=https"
	SRC_URI = "${OPTEE_OS_SRC};branch=${SRCBRANCH}"
	SRCREV = " 7edb46e0fe60261d06bb2390b716201d6772e16f"

- Append CFG_IMXCRYPT=y to oe_runmake 
	"oe_runmake -C ${S} all CFG_TEE_TA_LOG_LEVEL=0 CFG_IMXCRYPT=y"

- Build Optee-os 
	$ bitbake -f -c compile optee-os-imx
	$ bitbake optee-os-imx

- Apply patches:
	$ cd ~/imx-yocto-bsp/sources/meta-fsl-bsp-release/imx/meta-bsp/recipes-security/optee-imx/
	$ mkdir patches

- Copy the patches found on the source code under pta directory to the patches directory. 
  Create a bbappend file in order to add the patches:
	FILESEXTRAPATHS_prepend := "${THISDIR}/patches:"

	SRC_URI_append = " file://0001-Enable-CAAM-MP-feature.patch”
	SRC_URI_append = " file://0002-Sign-message-MP.patch”

  The patches get applied in the do_patch task after fetching and unpacking, but before configuring or compiling.

- Build Optee-os again by invoking
	$ bitbake -f -c compile optee-os-imx
	$ bitbake optee-os-imx

1.4  Build Trusted Application (TA)
---------------------------------------
- Set OPENSSL_LIB_PATH, OPENSSL_PATH, CROSS_COMPILE, TA_DEV_KIT_DIR env variables.
  Example:
    $ export OPENSSL_LIB_PATH= ~/imx-yocto-bsp/build/tmp/work/aarch64-poky-linux/openssl/1.0.2p-r0/image/usr/lib
	$ export OPENSSL_PATH=~/imx-yocto-bsp/build/tmp/work/aarch64-poky-linux/openssl/1.0.2p-r0/image/usr/lib/openssl/ptest/
	$ export CROSS_COMPILE=~/toolchains/aarch64/bin/aarch64-linux-gnu-
	$ export TA_DEV_KIT_DIR=~/imx-yocto-bsp/build/tmp/work/imx8mmddr4evk-poky-linux/optee-os-imx/git-r0/build.mx8mmevk/export-ta_arm64
- Build:
	$ cd ~/demo_ota_updates/ta
	$ make
- Install:
	$ cp *.ta <Image_rootfs>/lib/optee_armtz/

1.5 Build Client Application (CA)
----------------------------------------
- Build:
	$ cd ~/demo_ota_updates/ca
	$ make
- Install:
	$ cp libsecure_ota_optee.so <Image_rootfs>/usr/lib
	$ cp ota_ca.h <Image_rootfs>/usr/include/

1.6 Secureota optee utility on the board:
This binary sends the requests to the CA for extracting the MPPubk and MPPrivk signature.
- Build:
	$ cd ~/demo_ota_updates/bin/
	$ make
- Install:
	$ cp secureota <Image_rootfs>/usr/bin/

1.7 Add secondary U-Boot functionality 
---------------------------------------
Redundant U-Boot if FIT image gets corrupted.
- Edit u-boot-mender-common.inc and add:
	$ cd ~/imx-yocto-bsp/sources/meta-mender/meta-mender-core/recipes-bsp/u-boot/
	$ vim u-boot-mender-common.inc
	Add: SRC_URI_append_mender-uboot = " file://0001-Add-support-secondary-boot.patch”
	Copy the patch 0001-Add-support-secondary-boot.patch to the patches/ directory

- Build U-Boot:
	$ bitbake -f -c compile u-boot
	$ bitbake u-boot

1.8 Add CAAM blobs support 
---------------------------------------
Needed for creating a user-space blob for the MPPubk.
- Apply patches:
	$ cd ~/imx-yocto-bsp/sources/meta-fsl-bsp-release/imx/meta-bsp/recipes-kernel/linux/
	$ mkdir patches

- Copy the patches found on the source code under caam_blobs directory to the patches directory. 
  Create a bbappend  file in order to add the patches:
	FILESEXTRAPATHS_prepend := "${THISDIR}/patches:"
	 
	SRC_URI_append = " file://0001-Added-the-support-for-i.MX8-8X-in-sync-with-Linux-4..patch”
	SRC_URI_append = " file://0002-Add-kernel-configs.patch”

- Compile Linux Kernel:
	$ bitbake virtual/kernel -f -c compile

- Build a bootable .sdcard image and write it to sdcard:
	$ bitbake -f core-image-minimal
	$ sudo dd if=core-image-minimal.sdimg  of=/dev/<sdX> bs=1M && sudo sync

1.9 Customized Mender client-server
-------------------------------------
- Mender client:
	a. Download sources: https://github.com/mendersoftware/mender.
	b. Apply patch found in mender_client directory:
		$ cd ~/mender/src/github.com/mendersoftware/mender
		$ git apply 0001-Use-MP-mechanism-deviceuath-client.patch
	c. Build Mender client as described in the Mender documentation
	d. Copy mender executable to the rootfs on your board
	    $ cp mender /usr/bin
		
- Mender server:
  Add MP mechanism in the device authentication service: 
	a. Download mender deviceauth service: https://github.com/mendersoftware/deviceauth.
	b. Apply the patch found in mender_server directory and build the docker container: 
		$ cd ~/mender-server/deviceauth
		$ git apply 0001-Verify-MPPrivk-signature-deviceauth-server.patch  
	c. Set the Mender server to use the previously built container and start the Mender server.
	d. The Mender UI should now be found at https://localhost/.

2. Usage
- The device should appear as pending in the Mender Server until the Mender Server owner authorizes the device from
  Mender UI server. After getting authorized by the server owner, updates are ready to be deployed on the device.
- The status of the deployed artifact can be seen in the Mender Server UI or, for Mender client, on the device:
	$ journalctl -u mender
- Create an artifact with a new U-Boot binary file for an imx8mmddr4evk device and upload it to Mender Server UI:
	$ export DEVICE_TYPE=imx8mmddr4evk
	$ ./mender-artifact write module-image -t $DEVICE_TYPE -o update-uboot.mender -T update-uboot -n updateuboot-1.0 - f signed_flash.bin
- The mender-artifact utility version is also important. When building the .sdcard image, if mender-artifact receipe is for version 2, 
  the device will not accept artifacts created with version 3. In order to fix this, the prefered versions can be metioned in conf/local.conf 
  file from the yocto build:
    PREFERRED_VERSION_pn-mender-artifact = "3.1.0"
    PREFERRED_VERSION_pn-mender = "2.%"
- For testing the OPTEE part of the project, on the device run:
	$ secureota
	Usage: secureota <cmd>
	signmpprivk  : Sign message using the Manufacturing Protection Private key
	mppubk       : Get the Manufacturing Protection Publick key

More information can be found in AN....
