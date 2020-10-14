### Introduction
The OPTEE OS patch is based on top of [OPTEE OS branch  4.14.98_2.0.0](https://source.codeaurora.org/external/imx/imx-optee-os/log/?h=imx_4.14.98_2.2.0).

The patch contains following security enchacements:
- CAAM Black Key PTA
- CAAM Blob PTA
- OCOTP PTA
- SOC INFO PTA

### Installation
The OPTEE OS patch can be used in two ways:
1. Add the yocto layer and compile yocto BSP
2. Build OPTEE OS and flash.bin separately

### Fetch OPTEE OS patch
- Clone OPTEE OS patch from codeaurora.
```
git clone https://source.codeaurora.org/external/imxsupport/imx_sec_apps
```

### Build Yocto BSP with OPTEE OS patch
***1. Create a local branch for the demo:***
```
$ cd <yocto-dir>
$ repo start nxp-security-enhancements --all
```

***2. Copy OPTEE OS patch to Yocto build:***
```
$ cp -r imx_optee_os_security_enhancements/meta-nxp-security-enhancements <yocto-dir>/sources/
```

***3. Add meta-nxp-security-enhancements layer:***
```
$ cd <yocto-dir>/<build-dir>
$ bitbake-layers add-layer ../sources/meta-nxp-security-enhancements
```

***4. Build the Yocto BSP images (for ex:)***
```
$ bitbake core-image-minimal
```

### Build OPTEE OS and flash.bin separately in Yocto
***1. Apply OPTEE OS patch to OPTEE OS source:***
```
$ cd <yocto-dir>/<build-dir>/tmp/work/imx8mmevk-poky-linux/optee-os-imx/git-r0/git/
$ git apply imx_optee_os_security_enhancements/meta-nxp-security-enhancements/recipes-security/optee-imx/files/0001-imx-optee-os-4.14.98_2.0.0-security-enhancements.patch
```

***2. Enable CFG_IMXCRYPT in OPTEE OS configuration:***
Append CFG_IMXCRYPT=y to oe_runmake in optee-os bb file.
```
$ vim <yocto-dir>/sources/meta-fsl-bsp-release/imx/meta-bsp/recipes-security/optee-imx/optee-os-imx_git.bb
```
```diff
- oe_runmake -C ${S} all CFG_TEE_TA_LOG_LEVEL=0
+ oe_runmake -C ${S} all CFG_TEE_TA_LOG_LEVEL=0 CFG_IMXCRYPT=y
```

***3. Build OPTEE OS in Yocto build:***
```
$ cd <yocto-dir>/<build-dir>
$ bitbake -f -c compile optee-os-imx
$ bitbake optee-os-imx
```

***4. Build flash_evk.bin in Yocto build:***
```
$ cd <yocto-dir>/<build-dir>
$ bitbake -f -c compile imx-boot
$ bitbake imx-boot
```

***The final flash_evk.bin image will be available in ```<yocto-dir>/<build-dir>/tmp/deploy/images/imx8mmevk/``` directory to flash in the sdcard.***

