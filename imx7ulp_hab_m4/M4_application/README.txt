# HAB application demo

## 1. INTRODUCTION
    This application can be used to dump the HAB (High Assurance Boot) events for M4 application. The output of this application will look like the output of the "hab_status" u-boot command.
    In its actual form, the application is capable to run only on iMX7ULP boards, but can be easily addapted to run on other boards.

## 2. BUILD STEPS
    In order to build this application you have to download the SDK for your board. SDKs are available at this link: https://mcuxpresso.nxp.com/en/dashboard.
    
    Unpack the SDK then navigate to this path: <path to SDK directory>/boards/evkmcimx7ulp/demo_apps/hello_world
    
    Set the ARMGCC directory using: export ARMGCC_DIR=/usr/
    
    Copy and replace the content in hello_world.c with the content in hab_M4.c and add hab_M4.h file in <path to SDK directory>/boards/evkmcimx7ulp/demo_apps/hello_world directory.

    Go to: <path to SDK directory>/boards/evkmcimx7ulp/demo_apps/hello_world/armgcc directory and run the "build_all.sh" script. 
    The result of this can be found in the "<path to SDK directory>/boards/evkmcimx7ulp/demo_apps/hello_world/armgcc/debug" folder named as "sdk20-app.bin". 
    
    Copy "sdk20-app.bin" to <path to SDK directory>/tools/imgutil/evkmcimx7ulp/ and run the following command: ./mkimg.sh ram
    This command will create an image named "sdk20-app.img" which can be loaded in QSPI and runned on the M4 core.

## 3. RUN STEPS
    In  order to run this app on the M4 core a FAT partition and an u-boot for A7 core are needed. The FAT partition and u-boot can be easily obtained by writing an yocto build on the sdcard(this will automatically create a FAT partition).
    
    Create and load the yocto build on the sdcard:
        a) Clone the repo containing the u-boot:
            $ mkdir imx7ulp
            $ cd imx7ulp
            $ repo init -u https://source.codeaurora.org/external/imx/imx-manifest -b imx-linux-rocko -m imx-4.9.88-2.0.0_ga.xml
            $ repo sync

        b) Set the distribution, machine and build directory:
            $ DISTRO=fsl-imx-x11 MACHINE=imx7ulpevk source fsl-setup-release.sh -b build
        
        c) Build the image:
            bitbake fsl-image-gui

        d) Flash the uboot on the sdcard:
            sudo dd if=<path to build dir>/build/tmp/deploy/images/imx7ulpevk/fsl-image-gui-imx7ulpevk.sdcard of=/dev/sdX bs=1M ; sync

            NOTE: The .sdcard image might be created in an archive. Extract it before writing it on sdcard.
            NOTE: The X letter is specific to your machine. To find out the letter use the follofing command: sudo fdisk -l

    Copy the M4 image on the FAT partition. In my case the command looks like this:
        cp sdk20-app.img /media/<user/computer name>/Boot\ imx7ulpevk/

    Insert the sdcard into the board and boot up the u-boot. Use the following commands to load the M4 image in the QSPI:
        => sf probe
        => sf erase 0 +0x10000
        => fatload mmc 0:1 0x67800000 sdk20-app.img
        => sf write 0x67800000 0 0x10000
    
    Restart the board.
    
    In the M4 console will be displayed automatically the HAB status. In order to see the HAB status on A7 core use "hab_status" command in the u-boot console.



