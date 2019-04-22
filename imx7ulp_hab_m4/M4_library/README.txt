# HAB library demo

## 1. INTRODUCTION
    This static library can be used to dump the HAB (High Assurance Boot) events for M4 applications.
    It exposes a function, get_hab_status(), whose output is similar "hab_status" u-boot command.
    In its actual form, the library is capable to run only on iMX7ULP boards, but can be easily 
    addapted to run on other boards.

## 2. BUILD STEPS
    In order to build this application you have to download the SDK for your board.
    SDKs are available at this link: https://mcuxpresso.nxp.com/en/dashboard.
    
    Unpack the SDK then navigate to this path: <path to SDK directory>/boards/evkmcimx7ulp/demo_apps/hello_world
    
    Set the ARMGCC directory using: export ARMGCC_DIR=/usr/
    
    Copy and replace the content in hello_world.c with the content in hab_M4.c and add hab_M4.h file in 
    <path to SDK directory>/boards/evkmcimx7ulp/demo_apps/hello_world directory.

    Copy and replace the CMakeList.txt from <path to SDK directory>/boards/evkmcimx7ulp/demo_apps/hello_world/armgcc
    in order to compile as static library.

    Go to: <path to SDK directory>/boards/evkmcimx7ulp/demo_apps/hello_world/armgcc directory and run the "build_all.sh" script. 
    The result of this can be found in the "<path to SDK directory>/boards/evkmcimx7ulp/demo_apps/hello_world/armgcc/debug"
    folder named as "hab_lib.a". 

## 3. LINK STEPS
    In order to link this library to your M4 application, you have to modify your build mechanism files.
    For example, if CMake is used, you have to append the following in order to link the library:
    
    target_link_libraries(<your_app_name>.elf </path/to/hab_lib>/hab_lib.a)
