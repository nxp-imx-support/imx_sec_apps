Get linux-imx Source Code(tag rel_imx_5.4.70_2.3.0):
https://source.codeaurora.org/external/imx/linux-imx/commit/?h=rel_imx_5.4.70_2.3.0

Arm cross compiler toolchain(any other compatible toolchain can work):
$ wget https://developer.arm.com/-/media/Files/downloads/gnu-a/8.2-2019.01/gcc-arm-8.2-2019.01-x86_64-aarch64-elf.tar.xz
$ tar xf gcc-arm-8.2-2019.01-x86_64-aarch64-elf.tar.xz

Build Linux:
Enable below CONFIG in imx_v8_defconfig.
CONFIG_CRYPTO_USER_API
CONFIG_CRYPTO_USER_API_HASH
CONFIG_CRYPTO_USER_API_SKCIPHER
CONFIG_CRYPTO_USER_API_RNG
CONFIG_CRYPTO_USER_API_AEAD

$ export CROSS_COMPILE=<path to toolchain>/bin/aarch64-linux-gnu-
$ export ARCH=arm64
$ make distclean
$ make imx_v8_defconfig
$ make -j32
$ make modules_install INSTALL_MOD_PATH=<path where to install>

Build Application:
$ export CC=${CROSS_COMPILE}gcc
$ export LD=${CROSS_COMPILE}ld
$ export KERNEL_DIR=<path to linux-imx>/kernel
$ export KERNEL_SRC=<path to linux-imx>/kernel
$ make

Running Application on iMX8MN/MM:
- boot linux on target board.
- copy applicaion on target board
$ caam-decrypt <path to black blob> AES-256-CBC <path to enc file> <path to output file>

Application usage: caam-decrypt [options]
Options:
        <blob_name> <enc_algo> <input_file> <output_file>
        <blob_name> the absolute path of the file that contains the ddek_black_blob
        <enc_algo> can be AES-256-CBC
        <input_file> the absolute path of the file that contains input data
                     initialization vector(iv) of 16 bytes prepended
                     size of input file must be multiple of 16
        <output_file> the absolute path of the file that contains output data
