1. Demo application to generate red/black blobs using CAAM and to encrypt/decrypt data

This document provides a step-by-step procedure on how to generate both red and black
key blobs and to use them to encrypt and decrypt data.
CAAM's blob mechanism provides a method for protecting user-defined data across system power cycles.
It ensures both confidentiality and integrity protection.
More details about blobs and the structure of the demo application can be found in the application
note AN12554[1].

1.1 Download the source code
-----------------------------

- The kernel patch and the source code of the demo application can be downloaded by cloning this
  bitbucket repo, branch master:

  $ git clone ssh://git@bitbucket.sw.nxp.com/imxs/imx_sec_apps.git

- Download the kernel sources via Yocto:

  $ repo init -u git://source.codeaurora.org/external/imx/fsl-arm-yocto-bsp.git -b nxp/imx-thud -m imx-4.19.35-1.0.0.xml
  $ repo sync -j8
  $. ./setup-environment imx8mm
  $ MACHINE=imx8mmevk DISTRO=fsl-imx-xwayland source ./fsl-setup-release.sh -b imx8mmevk
  $ bitbake virtual/kernel -f -c unpack

1.2 Patch the kernel
---------------------

Patch the kernel sources in order to add and enable the kernel support for generating the red/black 
blobs using CAAM and for encrypting/decrypting data using them.

- Apply the patch:

  $ cd tmp/work/imx8mmevk-poky-linux/linux-imx/4.19.35-r0/git
  //copy micro/key_blob/kernel/0001-Added-the-support-for-i.MX8-8X-in-sync-with-Linux-4.patch here
  $ git apply 0001-Added-the-support-for-i.MX8-8X-in-sync-with-Linux-4.patch

- Enable the module into virtual/kernel:

  //add in arch/arm64/configs/defconfig next line
  CONFIG_CRYPTO_DEV_FSL_CAAM_SM_KEY_BLOB=y

- Enable kernel-level keystore API:

  //add in drivers/crypto/caam/Kconfig next lines
  config CRYPTO_DEV_FSL_CAAM_SM_KEY_BLOB
       bool "CAAM Secure Memory Key Blob Generation"
       depends on CRYPTO_DEV_FSL_CAAM_SM
       default n
       help
         Enables use of a prototype kernel-level Keystore API with CAAM
         Secure Memory for key blob generation.

  //set “default 9” in drivers/crypto/caam/Kconfig for config CRYPTO_DEV_FSL_CAAM_SM_SLOTSIZE

  //add in drivers/crypto/caam/Makefile next line
  obj-$(CONFIG_CRYPTO_DEV_FSL_CAAM_SM_KEY_BLOB) += key_blob.o

1.3 Build the kernel
----------------------

Build a bootable image that includes the patched Linux kernel.

- Compile Linux Kernel:

  $ bitbake virtual/kernel -f -c compile

- Build a bootable .sdcard image:

  $ bitbake -f fsl-image-gui
  //or
  $ bitbake -f core-image-minimal

1.4 Build a toolchain
-----------------------

Build a toolchain in order to cross compile the sources of the kb_test application.

- Build a toolchain from the Yocto build directory:

  $ bitbake fsl-image-gui -c populate_sdk
  $ cd tmp/deploy/sdk
  $ ./fsl-imx-xwayland-glibc-x86_64-fsl-image-gui-aarch64-toolchain-4.19-thud.sh
  //choose a install directory. For example /work/fsl-toolchain-4.19-thud

1.5 Cross compile the user space sources
-----------------------------------------

Setup the environment for cross compilation using the toolchain previously prepared.

- From the toolchain install folder set up the environment:

  $ ./environment-setup-aarch64-poky-linux

- Build the kb_test user space application, go to source folder and run:

  $ make
  //or just run
  $ $CC kb_test.c -o kb_test

2. Usage
---------

After the device successfully boots with the the previously generated image, red/black 
blobs can be generated and data can be encrypted/decrypted using them.

2.1 Encapsulating/Decapsulating a key into/from a blob
-------------------------------------------------------

- Create a regular file with the desired key and encapsulate/decapsulate it into/from a red/black blob:

  $ ./kb_test encap <key_color> <key_file> <blob_file> //for encapsulation
  $ ./kb_test decap <key_color> <blob_file> <key_file> //for decapsulation
    <key_color> can be red or black
    <key_file> is a regular file that contains the key to be encapsulated. This file should exist.
    <blob_file> is the name of the file that will hold the blob

2.2 Encrypting/Decrypting a file using a blob
----------------------------------------------

- Create a blob with the desired key and color, as described in the previous section, and
  encrypt/decrypt a file using that blob:

  $ kb_test encr <key_color> <blob_file> <input_file> <encrypted_file>     // for encryption
  $ kb_test decr <key_color> <blob_file> <encrypted_file> <decrypted_file> // for decryption
    <key_color> can be red or black
    <blob_file> is a regular file that contains the blob to be used for encryption/decryption.
    <input_file> is a regular file that contains data to be encrypted_file. This file should exist.
    <encrypted_file> is the name of the file that will contain the encrypted data
    <decrypted_file> is the name of the file that will contain the decrypted data

2.3 (Optional) Adjust a file by padding
---------------------------------
Any key, regardless of size, can be encapsulated into a blob. However, if the blob is to 
be used for encryption/decryption of data, the key's size should be a multiple of 16 bytes. 
This example uses with AES-ECB mode encryption which works with 128, 192 or 256-bit long key size.
AES-ECB is a block cipher mode of operation and it uses 16 bytes for the block size.
Before encapsulating a key into a blob and encrypting a file with it, adjust the key size in order 
to be 128/192/256 bit long and adjust the file size in order to be a multiple of 16 bytes.
Otherwise, the kb_test application will automatically adjust the keyfile size and the size of the file
that contains data to be encrypted.

- Check the file size:
  $ wc -c <data-file>

- Adjust the file by adding padding:
  $ objcopy -I binary -O binary --pad-to 0x500010 --gap-fill=0x5A <data-file> <data-file-with-padding>

3. Use case example
---------------------

Next is exemplified how a file can be encrypted using a black key blob.

- Create a regular file with a desired key:

  $ echo desiredsecretkey > keyfile

- Check the size of the file:

  $ wc -c keyfile
  17 keyfile

- The size of the keyfile is not a multiple of 16. Adjust the file size to 32:

  $ objcopy -I binary -O binary --pad-to 0x20 --gap-fill=0x0 keyfile keyfilewithpad

- Create a file with random content:

  $ dd if=/dev/urandom of=src bs=1 count=1000

- Check the size of the file:

  $ wc -c src
  1000 src

- The size of the src is not a multiple of 16. Adjust the file size to 1008:

  $ objcopy -I binary -O binary --pad-to 0x3f0 --gap-fill=0x0 src srcpad

- Encapsulate the keyfile content into a black key blob:

  $ ./kb_test encap black keyfile blobfile

- Encrypt src using blobfile:

  $ ./kb_test encr black blobfile src srcenc

- Decrypt srcenc using blobfile:

  $ ./kb_test decr black blobfile srcenc srcdec
  $ diff src srcdec

- Decapsulate the blob(the resulting is a black key so it should differ from the initial key):

  $ ./kb_test decap black blobfile blackkey

References:
[1] AN12554: "Demo application to generate red/black blobs using CAAM and to encrypt/decrypt data"
