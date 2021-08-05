# 1. Overview
This document provides a step-by-step procedure on how to decrypt a file (encrypted with AES-CBC) without disclosing the key in the kernel using caam-decrypt application.

# 2. Black keys
Represent keys stored in memory in encrypted form and decrypted on-the-fly when used.

# 3. Blobs
CAAM provides a method to protect data, across system power cycles, in a cryptographic data structure called blob. The data to be protected is encrypted so that it can be safely placed into non-volatile storage. blobs can only be decapsulated by the SoC that created it.
Encapsulation of black key is called black blob. The decapsulation will result in a new black key readable only by the CAAM HW.


# 4. Prerequisites
caam-keygen application is needed to import black key from black blob. Make sure that caam-keygen app is already present at /usr/bin.


# 5. Build the kernel

## 5.1 Kernel configuration
- CONFIG_CRYPTO_USER_API
- CONFIG_CRYPTO_USER_API_HASH
- CONFIG_CRYPTO_USER_API_SKCIPHER
- CONFIG_CRYPTO_USER_API_RNG
- CONFIG_CRYPTO_USER_API_AEAD

Get a bootable image that includes the black key support and AF_ALG socket interface for Linux kernel. Or build the kernel from here: https://source.codeaurora.org/external/imx/linux-imx/. For more details refer to i.MX Linux User's Guide from https://www.nxp.com/


## 5.2 Build a toolchain
Build a toolchain in order to cross compile the sources of the caam-decrypt application. For details refer to i.MX Yocto Project User's Guide from https://www.nxp.com/

```
$ wget https://developer.arm.com/-/media/Files/downloads/gnu-a/8.2-2019.01/gcc-arm-8.2-2019.01-x86_64-aarch64-elf.tar.xz
$ tar xf gcc-arm-8.2-2019.01-x86_64-aarch64-elf.tar.xz
```

## 5.3 Cross compile the user space sources
Setup the environment for cross compilation using the toolchain previously prepared.

- From the toolchain folder set up the environment:

```
  $ export CROSS_COMPILE=<path to toolchain>/bin/aarch64-linux-gnu-
  $ export CC=${CROSS_COMPILE}gcc
  $ export LD=${CROSS_COMPILE}ld
```
- Build the caam-decrypt user space application, go to source folder and run:

```
  $ make clean
  $ make
```

# 6. Usage
After the device successfully boots with the previously generated image, caam-decrypt can be used to decrypt a encrypted data stored in a file.

```
  $ ./caam-decrypt
Application usage: caam-decrypt [options]
Options:
	<blob_name> <enc_algo> <input_file> <output_file>
	<blob_name> the absolute path of the file that contains the black blob
	<enc_algo> can be AES-256-CBC
	<input_file> the absolute path of the file that contains input data
		     initialization vector(iv) of 16 bytes prepended
		     size of input file must be multiple of 16
	<output_file> the absolute path of the file that contains output data
```

# 7. Use case example

```
  $ caam-decrypt myblob AES-256-CBC my_encrypted_file output_decrypted
```

where:

- myblob - generated black key blob. caam-keygen application will import a black key from black blob. this black key will be used by CAAM for decryption.
- AES-256-CBC - currently the only supported symmetric algorithm used for decryption operation. user has to make sure that encrypted data must uses the same algorithm.
- my_encrypted_file - Encrypted data stored in a file. Initialization vector(iv) of 16 bytes used during encryption must be prepended to encrypted data.
```
AES Encrypted file format
	16 Octets - Initialization Vector (IV) is an input to encryption algorithm.
	nn Octets - Encrypted message  (for AES-256-CBC, it must be multiple of 16)
```
- output_decrypted - contain decrypted data after successful decryption operation.
