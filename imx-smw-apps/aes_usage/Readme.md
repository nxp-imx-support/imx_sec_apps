# 1. Intro

This is demo code for AES usage

# 2. Build

Please follow same build steps in [Key import](../key_import/) : 2. Device/Build

# 3. Usage

## 3.1 On the device side:
```bash
./smw_aes_usage <operation> <mode> <input file> <output file> <key_id>
    <operation>: encrypt, decrypt
    <mode>: ECB, CBC, CTR, CFB
    <input file>: input file name
    <output file>: output file name
    <key_id>: key identifier
```

- Note: 
    1. The key mode must be supported when the key is generated or imported.
    2. In current ELE HSM, cipher and AEAD are not allowed for one key at the same time.
    3. For ECB and CBC mode, PKCS#7 padding is used.
    4. For modes require IV, predefined IV array {0x0...0xF} is used.

## 3.2 On the host side:

scripts/aes_tool.sh can be used on the device for AES encryption and decryption. The usage is same.

```bash
Usage: ./aes_tool.sh <encrypt|decrypt> <CBC|ECB|CTR|CFB|OFB> <input_file> <output_file> <key_file>

AES Encrypt/Decrypt Tool

positional arguments:
  {encrypt,decrypt}     Operation to perform
  {CBC,ECB,CTR,CFB,OFB}
                        AES mode
  input_file            Path to input file
  output_file           Path to output file
  key_file              Path to AES key file (16/24/32 bytes)
```

# 4. Verify the imported AES key

Once the AES key is imported on the device:
1. Encrypt message on the device and decrypt it on the host.

    1.1 Run `./ele_aes_usage encrypt <mode> message.txt cipher.txt <key_id>` on the device.

    1.2 Run `./aes_tool.sh decrypt <mode> cipher.txt plain.txt <aes key>` on the host.

2. Encrypt message on the host and decrypt it on the device.

    1.2 Run `./aes_tool.sh encrypt <mode> message.txt cipher.txt <aes key>` on the host.

    1.1 Run `./ele_aes_usage decrypt <mode> cipher.txt plain.txt <key_id>` on the device.