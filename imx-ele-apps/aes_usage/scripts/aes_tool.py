#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright 2025 NXP
#
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

PRESET_IV = bytes(range(16))

def read_file(path):
    with open(path, 'rb') as f:
        return f.read()

def write_file(path, data):
    with open(path, 'wb') as f:
        f.write(data)

def encrypt(data, key, mode):
    if mode == 'CBC':
        padder = padding.PKCS7(128).padder()
        data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(PRESET_IV), backend=default_backend())
    elif mode == 'CTR':
        cipher = Cipher(algorithms.AES(key), modes.CTR(PRESET_IV), backend=default_backend())
    else:
        raise ValueError(f"Unsupported mode: {mode}")
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def decrypt(data, key, mode):
    if mode == 'CBC':
        cipher = Cipher(algorithms.AES(key), modes.CBC(PRESET_IV), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted) + unpadder.finalize()
    elif mode == 'ECB':
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted) + unpadder.finalize()
    elif mode == 'CTR':
        cipher = Cipher(algorithms.AES(key), modes.CTR(PRESET_IV), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()
    elif mode == 'CFB':
        cipher = Cipher(algorithms.AES(key), modes.CFB(PRESET_IV), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()
    elif mode == 'OFB':
        cipher = Cipher(algorithms.AES(key), modes.OFB(PRESET_IV), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()
    else:
        raise ValueError(f"Unsupported mode: {mode}")

def main():
    parser = argparse.ArgumentParser(description="AES Encrypt/Decrypt Tool")
    parser.add_argument("operation", choices=["encrypt", "decrypt"], help="Operation to perform")
    parser.add_argument("mode", choices=["CBC", "ECB", "CTR", "CFB" , "OFB"], help="AES mode")
    parser.add_argument("input_file", help="Path to input file")
    parser.add_argument("output_file", help="Path to output file")
    parser.add_argument("key_file", help="Path to AES key file (16/24/32 bytes)")

    args = parser.parse_args()

    key = read_file(args.key_file)
    if len(key) not in [16, 24, 32]:
        raise ValueError("AES key must be 16, 24, or 32 bytes long")

    data = read_file(args.input_file)

    if args.operation == "encrypt":
        result = encrypt(data, key, args.mode)
    else:
        result = decrypt(data, key, args.mode)

    write_file(args.output_file, result)
    print(f"{args.operation.capitalize()}ion completed. Output written to {args.output_file}")
    print(f"\n--- Result Preview ({args.operation}) ---")
    try:
        print(result.decode('utf-8'))
    except UnicodeDecodeError:
        print(result.hex())


if __name__ == "__main__":
    main()
