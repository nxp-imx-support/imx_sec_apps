#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright 2025 NXP
#
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import hashlib

# read pem file
with open("oem_public_key.pem", "rb") as pem_file:
    pem_data = pem_file.read()

public_key = serialization.load_pem_public_key(pem_data, backend=default_backend())

# get the raw public key bytes
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)

raw_key_bytes = public_bytes[1:]

# calculate SHA-256 hash
sha256_hash = hashlib.sha256(raw_key_bytes).hexdigest()

print("SHA-256 of public key:", sha256_hash)
