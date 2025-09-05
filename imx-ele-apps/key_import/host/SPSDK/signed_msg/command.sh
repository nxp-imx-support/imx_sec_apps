#!/bin/bash

# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright 2025 NXP
#

set -e

# For decrypting the private key from CST tool:
openssl ec -in SRK1_sha384_secp384r1_v3_usr_key.pem -out decrypted_ec_key.pem

# For signed msg generation:
nxpimage -v signed-msg export -c signed_msg.yaml
