#!/bin/bash

# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright 2025 NXP
#

set -e
CST_PATH="/path/to/cst"  # Update this to your CST path

$CST_PATH/linux64/bin/$CST -i signed_msg_key_exchange.csf -o signed_msg.bin