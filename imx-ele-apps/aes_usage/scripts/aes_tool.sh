#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright 2025 NXP
#

if [ "$#" -ne 5 ]; then
    echo "Usage: $0 <encrypt|decrypt> <CBC|ECB|CTR|CFB|OFB> <input_file> <output_file> <key_file>"
    exit 1
fi

OPERATION=$1
MODE=$2
INPUT_FILE=$3
OUTPUT_FILE=$4
KEY_FILE=$5

if ! command -v openssl &> /dev/null; then
    echo "Error: openssl is not installed."
    exit 1
fi

if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file not found."
    exit 1
fi

if [ ! -f "$KEY_FILE" ]; then
    echo "Error: Key file not found."
    exit 1
fi

IV_HEX="000102030405060708090a0b0c0d0e0f"

KEY_HEX=$(xxd -p "$KEY_FILE" | tr -d '\n')

if [ "$OPERATION" = "encrypt" ]; then
    ENC_FLAG=""
    echo "message preview:"
    cat $INPUT_FILE
elif [ "$OPERATION" = "decrypt" ]; then
    ENC_FLAG="-d"
else
    echo "Error: Operation must be 'encrypt' or 'decrypt'."
    exit 1
fi

KEY_LEN=$(stat -c %s "$KEY_FILE")

if [ "$KEY_LEN" -eq 16 ]; then
    CIPHER="aes-128-$MODE"
elif [ "$KEY_LEN" -eq 24 ]; then
    CIPHER="aes-192-$MODE"
elif [ "$KEY_LEN" -eq 32 ]; then
    CIPHER="aes-256-$MODE"
else
    echo "Error: Invalid key length. Must be 16, 24, or 32 bytes."
    exit 1
fi

openssl enc $ENC_FLAG -$CIPHER -in "$INPUT_FILE" -out "$OUTPUT_FILE" -K "$KEY_HEX" -iv "$IV_HEX"

if [ $? -eq 0 ]; then
    echo "$OPERATION completed successfully. Output written to $OUTPUT_FILE"
    if [ "$OPERATION" = "decrypt" ]; then
        echo "decrypt preview:"
        cat "$OUTPUT_FILE"
    fi
else
    echo "Error during $OPERATION."
    exit 1
fi
