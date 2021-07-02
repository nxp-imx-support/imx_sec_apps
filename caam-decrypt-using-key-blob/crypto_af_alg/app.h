/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 *
 * Author: Gaurav Jain <gaurav.jain@nxp.com>
 *
 */
#ifndef __APP_H
#define __APP_H

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#define CAAM_KEYGEN_APP		"/usr/bin/caam-keygen"
#define CAAM_KEYGEN_IMPORT	"import"
#define KEY_LOCATION		"/data/caam/"
#define KEY_NAME		"black_key"
#define IV_LEN			16

/*
 * aes_cipher:	structure to describe a symmetric cipher input
 * @key:	Pointer to key
 * @klen:	Length of @key in bytes
 * @iv:		Pointer to iv.
 * @ptext:	Pointer to plaintext
 * @ctext:	Pointer to ciphertext
 * @len:	Length of @ptext and @ctext in bytes
 */
struct aes_cipher {
	char *key;
	const char *iv;
	char *ptext;
	char *ctext;
	unsigned int klen;
	unsigned int len;
};
#endif
