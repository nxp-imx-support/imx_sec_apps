/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2019 NXP
 *
 * @file    pta_decrypt.h
 *
 * @brief   PTA Decrypt interface identification.
 */
#ifndef __PTA_DECRYPT_H__
#define __PTA_DECRYPT_H__

/**
 * @brief   PTA UUID generated at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define PTA_DECRYPT_UUID { \
	0xcf92e9b6, 0xd550, 0x11e9, \
	{0xbb, 0x65, 0x2a, 0x2a, 0xe2, 0xdb, 0xcc, 0xe4} }
/**
 * @brief   PTA Command IDs
 */
#define PTA_DECRYPT_RSA_NOPAD 1
#define PTA_DECRYPT_RSAES 2
#define DECRYPT_PTA_NAME "decrypt.pta"

typedef struct{
	uint8_t *modulus;
	uint8_t *pub_exp;
	uint8_t *priv_exp;
	uint32_t mod_size;
	uint32_t pub_size;
	uint32_t priv_size;
} SK_RSA_KEY;

/*
 * A type for all the defines.
 */
typedef uint32_t SK_TYPE;

/*
 * An Attribute Type.
 */
typedef SK_TYPE SK_ATTRIBUTE_TYPE;

#define SK_ATTR_OBJECT_TYPE		0 /* The object type (Mandatory in Create) */
#define SK_ATTR_OBJECT_INDEX		1 /* The object index (Mandatory in Create) */
#define SK_ATTR_OBJECT_LABEL		2 /* The object label (Mandatory in Create) */
#define SK_ATTR_OBJECT_VALUE		3 /*  Value of Object */
#define SK_ATTR_KEY_TYPE		5 /* Key Type RSA/EC (Mandatory with key type objects) */

/* Attributes For RSA Key Pair */
#define SK_ATTR_MODULUS_BITS		30 /* Length in bits of modulus n */
#define SK_ATTR_MODULUS			31 /* Big integer Modulus n */
#define SK_ATTR_PUBLIC_EXPONENT		32 /* Big integer Public exponent e */

#define SK_ATTR_PRIVATE_EXPONENT	33 /* Big integer Private exponent e */
#define SK_ATTR_PRIME_1			34 /* Big Integer Prime p */
#define SK_ATTR_PRIME_2			35 /* Big Integer Prime q */
#define SK_ATTR_EXPONENT_1		36 /* Big integer Private exponent d modulo p-1 */
#define SK_ATTR_EXPONENT_2		37 /* Big integer Private exponent d modulo q-1 */
#define SK_ATTR_COEFFICIENT		38 /* Big integer CRT coefficient q-1 mod p */

/* Attributes For ECC Key Pair */
#define SK_ATTR_PARAMS			50 /* DER encoding of namedcurve */
#define SK_ATTR_POINT			51 /* Public point in octet uncompressed format */
#define SK_ATTR_PRIV_VALUE		52 /* Private Value */

/*
 * Stores all the information required for an object's attribute - its type, value and value length.
 */
typedef struct SK_ATTRIBUTE{
	SK_ATTRIBUTE_TYPE	type;		/* The attribute's type */
	void			*value;		/* The attribute's value */
	uint16_t		valueLen;	/* The length in bytes of \p value. */
} SK_ATTRIBUTE;

#endif