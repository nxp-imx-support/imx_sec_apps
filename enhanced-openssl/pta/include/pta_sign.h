/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2019 NXP
 *
 * @file    pta_sign.h
 *
 * @brief    PTA Hash interface identification.
 */

#ifndef __PTA_SIGN_H__
#define __PTA_SIGN_H__


/**
 * @brief   PTA UUID generated at http://www.itu.int/ITU-T/asn1/uuid.html
 * 24e44203-e69e-4505-9d4a-1f50043d19ec
 */
#define PTA_SIGN_UUID { \
	0x24e44203, 0xe69e, 0x4505, \
	{0x9d, 0x4a, 0x1f, 0x50, 0x04, 0x3d, 0x19, 0xec} }

#define PTA_SIGN_RSA_DIGEST 1
#define PTA_SIGN_ECC_DIGEST 2

typedef struct{
	uint8_t *modulus;
	uint8_t *pub_exp;
	uint8_t *priv_exp;
	uint32_t mod_size;
	uint32_t pub_size;
	uint32_t priv_size;
} SK_RSA_KEY;

typedef struct {
	uint8_t *priv_val;
	uint8_t *pub_x;
	uint8_t *pub_y;
	uint32_t curve;
	uint32_t priv_size;
	uint32_t x_size;
	uint32_t y_size;
} SK_ECC_KEY;

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

#define SUPPORTED_EC_CURVES	2
/* EC Curve in DER encoding */


#endif


