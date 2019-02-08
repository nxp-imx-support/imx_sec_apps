/*
 * Copyright 2008-2013 Freescale Semiconductor, Inc.
 *
 * SPDX-License-Identifier: BSD-3-Clause or GPL-2.0+
 */

#ifndef __DESC_TLS_H__
#define __DESC_TLS_H__

#include "flib/rta.h"
#include "common.h"

/**
 * DOC: SSL/TLS/DTLS Shared Descriptor Constructors
 *
 * Shared descriptors for SSL / TLS and DTLS protocols.
 */

/*
 * TLS family encapsulation/decapsulation PDB definitions.
 */
#define DTLS_PDBOPTS_ARS_MASK	0xC0
#define DTLS_PDBOPTS_ARS32	0x40	/* 32-entry DTLS anti-replay window */
#define DTLS_PDBOPTS_ARS128	0x80	/* 128-entry DTLS anti-replay window */
#define DTLS_PDBOPTS_ARS64	0xc0	/* 64-entry DTLS anti-replay window */
#define DTLS_PDBOPTS_ARSNONE	0x00	/* DTLS anti-replay window disabled */

/**
 * TLS_PDBOPTS_OUTFMT_MASK - output frame format mask (decapsulation only)
 */
#define TLS_PDBOPTS_OUTFMT_MASK	0x0C

/**
 * TLS_PDBOPTS_OUTFMT_FULL - Full copy of unencrypted fields from input frame
 *                           to output frame.
 */
#define TLS_PDBOPTS_OUTFMT_FULL	0x08
/**
 * TLS_PDBOPTS_OUTFMT_RHP - record header + payload; valid for SEC ERA >= 5
 */
#define TLS_PDBOPTS_OUTFMT_RHP	0x04

#define TLS_PDBOPTS_IV_WRTBK	0x02	/* TLS1.1/TLS1.2/DTLS only */
#define TLS_PDBOPTS_EXP_RND_IV	0x01	/* TLS1.1/TLS1.2/DTLS only */
#define TLS_PDBOPTS_TR_ICV	0x10	/* Available starting with SEC ERA 5 */
#define TLS_PDBOPTS_TR_ICV_LEN_SHIFT	24
#define TLS_PDBOPTS_TR_ICV_LEN_MASK	(0xff << TLS_PDBOPTS_TR_ICV_LEN_SHIFT)

/**
 * TLS_DPOVRD_USE - DPOVRD will override values specified in the PDB
 */
#define TLS_DPOVRD_USE		BIT(31)

/**
 * DTLS_DPOVRD_METADATA_LEN_SHIFT - Metadata length
 */
#define DTLS_DPOVRD_METADATA_LEN_SHIFT	16

/**
 * DTLS_DPOVRD_METADATA_LEN_MASK - See DTLS_DPOVRD_METADATA_LEN_SHIFT
 */
#define DTLS_DPOVRD_METADATA_LEN_MASK	(0xff << DTLS_DPOVRD_METADATA_LEN_SHIFT)

/**
 * TLS_DPOVRD_TYPE_MASK - Mask for TLS / DTLS type
 *                        Valid only for encapsulation.
 */
#define TLS_DPOVRD_TYPE_MASK	0xff

/**
 * struct tls_block_enc - SSL3.0/TLS1.0/TLS1.1/TLS1.2 block encapsulation PDB
 *                        part.
 * @type: protocol content type
 * @version: protocol version
 * @options: PDB options
 * @seq_num: protocol sequence number; big endian format
 */
#pragma pack(push, 1)
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct tls_block_enc {
	union {
		uint32_t word1;
		struct {
			uint8_t type;
			uint8_t version[2];
			uint8_t options;
		};
	};
	uint64_t seq_num;
};
#else
struct tls_block_enc {
	union {
		uint32_t word1;
		struct {
			uint8_t options;
			uint8_t version[2];
			uint8_t type;
		};
	};
	uint64_t seq_num;
};
#endif
#pragma pack(pop)

/**
 * struct dtls_block_enc - DTLS1.0/DTLS1.2 block encapsulation PDB part
 * @type: protocol content type
 * @version: protocol version
 * @options: PDB options
 * @epoch: protocol epoch
 * @seq_num_hi: protocol sequence number (upper 16 bits)
 * @seq_num_lo: protocol sequence number (lower 32 bits)
 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct dtls_block_enc {
	union {
		struct {
			uint8_t type;
			uint8_t version[2];
			uint8_t options;
		};
		uint32_t word1;
	};
	union {
		struct {
			uint16_t epoch;
			uint16_t seq_num_hi;
		};
		uint32_t word2;
	};
	uint32_t seq_num_lo;
};
#else
struct dtls_block_enc {
	union {
		struct {
			uint8_t options;
			uint8_t version[2];
			uint8_t type;
		};
		uint32_t word1;
	};
	union {
		struct {
			uint16_t seq_num_hi;
			uint16_t epoch;
		};
		uint32_t word2;
	};
	uint32_t seq_num_lo;
};
#endif

/**
 * struct tls_block_dec - SSL3.0/TLS1.0/TLS1.1/TLS1.2 block decapsulation PDB
 *                        part.
 * @rsvd: reserved, do not use
 * @options: PDB options
 * @seq_num: protocol sequence number; big endian format
 */
#pragma pack(push, 1)
struct tls_block_dec {
	union {
		struct {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			uint8_t rsvd[3];
			uint8_t options;
#else
			uint8_t options;
			uint8_t rsvd[3];
#endif
		};
		uint32_t word1;
	};
	uint64_t seq_num;
};
#pragma pack(pop)

/**
 * struct dtls_block_dec - DTLS1.0/DTLS1.2 block decapsulation PDB part
 * @rsvd: reserved, do not use
 * @options: PDB options
 * @epoch: protocol epoch
 * @seq_num_hi: protocol sequence number (upper 16 bits)
 * @seq_num_lo: protocol sequence number (lower 32 bits)
 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct dtls_block_dec {
	union {
		struct {
			uint8_t rsvd[3];
			uint8_t options;
		};
		uint32_t word1;
	};
	union {
		struct {
			uint16_t epoch;
			uint16_t seq_num_hi;
		};
		uint32_t word2;
	};
	uint32_t seq_num_lo;
};
#else
struct dtls_block_dec {
	union {
		struct {
			uint8_t options;
			uint8_t rsvd[3];
		};
		uint32_t word1;
	};
	union {
		struct {
			uint16_t seq_num_hi;
			uint16_t epoch;
		};
		uint32_t word2;
	};
	uint32_t seq_num_lo;
};
#endif

/**
 * struct tls_block_pdb - SSL3.0/TLS1.0/TLS1.1/TLS1.2/DTLS1.0/DTLS1.2 block
 *                        encapsulation / decapsulation PDB.
 * @iv: initialization vector; for CBC-mode cipher suites, the IV field is only
 *      8 bytes if the PROTINFO field of the Operation Command selects DES/3DES.
 * @anti_replay: Anti-replay window - valid only for DTLS decapsulation; size
 *               depends on DTLS_PDBOPTS_ARS32/64/128 option flags; big endian
 *               format
 * @icv_len: ICV length; valid only if TLS_PDBOPTS_TR_ICV option flag is set
 */
struct tls_block_pdb {
	union {
		struct tls_block_enc tls_enc;
		struct dtls_block_enc dtls_enc;
		struct tls_block_dec tls_dec;
		struct dtls_block_dec dtls_dec;
	};
	uint8_t iv[16];
	uint32_t anti_replay[4];
	uint8_t icv_len;
};

/**
 * struct tls_stream_enc - SSL3.0/TLS1.0/TLS1.1/TLS1.2 stream encapsulation PDB
 *                         part.
 * @type: protocol content type
 * @version: protocol version
 * @options: PDB options
 */
struct tls_stream_enc {
	union {
		struct {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			uint8_t type;
			uint8_t version[2];
			uint8_t options;
#else
			uint8_t options;
			uint8_t version[2];
			uint8_t type;
#endif
		};
		uint32_t word1;
	};
};

/**
 * struct tls_stream_dec - SSL3.0/TLS1.0/TLS1.1/TLS1.2 stream decapsulation PDB
 *                         part.
 * @rsvd: reserved, do not use
 * @options: PDB options
 */
struct tls_stream_dec {
	union {
		struct {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			uint8_t rsvd[3];
			uint8_t options;
#else
			uint8_t options;
			uint8_t rsvd[3];
#endif
		};
		uint32_t word1;
	};
};

/**
 * struct tls_stream_pdb - SSL3.0/TLS1.0/TLS1.1/TLS1.2 stream
 *                         encapsulation / decapsulation PDB.
 * @seq_num: protocol sequence number
 * @icv_len: ICV length; valid only if TLS_PDBOPTS_TR_ICV option flag is set
 */
#pragma pack(push, 1)
struct tls_stream_pdb {
	union {
		struct tls_stream_enc enc;
		struct tls_stream_dec dec;
	};
	uint64_t seq_num;
	uint8_t icv_len;
};
#pragma pack(pop)

/**
 * struct tls_ctr_enc - TLS1.1/TLS1.2 AES CTR encapsulation PDB part
 * @type: protocol content type
 * @version: protocol version
 * @options: PDB options
 * @seq_num: protocol sequence number; big endian format
 */
#pragma pack(push, 1)
struct tls_ctr_enc {
	union {
		struct {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			uint8_t type;
			uint8_t version[2];
			uint8_t options;
#else
			uint8_t options;
			uint8_t version[2];
			uint8_t type;
#endif
		};
		uint32_t word1;
	};
	uint64_t seq_num;
};
#pragma pack(pop)

/**
 * struct tls_ctr - PDB part for TLS1.1/TLS1.2 AES CTR decapsulation and
 *                  DTLS1.0/DTLS1.2 AES CTR encapsulation/decapsulation.
 * @rsvd: reserved, do not use
 * @options: PDB options
 * @epoch: protocol epoch
 * @seq_num_hi: protocol sequence number (upper 16 bits)
 * @seq_num_lo: protocol sequence number (lower 32 bits)
 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct tls_ctr {
	union {
		struct {
			uint8_t rsvd[3];
			uint8_t options;
		};
		uint32_t word1;
	};
	union {
		struct {
			uint16_t epoch;
			uint16_t seq_num_hi;
		};
		uint32_t word2;
	};
	uint32_t seq_num_lo;
};
#else
struct tls_ctr {
	union {
		struct {
			uint8_t options;
			uint8_t rsvd[3];
		};
		uint32_t word1;
	};
	union {
		struct {
			uint16_t seq_num_hi;
			uint16_t epoch;
		};
		uint32_t word2;
	};
	uint32_t seq_num_lo;
};
#endif

/**
 * struct tls_ctr_pdb - TLS1.1/TLS1.2/DTLS1.0/DTLS1.2 AES CTR
 *                      encapsulation / decapsulation PDB.
 * @write_iv: server write IV / client write IV
 * @constant: constant equal to 0x0000
 * @anti_replay: Anti-replay window - valid only for DTLS decapsulation; size
 *               depends on DTLS_PDBOPTS_ARS32/64/128 option flags; big endian
 *               format
 * @icv_len: ICV length; valid only if TLS_PDBOPTS_TR_ICV option flag is set
 *
 * TLS1.1/TLS1.2/DTLS1.0/DTLS1.2 AES CTR encryption processing is supported
 * starting with SEC ERA 5.
 */
struct tls_ctr_pdb {
	union {
		struct tls_ctr_enc tls_enc;
		struct tls_ctr ctr;
	};
	uint32_t write_iv_hi;
	union {
		struct {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			uint16_t write_iv_lo;
			uint16_t constant;
#else
			uint16_t constant;
			uint16_t write_iv_lo;
#endif
		};
		uint32_t word1;
	};
	uint32_t anti_replay[4];
	uint8_t icv_len;
};

/**
 * struct tls12_gcm_encap - TLS1.2 AES GCM encapsulation PDB part
 * @type: protocol content type
 * @version: protocol version
 * @options: PDB options
 * @seq_num: protocol sequence number; big endian format
 */
#pragma pack(push, 1)
struct tls12_gcm_encap {
	union {
		struct {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			uint8_t type;
			uint8_t version[2];
			uint8_t options;
#else
			uint8_t options;
			uint8_t version[2];
			uint8_t type;
#endif
		};
		uint32_t word1;
	};
	uint64_t seq_num;
};
#pragma pack(pop)

/**
 * struct tls12_gcm_decap - TLS1.2 AES GCM decapsulation PDB part
 * @rsvd: reserved, do not use
 * @options: PDB options
 * @seq_num: protocol sequence number; big endian format
 */
#pragma pack(push, 1)
struct tls12_gcm_decap {
	union {
		struct {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			uint8_t rsvd[3];
			uint8_t options;
#else
			uint8_t options;
			uint8_t rsvd[3];
#endif
		};
		uint32_t word1;
	};
	uint64_t seq_num;
};
#pragma pack(pop)

/**
 * struct dtls_gcm_enc - DTLS1.2 AES GCM encapsulation PDB part
 * @type: protocol content type
 * @version: protocol version
 * @options: PDB options
 * @epoch: protocol epoch
 * @seq_num_hi: protocol sequence number (upper 16 bits)
 * @seq_num_lo: protocol sequence number (lower 32 bits)
 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct dtls_gcm_enc {
	union {
		struct {
			uint8_t type;
			uint8_t version[2];
			uint8_t options;
		};
		uint32_t word1;
	};
	union {
		struct {
			uint16_t epoch;
			uint16_t seq_num_hi;
		};
		uint32_t word2;
	};
	uint32_t seq_num_lo;
};
#else
struct dtls_gcm_enc {
	union {
		struct {
			uint8_t options;
			uint8_t version[2];
			uint8_t type;
		};
		uint32_t word1;
	};
	union {
		struct {
			uint16_t seq_num_hi;
			uint16_t epoch;
		};
		uint32_t word2;
	};
	uint32_t seq_num_lo;
};
#endif

/**
 * struct dtls_gcm_dec - DTLS1.2 AES GCM decapsulation PDB part
 * @rsvd: reserved, do not use
 * @options: PDB options
 * @epoch: protocol epoch
 * @seq_num_hi: protocol sequence number (upper 16 bits)
 * @seq_num_lo: protocol sequence number (lower 32 bits)
 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct dtls_gcm_dec {
	union {
		struct {
			uint8_t rsvd[3];
			uint8_t options;
		};
		uint32_t word1;
	};
	union {
		struct {
			uint16_t epoch;
			uint16_t seq_num_hi;
		};
		uint32_t word2;
	};
	uint32_t seq_num_lo;
};
#else
struct dtls_gcm_dec {
	union {
		struct {
			uint8_t options;
			uint8_t rsvd[3];
		};
		uint32_t word1;
	};
	union {
		struct {
			uint16_t seq_num_hi;
			uint16_t epoch;
		};
		uint32_t word2;
	};
	uint32_t seq_num_lo;
};
#endif

/**
 * struct tls_gcm_pdb - TLS1.2/DTLS1.2 AES GCM encapsulation / decapsulation PDB
 * @salt: 4-byte array salt
 * @anti_replay: Anti-replay window - valid only for DTLS decapsulation; size
 *               depends on DTLS_PDBOPTS_ARS32/64/128 option flags; big endian
 *               format
 * @icv_len: ICV length; valid only if TLS_PDBOPTS_TR_ICV option flag is set
 */
struct tls_gcm_pdb {
	union {
		struct tls12_gcm_encap tls12_enc;
		struct tls12_gcm_decap tls12_dec;
		struct dtls_gcm_enc dtls_enc;
		struct dtls_gcm_dec dtls_dec;
	};
	uint8_t salt[4];
	uint32_t anti_replay[4];
	uint8_t icv_len;
};

/**
 * struct tls12_ccm_encap - TLS1.2 AES CCM encapsulation PDB part
 * @type: protocol content type
 * @version: protocol version
 * @options: PDB options
 * @seq_num: protocol sequence number; big endian format
 */
#pragma pack(push, 1)
struct tls12_ccm_encap {
	union {
		struct {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			uint8_t type;
			uint8_t version[2];
			uint8_t options;
#else
			uint8_t options;
			uint8_t version[2];
			uint8_t type;
#endif
		};
		uint32_t word1;
	};
	uint64_t seq_num;
};
#pragma pack(pop)

/**
 * struct tls_ccm - PDB part for TLS12 AES CCM decapsulation PDB and
 *                  DTLS1.2 AES CCM encapsulation / decapsulation.
 * @rsvd: reserved, do not use
 * @options: PDB options
 * @epoch: protocol epoch
 * @seq_num_hi: protocol sequence number (upper 16 bits)
 * @seq_num_lo: protocol sequence number (lower 32 bits)
 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct tls_ccm {
	union {
		struct {
			uint8_t rsvd[3];
			uint8_t options;
		};
		uint32_t word1;
	};
	union {
		struct {
			uint16_t epoch;
			uint16_t seq_num_hi;
		};
		uint32_t word2;
	};
	uint32_t seq_num_lo;
};
#else
struct tls_ccm {
	union {
		struct {
			uint8_t options;
			uint8_t rsvd[3];
		};
		uint32_t word1;
	};
	union {
		struct {
			uint16_t seq_num_hi;
			uint16_t epoch;
		};
		uint32_t word2;
	};
	uint32_t seq_num_lo;
};
#endif

/**
 * struct tls_ccm_pdb - TLS1.2/DTLS1.2 AES CCM encapsulation / decapsulation PDB
 * @write_iv: server write IV / client write IV
 * @b0_flags: use 0x5A for 8-byte ICV, 0x7A for 16-byte ICV
 * @ctr0_flags: equal to 0x2
 * @rsvd: reserved, do not use
 * @ctr0: CR0 lower 3 bytes, set to 0
 * @anti_replay: Anti-replay window - valid only for DTLS decapsulation; size
 *               depends on DTLS_PDBOPTS_ARS32/64/128 option flags; big endian
 *               format
 * @icv_len: ICV length; valid only if TLS_PDBOPTS_TR_ICV option flag is set
 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
struct tls_ccm_pdb {
	union {
		struct tls12_ccm_encap tls12;
		struct tls_ccm ccm;
	};
	uint32_t write_iv;
	union {
		struct {
			uint8_t b0_flags;
			uint8_t ctr0_flags;
			uint8_t rsvd1[2];
		};
		uint32_t word1;
	};
	union {
		struct {
			uint8_t rsvd2;
			uint8_t ctr0[3];
		};
		uint32_t word2;
	};
	uint32_t anti_replay[4];
	uint8_t icv_len;
};
#else
struct tls_ccm_pdb {
	union {
		struct tls12_ccm_encap tls12;
		struct tls_ccm ccm;
	};
	uint32_t write_iv;
	union {
		struct {
			uint8_t rsvd1[2];
			uint8_t ctr0_flags;
			uint8_t b0_flags;
		};
		uint32_t word1;
	};
	union {
		struct {
			uint8_t ctr0[3];
			uint8_t rsvd2;
		};
		uint32_t word2;
	};
	uint32_t anti_replay[4];
	uint8_t icv_len;
};
#endif

/**
 * enum tls_cipher_mode - (D)TLS cipher mode
 */
enum tls_cipher_mode {
	RTA_TLS_CIPHER_INVALID = 0,
	RTA_TLS_CIPHER_CBC,
	RTA_TLS_CIPHER_GCM,
	RTA_TLS_CIPHER_CCM,
	RTA_TLS_CIPHER_CTR,
	RTA_TLS_CIPHER_STREAM
};

/**
 * rta_dtls_pdb_ars - Get DTLS anti-replay scorecard size
 * @options: 1st word in the DTLS PDB
 *
 * Return: Anti-replay scorecard (ARS) size in units of 32bit entries
 */
static inline uint8_t rta_dtls_pdb_ars(uint32_t options)
{
	switch (options & DTLS_PDBOPTS_ARS_MASK) {
	case DTLS_PDBOPTS_ARS32:
	case DTLS_PDBOPTS_ARS64:
		return 2;

	case DTLS_PDBOPTS_ARS128:
		return 4;

	default:
		pr_err("Invalid AntiReplay Window size in options: 0x%08x\n",
		       options);
	case DTLS_PDBOPTS_ARSNONE:
		return 0;
	}
}
static inline void __rta_copy_tls_block_pdb(struct program *p, void *pdb,
					    uint32_t protid)
{
	struct tls_block_pdb *block_pdb = (struct tls_block_pdb *)pdb;
	bool encap = ((protid & OP_TYPE_MASK) == OP_TYPE_ENCAP_PROTOCOL);
	uint8_t ars = 0;
	int i = 0;

	switch (protid & OP_PCLID_MASK) {
	case OP_PCLID_SSL30:
	case OP_PCLID_TLS10:
	case OP_PCLID_TLS11:
	case OP_PCLID_TLS12:
		__rta_out32(p, block_pdb->tls_enc.word1);
		__rta_out_be64(p, true, block_pdb->tls_enc.seq_num);
		break;

	case OP_PCLID_DTLS:
		__rta_out32(p, block_pdb->dtls_enc.word1);
		__rta_out32(p, block_pdb->dtls_enc.word2);
		__rta_out32(p, block_pdb->dtls_enc.seq_num_lo);

		if (!encap)
			ars = rta_dtls_pdb_ars(block_pdb->dtls_dec.options);
		break;

	default:
		pr_err("Invalid protid 0x0%8x\n", protid);
		break;
	}

	rta_copy_data(p, (uint8_t *)block_pdb->iv, sizeof(block_pdb->iv));

	/* Copy 0, 1, 2 or 4 words of anti-replay scorecard */
	for (i = 0; i < ars; i++)
		__rta_out_be32(p, block_pdb->anti_replay[i]);

	/* If ICV is truncated, then another word is needed */
	if (block_pdb->tls_enc.options & TLS_PDBOPTS_TR_ICV)
		__rta_out32(p, (uint32_t)(block_pdb->icv_len <<
					  TLS_PDBOPTS_TR_ICV_LEN_SHIFT));
}

static inline void __rta_copy_tls_stream_pdb(struct program *p, void *pdb,
					     uint32_t protid)
{
	struct tls_stream_pdb *stream_pdb = (struct tls_stream_pdb *)pdb;

	switch (protid & OP_PCLID_MASK) {
	case OP_PCLID_SSL30:
	case OP_PCLID_TLS10:
	case OP_PCLID_TLS11:
	case OP_PCLID_TLS12:
		__rta_out32(p, stream_pdb->enc.word1);
		break;

	default:
		pr_err("Invalid protid 0x0%8x\n", protid);
		break;
	}

	__rta_out_be64(p, true, stream_pdb->seq_num);

	/* If ICV is truncated, then another word is needed */
	if (stream_pdb->enc.options & TLS_PDBOPTS_TR_ICV)
		__rta_out32(p, (uint32_t)(stream_pdb->icv_len <<
					  TLS_PDBOPTS_TR_ICV_LEN_SHIFT));
}

static inline void __rta_copy_tls_ctr_pdb(struct program *p, void *pdb,
					  uint32_t protid)
{
	struct tls_ctr_pdb *ctr_pdb = (struct tls_ctr_pdb *)pdb;
	bool encap = ((protid & OP_TYPE_MASK) == OP_TYPE_ENCAP_PROTOCOL);
	uint8_t ars = 0;
	int i = 0;

	switch (protid & OP_PCLID_MASK) {
	case OP_PCLID_TLS11:
	case OP_PCLID_TLS12:
		if (encap) {
			__rta_out32(p, ctr_pdb->tls_enc.word1);
			__rta_out_be64(p, true, ctr_pdb->tls_enc.seq_num);
		} else {
			__rta_out32(p, ctr_pdb->ctr.word1);
			__rta_out32(p, ctr_pdb->ctr.word2);
			__rta_out32(p, ctr_pdb->ctr.seq_num_lo);
		}

		break;

	case OP_PCLID_DTLS:
		__rta_out32(p, ctr_pdb->ctr.word1);
		__rta_out32(p, ctr_pdb->ctr.word2);
		__rta_out32(p, ctr_pdb->ctr.seq_num_lo);

		if (!encap)
			ars = rta_dtls_pdb_ars(ctr_pdb->ctr.options);
		break;

	default:
		pr_err("Invalid protid 0x0%8x\n", protid);
		break;
	}

	__rta_out32(p, ctr_pdb->word1);

	/* Copy 0, 1, 2 or 4 words of anti-replay scorecard */
	for (i = 0; i < ars; i++)
		__rta_out_be32(p, ctr_pdb->anti_replay[i]);

	/* If ICV is truncated, then another word is needed */
	if (ctr_pdb->ctr.options & TLS_PDBOPTS_TR_ICV)
		__rta_out32(p, (uint32_t)(ctr_pdb->icv_len <<
					  TLS_PDBOPTS_TR_ICV_LEN_SHIFT));
}

static inline void __rta_copy_tls_gcm_pdb(struct program *p, void *pdb,
					  uint32_t protid)
{
	struct tls_gcm_pdb *gcm_pdb = (struct tls_gcm_pdb *)pdb;
	bool encap = ((protid & OP_TYPE_MASK) == OP_TYPE_ENCAP_PROTOCOL);
	uint8_t ars = 0;
	int i = 0;

	switch (protid & OP_PCLID_MASK) {
	case OP_PCLID_TLS12:
		__rta_out32(p, gcm_pdb->tls12_enc.word1);
		__rta_out_be64(p, true, gcm_pdb->tls12_enc.seq_num);
		break;

	case OP_PCLID_DTLS:
		__rta_out32(p, gcm_pdb->dtls_enc.word1);
		__rta_out32(p, gcm_pdb->dtls_enc.word2);
		__rta_out32(p, gcm_pdb->dtls_enc.seq_num_lo);

		if (!encap)
			ars = rta_dtls_pdb_ars(gcm_pdb->dtls_enc.options);
		break;

	default:
		pr_err("Invalid protid 0x0%8x\n", protid);
		break;
	}

	rta_copy_data(p, gcm_pdb->salt, sizeof(gcm_pdb->salt));

	/* Copy 0, 1, 2 or 4 words of anti-replay scorecard */
	for (i = 0; i < ars; i++)
		__rta_out_be32(p, gcm_pdb->anti_replay[i]);

	/* If ICV is truncated, then another word is needed */
	if (gcm_pdb->tls12_enc.options & TLS_PDBOPTS_TR_ICV)
		__rta_out32(p, (uint32_t)(gcm_pdb->icv_len <<
					  TLS_PDBOPTS_TR_ICV_LEN_SHIFT));
}

static inline void __rta_copy_tls_ccm_pdb(struct program *p, void *pdb,
					  uint32_t protid)
{
	struct tls_ccm_pdb *ccm_pdb = (struct tls_ccm_pdb *)pdb;
	bool encap = ((protid & OP_TYPE_MASK) == OP_TYPE_ENCAP_PROTOCOL);
	uint8_t ars = 0;
	int i = 0;

	switch (protid & OP_PCLID_MASK) {
	case OP_PCLID_TLS12:
		if (encap) {
			__rta_out32(p, ccm_pdb->tls12.word1);
			__rta_out_be64(p, true, ccm_pdb->tls12.seq_num);
		} else {
			__rta_out32(p, ccm_pdb->ccm.word1);
			__rta_out32(p, ccm_pdb->ccm.word2);
			__rta_out32(p, ccm_pdb->ccm.seq_num_lo);
		}
		break;

	case OP_PCLID_DTLS:
		__rta_out32(p, ccm_pdb->ccm.word1);
		__rta_out32(p, ccm_pdb->ccm.word2);
		__rta_out32(p, ccm_pdb->ccm.seq_num_lo);

		if (!encap)
			ars = rta_dtls_pdb_ars(ccm_pdb->ccm.options);
		break;

	default:
		pr_err("Invalid protid 0x0%8x\n", protid);
		break;
	}

	__rta_out32(p, ccm_pdb->write_iv);
	__rta_out32(p, ccm_pdb->word1);
	__rta_out32(p, ccm_pdb->word2);

	/* Copy 0, 1, 2 or 4 words of anti-replay scorecard */
	for (i = 0; i < ars; i++)
		__rta_out_be32(p, ccm_pdb->anti_replay[i]);

	/* If ICV is truncated, then another word is needed */
	if (ccm_pdb->ccm.options & TLS_PDBOPTS_TR_ICV)
		__rta_out32(p, (uint32_t)(ccm_pdb->icv_len <<
					  TLS_PDBOPTS_TR_ICV_LEN_SHIFT));
}

/**
 * rta_tls_cipher_mode - Get TLS cipher mode based on IANA cipher suite value
 * @protinfo: protocol information
 *
 * Return: TLS cipher mode
 */
static inline enum tls_cipher_mode rta_tls_cipher_mode(uint16_t protinfo)
{
	switch (protinfo) {
	case OP_PCL_TLS_RSA_WITH_AES_128_GCM_SHA256:
	case OP_PCL_TLS_RSA_WITH_AES_256_GCM_SHA384:
	case OP_PCL_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
	case OP_PCL_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
	case OP_PCL_TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
	case OP_PCL_TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
	case OP_PCL_TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
	case OP_PCL_TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
	case OP_PCL_TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
	case OP_PCL_TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
	case OP_PCL_TLS_DH_anon_WITH_AES_128_GCM_SHA256:
	case OP_PCL_TLS_DH_anon_WITH_AES_256_GCM_SHA384:
	case OP_PCL_TLS_PSK_WITH_AES_128_GCM_SHA256:
	case OP_PCL_TLS_PSK_WITH_AES_256_GCM_SHA384:
	case OP_PCL_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
	case OP_PCL_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
	case OP_PCL_TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
	case OP_PCL_TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
	case OP_PCL_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
	case OP_PCL_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
	case OP_PCL_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
	case OP_PCL_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
	case OP_PCL_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
	case OP_PCL_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
	case OP_PCL_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
	case OP_PCL_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
		return RTA_TLS_CIPHER_GCM;

	case OP_PCL_TLS_KRB5_WITH_RC4_128_MD5:
	case OP_PCL_TLS_RSA_WITH_RC4_128_MD5:
	case OP_PCL_TLS_DH_anon_WITH_RC4_128_MD5:
	case OP_PCL_TLS_KRB5_EXPORT_WITH_RC4_40_MD5:
	case OP_PCL_TLS_RSA_EXPORT_WITH_RC4_40_MD5:
	case OP_PCL_TLS_DH_anon_EXPORT_WITH_RC4_40_MD5:
	case OP_PCL_TLS_KRB5_WITH_RC4_128_SHA:
	case OP_PCL_TLS_PSK_WITH_RC4_128_SHA:
	case OP_PCL_TLS_DHE_PSK_WITH_RC4_128_SHA:
	case OP_PCL_TLS_RSA_PSK_WITH_RC4_128_SHA:
	case OP_PCL_TLS_RSA_WITH_RC4_128_SHA:
	case OP_PCL_TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
	case OP_PCL_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
	case OP_PCL_TLS_ECDH_RSA_WITH_RC4_128_SHA:
	case OP_PCL_TLS_ECDHE_RSA_WITH_RC4_128_SHA:
	case OP_PCL_TLS_ECDH_anon_WITH_RC4_128_SHA:
	case OP_PCL_TLS_ECDHE_PSK_WITH_RC4_128_SHA:
	case OP_PCL_TLS_KRB5_EXPORT_WITH_RC4_40_SHA:
		return RTA_TLS_CIPHER_STREAM;

	case OP_PCL_TLS_RSA_WITH_AES_128_CBC_SHA:
	case OP_PCL_TLS_DH_DSS_WITH_AES_128_CBC_SHA:
	case OP_PCL_TLS_DH_RSA_WITH_AES_128_CBC_SHA:
	case OP_PCL_TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
	case OP_PCL_TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
	case OP_PCL_TLS_DH_anon_WITH_AES_128_CBC_SHA:
	case OP_PCL_TLS_PSK_WITH_AES_128_CBC_SHA:
	case OP_PCL_TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
	case OP_PCL_TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
	case OP_PCL_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
	case OP_PCL_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
	case OP_PCL_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
	case OP_PCL_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
	case OP_PCL_TLS_ECDH_anon_WITH_AES_128_CBC_SHA:
	case OP_PCL_TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
	case OP_PCL_TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
	case OP_PCL_TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
	case OP_PCL_TLS_RSA_WITH_AES_256_CBC_SHA:
	case OP_PCL_TLS_DH_DSS_WITH_AES_256_CBC_SHA:
	case OP_PCL_TLS_DH_RSA_WITH_AES_256_CBC_SHA:
	case OP_PCL_TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
	case OP_PCL_TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
	case OP_PCL_TLS_DH_anon_WITH_AES_256_CBC_SHA:
	case OP_PCL_TLS_PSK_WITH_AES_256_CBC_SHA:
	case OP_PCL_TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
	case OP_PCL_TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
	case OP_PCL_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
	case OP_PCL_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
	case OP_PCL_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
	case OP_PCL_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
	case OP_PCL_TLS_ECDH_anon_WITH_AES_256_CBC_SHA:
	case OP_PCL_TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
	case OP_PCL_TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
	case OP_PCL_TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
	case OP_PCL_TLS_PSK_WITH_AES_128_CBC_SHA256:
	case OP_PCL_TLS_PSK_WITH_AES_256_CBC_SHA384:
	case OP_PCL_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:
	case OP_PCL_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
	case OP_PCL_TLS_RSA_PSK_WITH_AES_128_CBC_SHA256:
	case OP_PCL_TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
	case OP_PCL_TLS_KRB5_WITH_3DES_EDE_CBC_MD5:
	case OP_PCL_TLS_KRB5_WITH_3DES_EDE_CBC_SHA:
	case OP_PCL_TLS_PSK_WITH_3DES_EDE_CBC_SHA:
	case OP_PCL_TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
	case OP_PCL_TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
	case OP_PCL_TLS_RSA_WITH_3DES_EDE_CBC_SHA:
	case OP_PCL_TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
	case OP_PCL_TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
	case OP_PCL_TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
	case OP_PCL_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
	case OP_PCL_TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:
	case OP_PCL_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
	case OP_PCL_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
	case OP_PCL_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
	case OP_PCL_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
	case OP_PCL_TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA:
	case OP_PCL_TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
	case OP_PCL_TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
	case OP_PCL_TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
	case OP_PCL_TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5:
	case OP_PCL_TLS_KRB5_WITH_DES_CBC_MD5:
	case OP_PCL_TLS_RSA_EXPORT_WITH_DES40_CBC_SHA:
	case OP_PCL_TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA:
	case OP_PCL_TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA:
	case OP_PCL_TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA:
	case OP_PCL_TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA:
	case OP_PCL_TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA:
	case OP_PCL_TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA:
	case OP_PCL_TLS_KRB5_WITH_DES_CBC_SHA:
	case OP_PCL_TLS_RSA_WITH_DES_CBC_SHA:
	case OP_PCL_TLS_DH_DSS_WITH_DES_CBC_SHA:
	case OP_PCL_TLS_DH_RSA_WITH_DES_CBC_SHA:
	case OP_PCL_TLS_DHE_DSS_WITH_DES_CBC_SHA:
	case OP_PCL_TLS_DHE_RSA_WITH_DES_CBC_SHA:
	case OP_PCL_TLS_DH_anon_WITH_DES_CBC_SHA:
	case OP_PCL_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
	case OP_PCL_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
	case OP_PCL_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
	case OP_PCL_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
	case OP_PCL_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
	case OP_PCL_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
	case OP_PCL_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
	case OP_PCL_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
	case OP_PCL_TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA:
	case OP_PCL_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA:
	case OP_PCL_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA:
	case OP_PCL_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
	case OP_PCL_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
	case OP_PCL_TLS_RSA_WITH_AES_128_CBC_SHA256:
	case OP_PCL_TLS_RSA_WITH_AES_256_CBC_SHA256:
	case OP_PCL_TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
	case OP_PCL_TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
	case OP_PCL_TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
	case OP_PCL_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
	case OP_PCL_TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
	case OP_PCL_TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
	case OP_PCL_TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
	case OP_PCL_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
	case OP_PCL_TLS_DH_anon_WITH_AES_128_CBC_SHA256:
	case OP_PCL_TLS_DH_anon_WITH_AES_256_CBC_SHA256:
		return RTA_TLS_CIPHER_CBC;

	default:
		pr_err("Invalid protinfo 0x%08x\n", protinfo);
		return RTA_TLS_CIPHER_INVALID;
	}
}

static inline void __rta_copy_tls_pdb(struct program *p, void *pdb,
				      struct protcmd *protcmd)
{
	uint16_t protinfo = protcmd->protinfo;
	uint32_t protid = protcmd->protid;

	switch (rta_tls_cipher_mode(protinfo)) {
	case RTA_TLS_CIPHER_GCM:
		__rta_copy_tls_gcm_pdb(p, pdb, protid);
		break;
	case RTA_TLS_CIPHER_STREAM:
		__rta_copy_tls_stream_pdb(p, pdb, protid);
		break;
	case RTA_TLS_CIPHER_CBC:
		__rta_copy_tls_block_pdb(p, pdb, protid);
		break;
	case RTA_TLS_CIPHER_INVALID:
	default:
		pr_err("Invalid protinfo 0x%08x\n", protinfo);
	}
}

static inline int __tls_gen_auth_key(struct program *program,
				     struct alginfo *authdata,
				     uint16_t protinfo)
{
	uint32_t dkp_protid;

	switch (protinfo) {
	case OP_PCL_TLS_RSA_WITH_AES_128_CBC_SHA:
	case OP_PCL_TLS_RSA_WITH_AES_256_CBC_SHA:
	case OP_PCL_TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
	case OP_PCL_TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
	case OP_PCL_TLS_PSK_WITH_AES_128_CBC_SHA:
	case OP_PCL_TLS_PSK_WITH_AES_256_CBC_SHA:
	case OP_PCL_TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
	case OP_PCL_TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
		dkp_protid = OP_PCLID_DKP_SHA1;
		break;
	case OP_PCL_TLS_RSA_WITH_AES_128_CBC_SHA256:
	case OP_PCL_TLS_RSA_WITH_AES_256_CBC_SHA256:
	case OP_PCL_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
	case OP_PCL_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
		dkp_protid = OP_PCLID_DKP_SHA256;
		break;
	default:
		pr_err("Invalid protinfo 0x%08x\n", protinfo);
		return -EINVAL;
	}

	if (authdata->key_type == RTA_DATA_PTR)
		return DKP_PROTOCOL(program, dkp_protid, OP_PCL_DKP_SRC_PTR,
				    OP_PCL_DKP_DST_PTR,
				    (uint16_t)authdata->keylen, authdata->key,
				    authdata->key_type);
	else
		return DKP_PROTOCOL(program, dkp_protid, OP_PCL_DKP_SRC_IMM,
				    OP_PCL_DKP_DST_IMM,
				    (uint16_t)authdata->keylen, authdata->key,
				    authdata->key_type);
}

/**
 * cnstr_shdsc_tls - TLS family block cipher encapsulation / decapsulation
 *                   shared descriptor.
 * @descbuf: pointer to buffer used for descriptor construction
 * @ps: if 36/40bit addressing is desired, this parameter must be true
 * @swap: must be true when core endianness doesn't match SEC endianness
 * @pdb: pointer to the PDB to be used in this descriptor
 *       This structure will be copied inline to the descriptor under
 *       construction. No error checking will be made. Refer to the block guide
 *       for details of the PDB.
 * @protcmd: pointer to Protocol Operation Command definitions
 * @cipherdata: pointer to block cipher transform definitions
 * @authdata: pointer to authentication transform definitions
 *
 * Return: size of descriptor written in words or negative number on error
 *
 * The following built-in protocols are supported:
 * SSL3.0 / TLS1.0 / TLS1.1 / TLS1.2 / DTLS1.0 / DTLS1.2
 */
static inline int cnstr_shdsc_tls(uint32_t *descbuf, bool ps, bool swap,
				  uint8_t *pdb, struct protcmd *protcmd,
				  struct alginfo *cipherdata,
				  struct alginfo *authdata)
{
	struct program prg;
	struct program *p = &prg;

	LABEL(pdb_end);
	LABEL(keyjmp);
	REFERENCE(phdr);
	REFERENCE(pkeyjmp);

	PROGRAM_CNTXT_INIT(p, descbuf, 0);
	if (ps)
		PROGRAM_SET_36BIT_ADDR(p);
	if (swap)
		PROGRAM_SET_BSWAP(p);

	phdr = SHR_HDR(p, SHR_SERIAL, 0, 0);
	__rta_copy_tls_pdb(p, pdb, protcmd);
	SET_LABEL(p, pdb_end);
	pkeyjmp = JUMP(p, keyjmp, LOCAL_JUMP, ALL_TRUE, BOTH|SHRD|SELF);
	/*
	 * SSL3.0 uses SSL-MAC (SMAC) instead of HMAC, thus MDHA Split Key
	 * does not apply.
	 */
	if (protcmd->protid == OP_PCLID_SSL30)
		KEY(p, KEY2, authdata->key_enc_flags, authdata->key,
		    authdata->keylen, INLINE_KEY(authdata));
	else
		KEY(p, MDHA_SPLIT_KEY, authdata->key_enc_flags, authdata->key,
		    authdata->keylen, INLINE_KEY(authdata));
	KEY(p, KEY1, cipherdata->key_enc_flags, cipherdata->key,
	    cipherdata->keylen, INLINE_KEY(cipherdata));
	SET_LABEL(p, keyjmp);
	PROTOCOL(p, protcmd->optype, protcmd->protid, protcmd->protinfo);

	PATCH_HDR(p, phdr, pdb_end);
	PATCH_JUMP(p, pkeyjmp, keyjmp);
	return PROGRAM_FINALIZE(p);
}

/**
 * CWAP_DTLS_ENC_BASE_SD_LEN - CAPWAP/DTLS encapsulation shared descriptor
 *                             length
 *
 * Accounts only for the "base" commands, i.e. excludes KEY / DKP commands,
 * immediate keys, and is intended to be used by upper layers to determine
 * whether keys can be inlined or not.
 * To be used as first parameter of rta_inline_query(), added with PDB length.
 */
#define CWAP_DTLS_ENC_BASE_SD_LEN	(11 * CAAM_CMD_SZ)

/**
 * CWAP_DTLS_DEC_BASE_SD_LEN - CAPWAP/DTLS decapsulation shared descriptor
 *                             length
 *
 * Accounts only for the "base" commands, i.e. excludes KEY / DKP commands,
 * immediate keys, and is intended to be used by upper layers to determine
 * whether keys can be inlined or not.
 * To be used as first parameter of rta_inline_query(), added with PDB length.
 */
#define CWAP_DTLS_DEC_BASE_SD_LEN	(10 * CAAM_CMD_SZ)

/**
 * cnstr_shdsc_cwap_dtls - DTLS (in CAPWAP context) block cipher encapsulation /
 *                         decapsulation shared descriptor.
 * @descbuf: pointer to buffer used for descriptor construction
 * @ps: if 36/40bit addressing is desired, this parameter must be true
 * @swap: must be true when core endianness doesn't match SEC endianness
 * @pdb: pointer to the PDB to be used in this descriptor
 *       This structure will be copied inline to the descriptor under
 *       construction. No error checking will be made. Refer to the block guide
 *       for details of the PDB.
 * @protcmd: pointer to Protocol Operation Command definitions
 *           The following built-in protocols are supported: DTLS1.0 / DTLS1.2
 * @cipherdata: pointer to block cipher transform definitions
 * @authdata: pointer to authentication transform definitions
 *            If an authentication key is required by the protocol:
 *            -For SEC Eras 1-5, an MDHA split key must be provided;
 *            Note that the size of the split key itself must be specified.
 *            -For SEC Eras 6+, a "normal" key must be provided; DKP (Derived
 *            Key Protocol) will be used to compute MDHA on the fly in HW.
 *
 * Return: size of descriptor written in words or negative number on error
 */
static inline int cnstr_shdsc_cwap_dtls(uint32_t *descbuf, bool ps, bool swap,
					uint8_t *pdb, struct protcmd *protcmd,
					struct alginfo *cipherdata,
					struct alginfo *authdata)
{
	struct program prg;
	struct program *p = &prg;
	int ret;
	LABEL(pdb_end);
	LABEL(keyjmp);
	REFERENCE(phdr);
	REFERENCE(pkeyjmp);

	PROGRAM_CNTXT_INIT(p, descbuf, 0);
	if (ps)
		PROGRAM_SET_36BIT_ADDR(p);
	if (swap)
		PROGRAM_SET_BSWAP(p);

	phdr = SHR_HDR(p, SHR_SERIAL, 0, 0);
	__rta_copy_tls_pdb(p, pdb, protcmd);
	SET_LABEL(p, pdb_end);

	MATHI(p, DPOVRD, RSHIFT, DTLS_DPOVRD_METADATA_LEN_SHIFT, VSEQOUTSZ, 1,
	      0);
	/* invalidate DPOVRD, since it's not (currently) used in CAPWAP DTLS */
	MATHB(p, DPOVRD, AND, ~TLS_DPOVRD_USE, DPOVRD, 4, IMMED2);
	/* TODO: CLASS2 corresponds to AUX=2'b10; add more intuitive defines */
	SEQFIFOSTORE(p, METADATA, 0, 0, CLASS2 | VLF);

	if (protcmd->optype == OP_TYPE_ENCAP_PROTOCOL)
		/* Add CAPWAP DTLS header */
		SEQSTORE(p, 0x00000001, 0, 4, IMMED);
	else
		/* Skip over CAPWAP DTLS header */
		SEQFIFOLOAD(p, SKIP, 4, 0);

	pkeyjmp = JUMP(p, keyjmp, LOCAL_JUMP, ALL_TRUE, BOTH | SHRD | SELF);
	if (authdata->keylen)
		if (rta_sec_era < RTA_SEC_ERA_6) {
			KEY(p, MDHA_SPLIT_KEY, authdata->key_enc_flags,
			    authdata->key, authdata->keylen,
			    INLINE_KEY(authdata));
		} else {
			ret = __tls_gen_auth_key(p, authdata,
						 protcmd->protinfo);
			if (ret < 0)
				return ret;
		}
	if (cipherdata->keylen)
		KEY(p, KEY1, cipherdata->key_enc_flags, cipherdata->key,
		    cipherdata->keylen, INLINE_KEY(cipherdata));
	SET_LABEL(p, keyjmp);
	PROTOCOL(p, protcmd->optype, protcmd->protid, protcmd->protinfo);

	PATCH_HDR(p, phdr, pdb_end);
	PATCH_JUMP(p, pkeyjmp, keyjmp);
	return PROGRAM_FINALIZE(p);
}

#endif /* __DESC_TLS_H__ */
