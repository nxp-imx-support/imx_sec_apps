/*
 * caam descriptor construction helper functions
 *
 * Copyright 2008-2014 Freescale Semiconductor, Inc.
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier:	GPL-2.0+
 *
 * Based on desc_constr.h file in linux drivers/crypto/caam
 */

#include "desc.h"

#define IMMEDIATE (1 << 23)
#define CAAM_CMD_SZ sizeof(uint32_t)
#define CAAM_PTR_SZ sizeof(uint32_t)
#define CAAM_DESC_BYTES_MAX (CAAM_CMD_SZ * MAX_CAAM_DESCSIZE)
#define DESC_JOB_IO_LEN (CAAM_CMD_SZ * 5 + CAAM_PTR_SZ * 3)

#ifdef DEBUG
#define PRINT_POS do { printf("%02d: %s\n", desc_len(desc),\
			      &__func__[sizeof("append")]); \
		     } while (0)
#else
#define PRINT_POS
#endif

#define SET_OK_NO_PROP_ERRORS (IMMEDIATE | LDST_CLASS_DECO | \
			       LDST_SRCDST_WORD_DECOCTRL | \
			       (LDOFF_CHG_SHARE_OK_NO_PROP << \
				LDST_OFFSET_SHIFT))
#define DISABLE_AUTO_INFO_FIFO (IMMEDIATE | LDST_CLASS_DECO | \
				LDST_SRCDST_WORD_DECOCTRL | \
				(LDOFF_DISABLE_AUTO_NFIFO << LDST_OFFSET_SHIFT))
#define ENABLE_AUTO_INFO_FIFO (IMMEDIATE | LDST_CLASS_DECO | \
			       LDST_SRCDST_WORD_DECOCTRL | \
			       (LDOFF_ENABLE_AUTO_NFIFO << LDST_OFFSET_SHIFT))

#if defined(CONFIG_PHYS_64BIT) && !defined(CONFIG_IMX8M)
union ptr_addr_t {
	uint64_t m_whole;
	struct {
#ifdef CONFIG_SYS_FSL_SEC_LE
		uint32_t low;
		uint32_t high;
#elif defined(CONFIG_SYS_FSL_SEC_BE)
		uint32_t high;
		uint32_t low;
#else
#error Neither CONFIG_SYS_FSL_SEC_LE nor CONFIG_SYS_FSL_SEC_BE is defined
#endif
	} m_halfs;
};
#endif

static inline void pdb_add_ptr(uint32_t *offset, uint32_t ptr)
{
#if defined(CONFIG_PHYS_64BIT) && !defined(CONFIG_IMX8M)
	/* The Position of low and high part of 64 bit address
	 * will depend on the endianness of CAAM Block */
	union ptr_addr_t *ptr_addr = (union ptr_addr_t *)offset;
	ptr_addr->m_halfs.high = (uint32_t)(ptr >> 32);
	ptr_addr->m_halfs.low = (uint32_t)ptr;
#else
	*offset = ptr;
#endif
}

static inline int desc_len(uint32_t *desc)
{
	return *desc & HDR_DESCLEN_MASK;
}

static inline int desc_bytes(void *desc)
{
	return desc_len(desc) * CAAM_CMD_SZ;
}

static inline uint32_t *desc_end(uint32_t *desc)
{
	return desc + desc_len(desc);
}

static inline void *desc_pdb(uint32_t *desc)
{
	return desc + 1;
}

static inline void init_desc(uint32_t *desc, uint32_t options)
{
	*desc = (options | HDR_ONE) + 1;
}

static inline void init_job_desc(uint32_t *desc, uint32_t options)
{
	init_desc(desc, CMD_DESC_HDR | options);
}

static inline void init_job_desc_pdb(uint32_t *desc, uint32_t options, size_t pdb_bytes)
{
	uint32_t pdb_len = (pdb_bytes + CAAM_CMD_SZ - 1) / CAAM_CMD_SZ;

	init_job_desc(desc,
		      (((pdb_len + 1) << HDR_START_IDX_SHIFT) + pdb_len) |
		       options);
}

static inline void append_ptr(uint32_t *desc, uint32_t ptr)
{
	uint32_t *offset = (uint32_t *)desc_end(desc);

#if defined(CONFIG_PHYS_64BIT) && !defined(CONFIG_IMX8M)
	/* The Position of low and high part of 64 bit address
	 * will depend on the endianness of CAAM Block */
	union ptr_addr_t *ptr_addr = (union ptr_addr_t *)offset;
	ptr_addr->m_halfs.high = (uint32_t)(ptr >> 32);
	ptr_addr->m_halfs.low = (uint32_t)ptr;
#else
	*offset = ptr;
#endif

	(*desc) += CAAM_PTR_SZ / CAAM_CMD_SZ;
}

static inline void append_data(uint32_t *desc, void *data, int len)
{
	uint32_t *offset = desc_end(desc);

	if (len) /* avoid sparse warning: memcpy with byte count of 0 */
		memcpy(offset, data, len);

	(*desc) += (len + CAAM_CMD_SZ - 1) / CAAM_CMD_SZ;
}

static inline void append_cmd(uint32_t *desc, uint32_t command)
{
	uint32_t *cmd = desc_end(desc);

	*cmd = command;

	(*desc)++;
}

#define append_uint32_t append_cmd

/* Write command without affecting header, and return pointer to next word */
static inline uint32_t *write_cmd(uint32_t *desc, uint32_t command)
{
	*desc = command;

	return desc + 1;
}

static inline void append_cmd_ptr(uint32_t *desc, uint32_t ptr, int len,
				  uint32_t command)
{
	append_cmd(desc, command | len);
	append_ptr(desc, ptr);
}

/* Write length after pointer, rather than inside command */
static inline void append_cmd_ptr_extlen(uint32_t *desc, uint32_t ptr,
					 unsigned int len, uint32_t command)
{
	append_cmd(desc, command);
	if (!(command & (SQIN_RTO | SQIN_PRE)))
		append_ptr(desc, ptr);
	append_cmd(desc, len);
}

static inline void append_cmd_data(uint32_t *desc, void *data, int len,
				   uint32_t command)
{
	append_cmd(desc, command | IMMEDIATE | len);
	append_data(desc, data, len);
}

#define APPEND_CMD_RET(cmd, op) \
static inline uint32_t *append_##cmd(uint32_t *desc, uint32_t options) \
{ \
	uint32_t *cmd = desc_end(desc); \
	PRINT_POS; \
	append_cmd(desc, CMD_##op | options); \
	return cmd; \
}
APPEND_CMD_RET(jump, JUMP)
APPEND_CMD_RET(move, MOVE)

static inline void set_jump_tgt_here(uint32_t *desc, uint32_t *jump_cmd)
{
	*jump_cmd = *jump_cmd | (desc_len(desc) - (jump_cmd - desc));
}

static inline void set_move_tgt_here(uint32_t *desc, uint32_t *move_cmd)
{
	*move_cmd &= ~MOVE_OFFSET_MASK;
	*move_cmd = *move_cmd | ((desc_len(desc) << (MOVE_OFFSET_SHIFT + 2)) &
				 MOVE_OFFSET_MASK);
}

#define APPEND_CMD(cmd, op) \
static inline void append_##cmd(uint32_t *desc, uint32_t options) \
{ \
	PRINT_POS; \
	append_cmd(desc, CMD_##op | options); \
}
APPEND_CMD(operation, OPERATION)

#define APPEND_CMD_LEN(cmd, op) \
static inline void append_##cmd(uint32_t *desc, unsigned int len, uint32_t options) \
{ \
	PRINT_POS; \
	append_cmd(desc, CMD_##op | len | options); \
}
APPEND_CMD_LEN(seq_store, SEQ_STORE)
APPEND_CMD_LEN(seq_fifo_load, SEQ_FIFO_LOAD)
APPEND_CMD_LEN(seq_fifo_store, SEQ_FIFO_STORE)

#define APPEND_CMD_PTR(cmd, op) \
static inline void append_##cmd(uint32_t *desc, uint32_t ptr, unsigned int len, \
				uint32_t options) \
{ \
	PRINT_POS; \
	append_cmd_ptr(desc, ptr, len, CMD_##op | options); \
}
APPEND_CMD_PTR(key, KEY)
APPEND_CMD_PTR(load, LOAD)
APPEND_CMD_PTR(fifo_load, FIFO_LOAD)
APPEND_CMD_PTR(fifo_store, FIFO_STORE)

static inline void append_store(uint32_t *desc, uint32_t ptr, unsigned int len,
				uint32_t options)
{
	uint32_t cmd_src;

	cmd_src = options & LDST_SRCDST_MASK;

	append_cmd(desc, CMD_STORE | options | len);

	/* The following options do not require pointer */
	if (!(cmd_src == LDST_SRCDST_WORD_DESCBUF_SHARED ||
	      cmd_src == LDST_SRCDST_WORD_DESCBUF_JOB    ||
	      cmd_src == LDST_SRCDST_WORD_DESCBUF_JOB_WE ||
	      cmd_src == LDST_SRCDST_WORD_DESCBUF_SHARED_WE))
		append_ptr(desc, ptr);
}

#define APPEND_SEQ_PTR_INTLEN(cmd, op) \
static inline void append_seq_##cmd##_ptr_intlen(uint32_t *desc, uint32_t ptr, \
						 unsigned int len, \
						 uint32_t options) \
{ \
	PRINT_POS; \
	if (options & (SQIN_RTO | SQIN_PRE)) \
		append_cmd(desc, CMD_SEQ_##op##_PTR | len | options); \
	else \
		append_cmd_ptr(desc, ptr, len, CMD_SEQ_##op##_PTR | options); \
}
APPEND_SEQ_PTR_INTLEN(in, IN)
APPEND_SEQ_PTR_INTLEN(out, OUT)

#define APPEND_CMD_PTR_TO_IMM(cmd, op) \
static inline void append_##cmd##_as_imm(uint32_t *desc, void *data, \
					 unsigned int len, uint32_t options) \
{ \
	PRINT_POS; \
	append_cmd_data(desc, data, len, CMD_##op | options); \
}
APPEND_CMD_PTR_TO_IMM(load, LOAD);
APPEND_CMD_PTR_TO_IMM(fifo_load, FIFO_LOAD);

#define APPEND_CMD_PTR_EXTLEN(cmd, op) \
static inline void append_##cmd##_extlen(uint32_t *desc, uint32_t ptr, \
					 unsigned int len, uint32_t options) \
{ \
	PRINT_POS; \
	append_cmd_ptr_extlen(desc, ptr, len, CMD_##op | SQIN_EXT | options); \
}
APPEND_CMD_PTR_EXTLEN(seq_in_ptr, SEQ_IN_PTR)
APPEND_CMD_PTR_EXTLEN(seq_out_ptr, SEQ_OUT_PTR)

/*
 * Determine whether to store length internally or externally depending on
 * the size of its type
 */
#define APPEND_CMD_PTR_LEN(cmd, op, type) \
static inline void append_##cmd(uint32_t *desc, uint32_t ptr, \
				type len, uint32_t options) \
{ \
	PRINT_POS; \
	if (sizeof(type) > sizeof(uint16_t)) \
		append_##cmd##_extlen(desc, ptr, len, options); \
	else \
		append_##cmd##_intlen(desc, ptr, len, options); \
}
APPEND_CMD_PTR_LEN(seq_in_ptr, SEQ_IN_PTR, uint32_t)
APPEND_CMD_PTR_LEN(seq_out_ptr, SEQ_OUT_PTR, uint32_t)

/*
 * 2nd variant for commands whose specified immediate length differs
 * from length of immediate data provided, e.g., split keys
 */
#define APPEND_CMD_PTR_TO_IMM2(cmd, op) \
static inline void append_##cmd##_as_imm(uint32_t *desc, void *data, \
					 unsigned int data_len, \
					 unsigned int len, uint32_t options) \
{ \
	PRINT_POS; \
	append_cmd(desc, CMD_##op | IMMEDIATE | len | options); \
	append_data(desc, data, data_len); \
}
APPEND_CMD_PTR_TO_IMM2(key, KEY);

#define APPEND_CMD_RAW_IMM(cmd, op, type) \
static inline void append_##cmd##_imm_##type(uint32_t *desc, type immediate, \
					     uint32_t options) \
{ \
	PRINT_POS; \
	append_cmd(desc, CMD_##op | IMMEDIATE | options | sizeof(type)); \
	append_cmd(desc, immediate); \
}
APPEND_CMD_RAW_IMM(load, LOAD, uint32_t);
