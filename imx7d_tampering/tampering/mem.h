/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MEM_H_
#define MEM_H_

#if defined(CONFIG_IMX7)
	#define AIPS1_ARB_BASE_ADDR            	0x30000000
	#define AIPS_TZ1_BASE_ADDR             	AIPS1_ARB_BASE_ADDR
	#define AIPS1_OFF_BASE_ADDR            	(AIPS_TZ1_BASE_ADDR+0x200000)
	#define SNVS_BASE_ADDR                 	(AIPS1_OFF_BASE_ADDR+0x170000)
#elif defined(CONFIG_IMX6)
	#define AIPS1_ARB_BASE_ADDR             0x02000000
	#define ATZ1_BASE_ADDR              	AIPS1_ARB_BASE_ADDR
	#define AIPS1_OFF_BASE_ADDR         	(ATZ1_BASE_ADDR + 0x80000)
	#define SNVS_BASE_ADDR                  (AIPS1_OFF_BASE_ADDR + 0x4C000)
#endif

// Offsets from SNVS_BASE_ADDR
#define HPLR 			0x00000000
#define LPPGDR			0x00000064
#define	LPSR			0x0000004C		
#define HPCOMR			0x00000004
#define LPCR			0x00000038
#define LPTDSR			0x000000A4
#define HPSVSR			0x00000018
#define LPSRTCMR		0x00000050
#define LPSRTCLR		0x00000054
#define LPZMKR0			0x0000006C

#define	LPSR_VAL		0x00000008
#define HPCOMR_VAL		0x80002000
#define	LPPGDR_VAL		0x41736166
#define LPCR_VAL		0x00000001
#define ZMK_SIZE		0x00000032

#define ADDR_SIZE 4
#define TIMEOUT_MAX_VAL 0x1000

#define get_SNVS_reg(virt_addr, add_offset)  (unsigned int*)(((void*)virt_addr)+add_offset)
#define set_value_of_SNVS_reg(virt_addr, add_offset, value)	*get_SNVS_reg(virt_addr, add_offset) = ((unsigned int)(value))

void check_mem();
void free_mem();
void write_mem(int value, unsigned int address);
unsigned int read_mem(unsigned int address);
int io_update_bits(unsigned int reg, int clear, int set);
unsigned int *get_mem();

#endif
