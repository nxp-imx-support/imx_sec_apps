/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include "mem.h"
 
int fd = 0;
unsigned int *mem = NULL;

inline void check_mem()
{
	fd = open("/dev/mem", O_SYNC | O_RDWR);
	
	if (fd < 0) {
		perror ("Can't open /dev/mem ! \n");
		exit(-1);
	}
	mem = mmap (NULL, ADDR_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, SNVS_BASE_ADDR);
	
	if (mem == MAP_FAILED) {
		perror ("Can't map memory, maybe the address is not truncated\n");
		exit(-1);
	}
}

inline void free_mem()
{
	munmap(mem, ADDR_SIZE);
	close(fd);
}

inline void write_mem(int value, unsigned int address)
{
	if (!fd) {
		check_mem();
	}
	set_value_of_SNVS_reg(mem, address, value);
	volatile int i = 0;
	for (i = 0; i < TIMEOUT_MAX_VAL; i++){}
}

inline unsigned int read_mem(unsigned int address)
{
	if (!fd) {
		check_mem();
	}
	return *get_SNVS_reg(mem, address);
}

inline int io_update_bits(unsigned int reg, int clear, int set)
{
	if (!fd) {
		check_mem();
	}
	int val = 0;
	val = *get_SNVS_reg(mem, reg);
	val = val & (~(clear));
	val = val | set;
	set_value_of_SNVS_reg(mem, reg, val);
	volatile int i = 0;
	for (i = 0; i < TIMEOUT_MAX_VAL; i++){}
	return 0;
}

inline unsigned int *get_mem()
{
	if (!fd) {
		check_mem();
	}
	return mem;
}

