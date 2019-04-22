/*
 * Copyright 2019 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MDHA_H
#define MDHA_H

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>

#define MAX_DIGEST_SIZE 20
#define MAX_BLOCK_SIZE 1024*1024*5
#define SHA1 0
#define MD5  1

typedef struct {
	uint8_t *digest;
	uint8_t *block;
	uint8_t algo;
}mdha_addr_t;

#define MDHA_IOCTL_TASKS_TYPE	_IOR('K', 0, mdha_addr_t)
#define MDHA_IOCTL_TASK				_IOWR('K', 1, uint32_t)

#endif /* MDHA_H */
