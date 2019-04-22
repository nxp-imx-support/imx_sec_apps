/*
 * Copyright 2019 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "mdha.h"
#include "mdha_test.h"

int mdha_fd;
mdha_addr_t mdha_addr;

void mdha_test_usage(void)
{
	printf("mdha test usage:\n");
	printf("sha1 test ==> mdha sha1 <input_file>\n");
	printf("md5  test ==> mdha md5 <input_file>\n");
}

int send_tasks(char *input_file)
{
	uint32_t task_block_size;
	int ret = -1;
	uint32_t i;
	FILE *fp;

	fp = fopen(input_file, "rb");
	if (fp == NULL) {
		printf("input file open failed\n");
		return ret;
	}

	task_block_size = fread(mdha_addr.block, 1, MAX_BLOCK_SIZE, fp);

	ret = ioctl(mdha_fd, MDHA_IOCTL_TASK, &task_block_size);

	if (ret < 0) {
		printf("[ioctl] Something went wrong");
		return -1;
	}

	printf("\nrecieved digest: \n");
	for (i = 0; i < MAX_DIGEST_SIZE; i++)
	{
		printf("%X ", mdha_addr.digest[i]);
	}
	printf("\n");

	fclose(fp);

	return 0;
}

int main(int argc, char *argv[])
{
	char *input_file = NULL;

	const char *op = argc >= 2 ? argv[1] : NULL;

	if (argc < 2)
		goto out_usage;

	if (!strcmp(op, "sha1") || !strcmp(op, "md5")) {
		if (argc < 3)
			goto out_usage;
		input_file = argv[2];
	} else
		goto out_usage;

	mdha_fd = open("/dev/mdha", O_RDWR);

	if(mdha_fd < 0) {
		fprintf(stderr, "mdha open failed\n");
		return -1;
	}

	if (!strcmp(op, "sha1"))
		mdha_addr.algo = SHA1;

	if (!strcmp(op, "md5"))
		mdha_addr.algo = MD5;

	mdha_addr.digest = calloc(1, MAX_DIGEST_SIZE);
	if (!mdha_addr.digest) {
		fprintf(stderr, "digest calloc failed");
		return -1;
	}

	mdha_addr.block = calloc(1, MAX_BLOCK_SIZE);
	if (!mdha_addr.block) {
		fprintf(stderr, "digest calloc failed");
		return -1;
	}

	ioctl(mdha_fd, MDHA_IOCTL_TASKS_TYPE, &mdha_addr);

	send_tasks(input_file);

	free((void *)mdha_addr.digest);
	free((void *)mdha_addr.block);

	close(mdha_fd);

	goto out;

out_usage:
	mdha_test_usage();

out:
	return 0;
}
