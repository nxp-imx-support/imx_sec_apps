/*
 * Copyright 2019 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "key_blob.h"
#include "kb_test.h"

#define BLOB_OVERHEAD 	48
#define KEY_MAX_LENGTH 	(512 - BLOB_OVERHEAD)

#define KEY_COLOR_RED	0x0
#define KEY_COLOR_BLACK	0x1

#define KEY_COVER_ECB	0x0
#define KEY_COVER_CCM	0x1

#define DATA_SIZE 16

int kb_fd;
kb_addr_t kb_addr;

void kb_test_usage(void)
{
	printf("key blob test usage:\n");
	printf("encap test ==> kb_test encap <key_color> <key_file> <blob_file>\n");
	printf("decap test ==> kb_test decap <key_color> <blob_file> <key_file>\n");
	printf("encr test  ==> kb_test encr <key_color> <blob_file> <input_file> <encrypted_file>\n");
	printf("decr test  ==> kb_test decr <key_color> <blob_file> <encrypted_file> <decrypted_file>\n");
}

int kb_encap_test(char *key_color, char *key_file, char *blob_file)
{
	FILE *fp;
	kb_parameter_t parameter;
	int ret = -1;
	uint32_t i;

	memset(kb_addr.key_addr, 0, KEY_MAX_LENGTH);
	memset(kb_addr.blob_addr, 0, KEY_MAX_LENGTH + BLOB_OVERHEAD);

	fp = fopen(key_file, "rb");
	if (fp == NULL) {
		printf("key file open failed\n");
		return ret;
	}

	parameter.key_len = fread(kb_addr.key_addr, 1, KEY_MAX_LENGTH, fp);
	parameter.key_cover = KEY_COVER_ECB;

	if (!strcmp(key_color, "red"))
		parameter.key_color = KEY_COLOR_RED;
	else
		parameter.key_color = KEY_COLOR_BLACK;

	fclose(fp);

	if (parameter.key_len <= 0) {
		printf("key file read failed\n");
		return ret;
	}

	parameter.blob_len = parameter.key_len + BLOB_OVERHEAD;

	printf("\nencap test\n");
	printf("\nkey: \n");
	for (i=0; i<parameter.key_len; i++)
	{
		printf("%X ", kb_addr.key_addr[i]);
	}
	printf("\n");

	ioctl(kb_fd, KB_IOCTL_ENCAP, &parameter);

	printf("\nblob: \n");
	for (i=0; i<parameter.blob_len; i++)
	{
		printf("%X ", kb_addr.blob_addr[i]);
	}
	printf("\n");

	fp = fopen(blob_file, "wb");
	if (fp == NULL) {
		printf("blob file open failed\n");
		return ret;
	}

	fwrite(kb_addr.blob_addr, 1, parameter.blob_len, fp);

	fclose(fp);

	return 0;
}

int kb_decap_test(char *key_color, char *blob_file, char *key_file)
{
	FILE *fp;
	kb_parameter_t parameter;
	int ret = -1;
	uint32_t i;

	memset(kb_addr.key_addr, 0, KEY_MAX_LENGTH);
	memset(kb_addr.blob_addr, 0, KEY_MAX_LENGTH + BLOB_OVERHEAD);

	fp = fopen(blob_file, "rb");
	if (fp == NULL) {
		printf("blob file open failed\n");
		return ret;
	}

	parameter.blob_len = fread(kb_addr.blob_addr, 1, KEY_MAX_LENGTH + BLOB_OVERHEAD, fp);
	parameter.key_cover = KEY_COVER_ECB;

	if (!strcmp(key_color, "red"))
		parameter.key_color = KEY_COLOR_RED;
	else
		parameter.key_color = KEY_COLOR_BLACK;

	fclose(fp);

	if (parameter.blob_len <= BLOB_OVERHEAD) {
		printf("blob file read failed\n");
		return ret;
	}

	parameter.key_len = parameter.blob_len - BLOB_OVERHEAD;

	printf("\ndecap test\n");
	printf("\nblob: \n");
	for (i=0; i<parameter.blob_len; i++)
	{
		printf("%X ", kb_addr.blob_addr[i]);
	}
	printf("\n");

	ioctl(kb_fd, KB_IOCTL_DECAP, &parameter);

	printf("\nkey: \n");
	for (i=0; i<parameter.key_len; i++)
	{
		printf("%X ", kb_addr.key_addr[i]);
	}
	printf("\n");

	fp = fopen(key_file, "wb");
	if (fp == NULL) {
		printf("key file open failed\n");
		return ret;
	}

	fwrite(kb_addr.key_addr, 1, parameter.key_len, fp);

	fclose(fp);

	return 0;
}

int kb_encr_test(char *key_color, char *blob_file, char *input_file, char *encrypted_file)
{
	int rc;
	FILE *fp;
	uint32_t i;
	int ret = -1;
	int fdin, fdout;
	char *src, *dst;
	int total_size = 0;
	struct stat statbuf;
	kb_operation_t operation;

	memset(kb_addr.key_addr, 0, KEY_MAX_LENGTH);
	memset(kb_addr.blob_addr, 0, KEY_MAX_LENGTH + BLOB_OVERHEAD);

	fp = fopen(blob_file, "rb");
	if (fp == NULL) {
		printf("blob file open failed\n");
		return ret;
	}

	// Store the blob into device file
	operation.blob_len = fread(kb_addr.blob_addr, 1, KEY_MAX_LENGTH + BLOB_OVERHEAD, fp);
	operation.key_cover = KEY_COVER_ECB;

	if (!strcmp(key_color, "red"))
		operation.key_color = KEY_COLOR_RED;
	else
		operation.key_color = KEY_COLOR_BLACK;

	fclose(fp);

	if (operation.blob_len <= BLOB_OVERHEAD) {
		printf("blob file read failed\n");
		return ret;
	}

	operation.returned = 0;
	operation.key_len = operation.blob_len - BLOB_OVERHEAD;

	// Open input file
	fdin = open(input_file, O_RDONLY);
	if (fdin == -1) {
		printf("open fdin\n");
		return ret;
	}

	// Open output file
	fdout = open(encrypted_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fdout == -1) {
		printf("open fdout\n");
		return ret;
	}

	// Truncate output file size to input file size
	rc = fstat(fdin, &statbuf);
	if (rc == -1) {
		printf("fstat\n");
		return ret;
	}

	rc = ftruncate(fdout, statbuf.st_size);
	if (rc == -1) {
		printf("truncate\n");
		return ret;
	}

	// Mmap the input file in memory
	src = mmap(0, statbuf.st_size, PROT_READ, MAP_SHARED, fdin, 0);
	if (src == MAP_FAILED) {
		printf("mmap src\n");
		return ret;
	}

	// Mmap the output file in memory
	dst = mmap(0, statbuf.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fdout, 0);
	if (dst == MAP_FAILED) {
		printf("mmap dst\n");
		return ret;
	}

	// Encrypt input data in chunks
	while (total_size < statbuf.st_size) {
		memcpy(operation.buffer, src + total_size, DATA_SIZE);

		rc = ioctl(kb_fd, KB_IOCTL_ENCR, &operation);
		if (rc == -1) {
			printf("ioctl\n");
			goto free_resources;
		}
		if (operation.returned != 0) {
			printf("operation failed\n");
			goto free_resources;
		}
		memcpy(dst + total_size, operation.buffer, DATA_SIZE);
		total_size += DATA_SIZE;
	}


free_resources:
	// Unmap input file mapping
	rc = munmap(src, statbuf.st_size);
	if (rc == -1) {
		printf("munmap source\n");
		return ret;
	}

	// Unmap output file mapping
	rc = munmap(dst, statbuf.st_size);
	if (rc == -1) {
		printf("munmap dest\n");
		return ret;
	}

	// Close input file
	rc = close(fdin);
	if (rc == -1) {
		printf("close source\n");
		return ret;
	}

	// Close output file
	rc = close(fdout);
	if (rc == -1) {
		printf("close dest\n");
		return ret;
	}

	return 0;
}

int kb_decr_test(char *key_color, char *blob_file, char *encrypted_file, char *decrypted_file)
{
	int rc;
	FILE *fp;
	uint32_t i;
	int ret = -1;
	int fdin, fdout;
	char *src, *dst;
	int total_size = 0;
	struct stat statbuf;
	kb_operation_t operation;

	memset(kb_addr.key_addr, 0, KEY_MAX_LENGTH);
	memset(kb_addr.blob_addr, 0, KEY_MAX_LENGTH + BLOB_OVERHEAD);

	fp = fopen(blob_file, "rb");
	if (fp == NULL) {
		printf("blob file open failed\n");
		return ret;
	}

	operation.blob_len = fread(kb_addr.blob_addr, 1, KEY_MAX_LENGTH + BLOB_OVERHEAD, fp);
	operation.key_cover = KEY_COVER_ECB;

	if (!strcmp(key_color, "red"))
		operation.key_color = KEY_COLOR_RED;
	else
		operation.key_color = KEY_COLOR_BLACK;

	fclose(fp);

	if (operation.blob_len <= BLOB_OVERHEAD) {
		printf("blob file read failed\n");
		return ret;
	}

	operation.returned = 0;
	operation.key_len = operation.blob_len - BLOB_OVERHEAD;

	// Open encrypted file
	fdin = open(encrypted_file, O_RDONLY);
	if (fdin == -1) {
		printf("open fdin\n");
		return ret;
	}

	// Open decrypted file
	fdout = open(decrypted_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fdout == -1) {
		printf("open fdout\n");
		return ret;
	}

	// Truncate output file size to input file size
	rc = fstat(fdin, &statbuf);
	if (rc == -1) {
		printf("fstat\n");
		return ret;
	}

	rc = ftruncate(fdout, statbuf.st_size);
	if (rc == -1) {
		printf("truncate\n");
		return ret;
	}

	// Mmap the input file in memory
	src = mmap(0, statbuf.st_size, PROT_READ, MAP_SHARED, fdin, 0);
	if (src == MAP_FAILED) {
		printf("mmap src\n");
		return ret;
	}

	// Mmap the output file in memory
	dst = mmap(0, statbuf.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fdout, 0);
	if (dst == MAP_FAILED) {
		printf("mmap dst\n");
		return ret;
	}

	// Decrypt input data in chunks
	while (total_size < statbuf.st_size) {
		memcpy(operation.buffer, src + total_size, DATA_SIZE);

		rc = ioctl(kb_fd, KB_IOCTL_DECR, &operation);
		if (rc == -1) {
			printf("ioctl\n");
			goto free_resources;
		}
		if (operation.returned != 0) {
			printf("operation failed\n");
			goto free_resources;
		}
		memcpy(dst + total_size, operation.buffer, DATA_SIZE);
		total_size += DATA_SIZE;
	}

free_resources:
	// Unmap input file mapping
	rc = munmap(src, statbuf.st_size);
	if (rc == -1) {
		printf("munmap source\n");
		return ret;
	}

	// Unmap output file mapping
	rc = munmap(dst, statbuf.st_size);
	if (rc == -1) {
		printf("munmap dest\n");
		return ret;
	}

	// Close input file
	rc = close(fdin);
	if (rc == -1) {
		printf("close source\n");
		return ret;
	}

	// Close output file
	rc = close(fdout);
	if (rc == -1) {
		printf("close dest\n");
		return ret;
	}

	return 0;
}

int roundup(char file_name[])
{
	int rc;
	int fdin;
	int ret = -1;
	int size_pad;
	struct stat statbuf;

	fdin = open(file_name, O_RDWR | O_CREAT);
	if (fdin == -1) {
		printf("Can not open the file %s\n", file_name);
		return ret;
	}

	rc = fstat(fdin, &statbuf);
	if (rc == -1) {
		printf("Fstat error\n");
		return ret;
	}

	if (statbuf.st_size % 16 == 0)
		return 0;

	printf("Adjust file's size ('%s') to be a multiple of 16 - needed by AES algorithm.\n", file_name);
	size_pad = ((statbuf.st_size + 15) & ~15);
	rc = ftruncate(fdin, size_pad);
	if(rc == -1)
	{
		printf("Truncate operation failed. Please check again the input key files \
			(properties, access settings etc)\n");
		return ret;
	}

	rc = close(fdin);
	if (rc == -1) {
		printf("Close input file failed.\n");
		return ret;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	char *key_file = NULL;
    char *blob_file = NULL;
	char *input_file = NULL;
	char *encrypted_file = NULL;
	char *decrypted_file = NULL;
	char *key_color;

	const char *op = argc >= 2 ? argv[1] : NULL;

	if (argc < 2)
		goto out_usage;

	if (!strcmp(op, "encap")) {
		if (argc < 5)
			goto out_usage;
		key_color = argv[2];
		key_file = argv[3];
		blob_file = argv[4];
		roundup(key_file);
	} else if (!strcmp(op, "decap")) {
		if (argc < 5)
			goto out_usage;
		key_color = argv[2];
		blob_file = argv[3];
		key_file = argv[4];
	} else if (!strcmp(op, "encr")){
		if (argc < 6)
			goto out_usage;
		key_color = argv[2];
		blob_file = argv[3];
		input_file = argv[4];
		encrypted_file = argv[5];
		roundup(input_file);
	} else if (!strcmp(op, "decr")) {
		if (argc < 6)
			goto out_usage;
		key_color = argv[2];
		blob_file = argv[3];
		encrypted_file = argv[4];
		decrypted_file = argv[5];
		} else
		goto out_usage;

	kb_fd = open("/dev/kb", O_RDWR);

	if(kb_fd < 0) {
		printf("kb open failed\n");
		return -1;
	}

	kb_addr.key_addr = malloc(KEY_MAX_LENGTH);
	if(!kb_addr.key_addr) {
		printf("mmap fail\n");
		return -1;
	}

	kb_addr.blob_addr = malloc(KEY_MAX_LENGTH + BLOB_OVERHEAD);
	if(!kb_addr.blob_addr) {
		printf("mmap fail\n");
		return -1;
	}

	ioctl(kb_fd, KB_IOCTL_SEND_VRT_ADDR, &kb_addr);

	if (!strcmp(op, "encap"))
		kb_encap_test(key_color, key_file, blob_file);

	if (!strcmp(op, "decap"))
		kb_decap_test(key_color, blob_file, key_file);

	if (!strcmp(op, "encr"))
		kb_encr_test(key_color, blob_file, input_file, encrypted_file);

	if (!strcmp(op, "decr"))
		kb_decr_test(key_color, blob_file, encrypted_file, decrypted_file);

	free((void *)kb_addr.key_addr);
	free((void *)kb_addr.blob_addr);

	close(kb_fd);

	goto out;

out_usage:
	kb_test_usage();

out:
	return 0;
}
