
/*
 * Copyright (C) 2012-2015 Freescale Semiconductor, Inc., All Rights Reserved
 */

#include "key_blob.h"
#include "kb_test.h"

#define BLOB_OVERHEAD 	48
#define KEY_MAX_LENGTH 	(512 - BLOB_OVERHEAD)

#define KEY_COLOR_RED	0x0

#define KEY_COVER_ECB	0x0
#define KEY_COVER_CCM	0x1

#define DATA_SIZE 16

int kb_fd;
kb_addr_t kb_addr;

int size_pad(char file_name[])
{
	int rc;
	int fdin;
	int ret = -1;
	int size_pad;
	struct stat statbuf;

	fdin = open(file_name, O_RDWR | O_CREAT);
	if (fdin == -1) {
		printf("can not open the file %s\n", file_name);
		return ret;
	}

	rc = fstat(fdin, &statbuf);
	if (rc == -1) {
		printf("fstat\n");
		return ret;
	}

	if (statbuf.st_size % 16 == 0)
		return 0;

	printf("Adjust file's size ('%s') to be a multiple of 16.\n", file_name);
	size_pad = ((statbuf.st_size + 15) & ~15);
	rc = ftruncate(fdin, size_pad);
	if(rc == -1)
	{
		printf("truncate\n");
		return ret;
	}

	rc = close(fdin);
	if (rc == -1) {
		printf("close source\n");
		return ret;
	}

	return 0;
}

int initialise()
{
	
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
	goto out;
out:
	return 0;	
}

int kb_encap_test(char *key_color, char *key_file, char *blob_file)
{
	FILE *fp = NULL;
	kb_parameter_t parameter;
	int ret = -1;
	uint32_t i;

	if (initialise() == -1){
		printf("initialization failed\n");
		goto out;
		return ret;
	}

	size_pad(key_file);

	memset(kb_addr.key_addr, 0, KEY_MAX_LENGTH);
	memset(kb_addr.blob_addr, 0, KEY_MAX_LENGTH + BLOB_OVERHEAD);

	fp = fopen(key_file, "rb");
	if (fp == NULL) {
		printf("key file open failed\n");
		goto out;
		return ret;
	}

	parameter.key_len = fread(kb_addr.key_addr, 1, KEY_MAX_LENGTH, fp);
	parameter.key_cover = KEY_COVER_ECB;

	if (!strcmp(key_color, "red"))
		parameter.key_color = KEY_COLOR_RED;

	fclose(fp);

	if (parameter.key_len <= 0) {
		printf("key file read failed\n");
		goto out;
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
		goto out;
		return ret;
	}

	fwrite(kb_addr.blob_addr, 1, parameter.blob_len, fp);
out:
	if(fp)
		fclose(fp);
	free((void *)kb_addr.key_addr);
	free((void *)kb_addr.blob_addr);

	close(kb_fd);

	return 0;
}

int kb_decap_test(char *key_color, char *blob_file, char *key_file)
{
	FILE *fp = NULL;
	kb_parameter_t parameter;
	int ret = -1;
	uint32_t i;

	if (initialise() == -1){
		printf("initialization failed\n");
		goto out;
		return ret;
	}
	memset(kb_addr.key_addr, 0, KEY_MAX_LENGTH);
	memset(kb_addr.blob_addr, 0, KEY_MAX_LENGTH + BLOB_OVERHEAD);

	fp = fopen(blob_file, "rb");
	if (fp == NULL) {
		printf("blob file open failed\n");
		goto out;
		return ret;
	}

	parameter.blob_len = fread(kb_addr.blob_addr, 1, KEY_MAX_LENGTH + BLOB_OVERHEAD, fp);
	parameter.key_cover = KEY_COVER_ECB;

	if (!strcmp(key_color, "red"))
		parameter.key_color = KEY_COLOR_RED;

	fclose(fp);

	if (parameter.blob_len <= BLOB_OVERHEAD) {
		printf("blob file read failed\n");
		goto out;
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
		goto out;
		return ret;
	}

	fwrite(kb_addr.key_addr, 1, parameter.key_len, fp);
out:
	if(fp)
		fclose(fp);
	free((void *)kb_addr.key_addr);
	free((void *)kb_addr.blob_addr);

	close(kb_fd);

	return 0;
}
