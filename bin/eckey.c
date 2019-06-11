// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    eckey.c
 *
 * @brief   Demo utility for exporting and importing
 *          black EC keys to/from blob.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>

struct kb_parameter {
	uint32_t key_len;
	uint32_t key_color;
	uint32_t key_cover;
	uint32_t blob_len;
};

struct kb_buffer {
	uint8_t *key_addr;
	uint8_t *blob_addr;
};

#define KB_IOCTL_ENCAP			_IOWR('K', 0, struct kb_parameter)
#define KB_IOCTL_DECAP			_IOWR('K', 1, struct kb_parameter)
#define KB_IOCTL_SEND_VRT_ADDR	_IOR('K', 2, struct kb_buffer)

#define STATUS_ERROR -1
#define STATUS_SUCCESS 0

#define BLOB_OVERHEAD	48
#define KEY_MAX_LENGTH	(512 - BLOB_OVERHEAD)
#define KEY_COLOR_RED	0x0
#define KEY_COLOR_BLACK	0x1
#define KEY_COVER_ECB	0x0
#define KEY_COVER_CCM	0x1
#define DATA_SIZE 32

int kb_fd;
struct kb_buffer kb_buff;

static EC_KEY *read_key(const char *pem_file)
{
	FILE *fb_key = NULL;
	EC_KEY *key = NULL;

	fb_key = fopen(pem_file, "r");
	if (!fb_key) {
		fprintf(stderr, "Error opening key file\n");
		goto out;
	}

	key = PEM_read_ECPrivateKey(fb_key, NULL, NULL, NULL);
	if (!key) {
		fprintf(stderr, "Error reading private key\n");
		goto out;
	}
out:
	if (fb_key)
		fclose(fb_key);
	return key;
}

static int export_key(const char *pem_file, const char *blob_file)
{
	int ret = STATUS_ERROR;
	FILE *fp_blob = NULL;
	struct kb_parameter param;
	EC_KEY *key = NULL;
	BIGNUM *d = NULL;

	if (!pem_file || !blob_file) {
		fprintf(stderr, "Invalid argument\n");
		goto out;
	}

	memset(kb_buff.key_addr, 0, KEY_MAX_LENGTH);
	memset(kb_buff.blob_addr, 0, KEY_MAX_LENGTH + BLOB_OVERHEAD);

	key = read_key(pem_file);

	if (!key) {
		fprintf(stderr, "Error reading key file\n");
		goto out;
	}

	d = (BIGNUM *)EC_KEY_get0_private_key(key);
	if (!d) {
		fprintf(stderr, "Error reading d\n");
		goto out;
	}

	param.key_len = BN_bn2bin(d, kb_buff.key_addr);

	if (param.key_len <= 0) {
		fprintf(stderr, "Error writing key to buffer\n");
		goto out;
	}

	param.key_cover = KEY_COVER_ECB;
	param.key_color = KEY_COLOR_BLACK;
	param.blob_len = param.key_len + BLOB_OVERHEAD;

	ioctl(kb_fd, KB_IOCTL_ENCAP, &param);

	fp_blob = fopen(blob_file, "wb");
	if (!fp_blob) {
		fprintf(stderr, "Error opening blob file\n");
		goto out;
	}

	fwrite(kb_buff.blob_addr, 1, param.blob_len, fp_blob);
	fclose(fp_blob);

	ret = STATUS_SUCCESS;

out:
	if (d)
		BN_free(d);
	if (key)
		EC_KEY_free(key);
	return ret;

}

static int import_key(const char *blob_file, const char *pem_file)
{
	int ret = STATUS_ERROR;
	FILE *fp_blob = NULL;
	struct kb_parameter param;
	FILE *fb_key = NULL;
	EC_KEY *key = NULL;
	BIGNUM *d = NULL;

	if ((!blob_file) || (!pem_file))
		return STATUS_ERROR;

	memset(kb_buff.key_addr, 0, KEY_MAX_LENGTH);
	memset(kb_buff.blob_addr, 0, KEY_MAX_LENGTH + BLOB_OVERHEAD);

	fp_blob = fopen(blob_file, "rb");
	if (fp_blob == NULL) {
		fprintf(stderr, "blob file open failed\n");
		goto out;
	}

	param.blob_len = fread(kb_buff.blob_addr, 1,
		KEY_MAX_LENGTH + BLOB_OVERHEAD, fp_blob);
	param.key_cover = KEY_COVER_ECB;
	param.key_color = KEY_COLOR_BLACK;

	fclose(fp_blob);

	if (param.blob_len <= BLOB_OVERHEAD) {
		fprintf(stderr, "blob file read failed\n");
		goto out;
	}

	param.key_len = param.blob_len - BLOB_OVERHEAD;

	ioctl(kb_fd, KB_IOCTL_DECAP, &param);

	d = BN_bin2bn(kb_buff.key_addr, param.key_len, NULL);

	if (!d) {
		fprintf(stderr, "Error setting d\n");
		goto out;
	}
	key = read_key(pem_file);

	if (!key) {
		fprintf(stderr, "Error reading key file\n");
		goto out;
	}

	if (!(EC_KEY_set_private_key(key, d))) {
		fprintf(stderr, "Error setting private key\n");
		goto out;
	}

	fb_key = fopen(pem_file, "w");
	if (!fb_key) {
		fprintf(stderr, "Error opening key file\n");
		goto out;
	}

	if (!(PEM_write_ECPrivateKey(fb_key, key, NULL, NULL, 0, NULL, NULL))) {
		fprintf(stderr, "Error writing key\n");
		goto out;
	}
out:
	if (d)
		BN_free(d);
	if (key)
		EC_KEY_free(key);

return ret;
}

int main(int argc, char *argv[])
{
	int ret = STATUS_ERROR;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <cmd>\n"
			"export : Export black key to a black blob\n"
			"import : Import black key from a black blob\n",
			argv[0]);
		goto out;
	}

	kb_fd = open("/dev/kb", O_RDWR);

	if (kb_fd < 0) {
		fprintf(stderr, "kb device open failed\n");
		goto out;
	}

	kb_buff.key_addr = malloc(KEY_MAX_LENGTH);
	if (!kb_buff.key_addr) {
		fprintf(stderr, "Error allocating memory\n");
		goto out;
	}

	kb_buff.blob_addr = malloc(KEY_MAX_LENGTH + BLOB_OVERHEAD);
	if (!kb_buff.blob_addr) {
		fprintf(stderr, "Error allocating memory\n");
		goto out;
	}

	ioctl(kb_fd, KB_IOCTL_SEND_VRT_ADDR, &kb_buff);

	if (strcmp(argv[1], "export") == 0) {
		if (argc < 4) {
			fprintf(
					stderr,
					"Usage %s %s </path/to/pem/key> </path/to/blob/key>\n",
					argv[0], argv[1]);
			goto out;
		}
		ret = export_key(argv[2], argv[3]);
	} else if (strcmp(argv[1], "import") == 0) {
		if (argc < 4) {
			fprintf(
					stderr,
					"Usage %s %s </path/to/blob/key> </path/to/pem/key>\n",
					argv[0], argv[1]);
			return STATUS_ERROR;
		}

		ret = import_key(argv[2], argv[3]);
	}

out:
	if (kb_buff.key_addr)
		free((void *)kb_buff.key_addr);
	if (kb_buff.blob_addr)
		free((void *)kb_buff.blob_addr);

	close(kb_fd);

	return ret;
}
