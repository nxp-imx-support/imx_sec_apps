// SPDX-License-Identifier: GPL-2.0
/**
 * @copyright 2020 NXP
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
#include <sys/stat.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>

#define STATUS_ERROR  -1
#define STATUS_SUCCESS 0

#define BLOB_OVERHEAD  48
#define MAX_KEY_LEN   (512 - BLOB_OVERHEAD)
#define MAX_BLOB_LEN  (MAX_KEY_LEN + BLOB_OVERHEAD)

static uint8_t skeymod[] = {
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
};

struct caam_blob_data {
    uint8_t *key;
    size_t key_len;
    uint8_t *blob;
    size_t blob_len;
    uint8_t *keymod;
    size_t keymod_len;
};

#define CAAM_BLOB_ENCAP _IOWR('I', 0, \
        struct caam_blob_data)

#define CAAM_BLOB_DECAP _IOWR('I', 1, \
        struct caam_blob_data)

static int bfd;

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
    EC_KEY *key = NULL;
    BIGNUM *d = NULL;
    struct caam_blob_data blob_data;

    if (!pem_file || !blob_file) {
        fprintf(stderr, "Invalid argument\n");
        goto out;
    }

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

    blob_data.key_len = BN_num_bytes(d);

    if ( blob_data.key_len <= 0) {
        fprintf(stderr, "Error writing key to buffer\n");
        goto out;
    }

    blob_data.key = malloc(blob_data.key_len);

    if (!blob_data.key) {
        fprintf(stderr, "Error allocating memory for key\n");
        goto out;
    }

    if(BN_bn2bin(d, blob_data.key) != blob_data.key_len) {
        fprintf(stderr, "BN_bn2bin(d) failed\n");
        goto out;
    }

    blob_data.blob_len = blob_data.key_len + BLOB_OVERHEAD;

    blob_data.blob = malloc(blob_data.blob_len);

    if (!blob_data.blob) {
        fprintf(stderr, "Error allocating memory for blob\n");
        goto out;
    }

    memset(blob_data.blob, 0, MAX_BLOB_LEN);

    blob_data.keymod = &skeymod[0];
    blob_data.keymod_len  = sizeof(skeymod) / sizeof((skeymod)[0]);

    ioctl(bfd, CAAM_BLOB_ENCAP, &blob_data);

    fp_blob = fopen(blob_file, "wb");
    if (!fp_blob) {
        fprintf(stderr, "Error opening blob file\n");
        goto out;
    }

    fwrite(blob_data.blob, 1, blob_data.blob_len, fp_blob);
    fclose(fp_blob);

    ret = STATUS_SUCCESS;

out:
    if (blob_data.key)
        free(blob_data.key);
    if (blob_data.blob)
        free(blob_data.blob);
    return ret;
}

static int import_key(const char *blob_file, const char *pem_file)
{
    int ret = STATUS_ERROR;
    FILE *fp_blob = NULL;
    FILE *fb_key = NULL;
    EC_KEY *key = NULL;
    BIGNUM *d = NULL;
    struct caam_blob_data blob_data;
    struct stat st;

    if ((!blob_file) || (!pem_file))
        return STATUS_ERROR;

    fp_blob = fopen(blob_file, "rb");
    if (fp_blob == NULL) {
        fprintf(stderr, "blob file open failed\n");
        goto out;
    }

    stat(blob_file, &st);
    blob_data.blob_len = st.st_size;

    if (blob_data.blob_len <= BLOB_OVERHEAD) {
        fprintf(stderr, "blob file read failed\n");
        goto out;
    }

    blob_data.blob = malloc(blob_data.blob_len);

    if (!blob_data.blob) {
        fprintf(stderr, "Error allocating memory for blob\n");
        goto out;
    }

    blob_data.key_len = blob_data.blob_len - BLOB_OVERHEAD;

    blob_data.key = malloc(blob_data.key_len);

    if (!blob_data.key) {
        fprintf(stderr, "Error allocating memory for key\n");
        goto out;
    }

    memset(blob_data.key, 0, blob_data.key_len);

    blob_data.blob_len = fread(blob_data.blob, sizeof(uint8_t),
        blob_data.blob_len, fp_blob);

    if ( ferror( fp_blob ) != 0 ) {
        fprintf(stderr, "blob file read failed\n");
        goto out;
    }

    fclose(fp_blob);

    blob_data.keymod = &skeymod[0];
    blob_data.keymod_len  = sizeof(skeymod) / sizeof((skeymod)[0]);

    ioctl(bfd, CAAM_BLOB_DECAP, &blob_data);

    d = BN_bin2bn(blob_data.key, blob_data.key_len, NULL);

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

    ret = STATUS_SUCCESS;

out:
    if (blob_data.key)
        free(blob_data.key);
    if (blob_data.blob)
        free(blob_data.blob);

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
        return STATUS_SUCCESS;
    }

    bfd = open("/dev/caam_blob", O_RDWR);

    if (bfd < 0) {
        fprintf(stderr, "caam_blob device open failed\n");
        goto out;
    }

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

    ret = STATUS_SUCCESS;

out:
    if(ret != STATUS_SUCCESS) {
        fprintf(stderr, "Error\n");
    }
    close(bfd);

    return ret;
}
