// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 *
 * Author: Gaurav Jain <gaurav.jain@nxp.com>
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <linux/socket.h>
#include "app.h"

/**
 * print_help - print application help
 */
void print_help(char *app)
{
	printf("Application usage: %s [options]\n", app);
	printf("Options:\n");
	printf("        <blob_name> <enc_algo> <input_file> <output_file>\n");
	printf("        <blob_name> the absolute path of the file that contains the ddek_black_blob\n");
	printf("        <enc_algo> can be AES-256-CBC\n");
	printf("        <input_file> the absolute path of the file that contains input data\n"
		"                     initialization vector(iv) of 16 bytes prepended\n"
		"                     size of input file must be multiple of 16\n");
	printf("        <output_file> the absolute path of the file that contains output data\n");
	return;
}

/**
 * get_fd_socket - get file descriptor for a new socket
 *
 * @sa              : The information about the algorithm we want to use for
 *                    encryption or decryption
 *
 * Return           : file descriptor on success, -1 otherwise
 */
int get_fd_socket(struct sockaddr_alg sa)
{
	int sock_fd, err;

	/*
	 * AF_ALG is the address family we use to interact with Kernel
	 * Crypto API. SOCK_SEQPACKET is used because we always know the
	 * maximum size of our data (no fragmentation) and we care about
	 * getting things in order in case there are consecutive calls
	 */
	sock_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (sock_fd < 0) {
		printf("Failed to allocate socket\n");
		return -1;
	}

	err = bind(sock_fd, (struct sockaddr *)&sa, sizeof(sa));
	if (err) {
		printf("Failed to bind socket, alg may not be supported\n");
		close(sock_fd);
		return -EAFNOSUPPORT;
	}

	return sock_fd;
}

/**
 * caam_import_black_key - Import black key from black blob using caam-keygen app
 *
 * @blob_name       : absolute path of the file that conatins the black blob
 *
 * Return           : '0' on success, -1 otherwise
 */
int caam_import_black_key(char *blob_name)
{
	pid_t cpid, w;
	int status;
	char *argv[] = {CAAM_KEYGEN_APP, CAAM_KEYGEN_IMPORT, NULL, KEY_NAME, NULL};

	argv[2] = blob_name;
	/*
	* Command to be execute, to create a black key is:
	* /usr/bin/caam-keygen import <blob_name> <key_name>
	* where:
	* <blob_name> the absolute path of the file that contains the blob
	* <key_name> the name of the file that will contain the black key.
	*/
	cpid = fork();
	if (cpid == -1) {
		printf("Failed to fork process.\n");
		return -1;
	}

	if (cpid == 0) {
		/* Execute command to import black key at KEY_LOCATION */
		if (execvp(argv[0], argv) < 0) {
			printf("Failed to execute command.\n");
			return -1;
		}
	} else {
		/* Wait for process to finish execution */
		do {
			w = waitpid(cpid, &status, WUNTRACED | WCONTINUED);
			if (w == -1) {
				printf("Fail to wait for process to finish execution.\n");
				return -1;
			}
		} while (!WIFEXITED(status) && !WIFSIGNALED(status));
	}
	return 0;
}

/**
 * skcipher_crypt - Encryption or decryption of an input
 *
 * @tfmfd           : The file descriptor for socket
 * @vec             : structure that contains key, iv, ptext/ctext.
 * @encrypt         : Used to determine if it's an encryption or decryption
 *                    operation
 * @output          : The output from encryption/decryption
 *
 * Return           : '0' on success, -1 otherwise
 */
int skcipher_crypt(int tfmfd, const struct aes_cipher *vec, bool encrypt, char *output)
{
	int opfd, err;
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	struct af_alg_iv *af_alg_iv;
	struct iovec iov;
	char cbuf[CMSG_SPACE(4) + CMSG_SPACE(20)] = {0};

	/* Set socket options for key */
	err = setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, vec->key, vec->klen);
	if (err) {
		printf("Failed to set socket key, err = %d\n", err);
		return err;
	}

	/*
	 * Once it's "configured", we tell the kernel to get ready for
	 * receiving some requests
	 */
	opfd = accept(tfmfd, NULL, 0);
	if (opfd < 0) {
		printf("Failed to open connection for the socket\n");
		return -EBADF;
	}

	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(__u32 *)CMSG_DATA(cmsg) = encrypt ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(20);

	af_alg_iv = (void *)CMSG_DATA(cmsg);
	af_alg_iv->ivlen = 16;
	memcpy(af_alg_iv->iv, vec->iv, af_alg_iv->ivlen);

	iov.iov_base = encrypt ? vec->ptext : vec->ctext;
	iov.iov_len = vec->len;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/*
	 * Start sending data to the opfd and read back
	 * from it to get our encrypted/decrypted data
	 */
	if (sendmsg(opfd, &msg, 0) < 0) {
		printf("Failed to send message.\n");
		return -1;
	}
	if (read(opfd, output, vec->len) < 0) {
		printf("Failed to read.\n");
		return -1;
	}
	close(opfd);
	return 0;
}

/**
 * store_decrypted_data - store the decrypted data in a file
 *
 * @file            : absolute path of the file that will contain output data
 * @output_text     : pointer to output data buffer
 * @len             : length of output data buffer
 *
 * Return           : '0' on success, -1 otherwise
 */
int store_decrypted_data(char *file, char *output_text, unsigned int len)
{
	FILE *fp;

	fp = fopen(file, "wb");
	if (!fp) {
		printf("Failed to create %s.\n", file);
		return -1;
	}

	if (fwrite(output_text, sizeof(char), len, fp) != len) {
		printf("Failed to write in %s.\n", file);
		fclose(fp);
		return -1;
	}

	fclose(fp);
	return 0;
}

/**
 * read_file - read file in a buffer
 *
 * @file            : the absolute path of the file
 * @buf             : double ptr to buffer that contain the data read from file
 * @len             : length of file to be read
 *
 * Return           : '0' on success, -1 otherwise
 */
int read_file(char *file, char **buf, unsigned int *len)
{
	FILE *fp;
	struct stat file_st;

	/* Get file size */
	if (stat(file, &file_st)) {
		printf("Failed to get file status.\n");
		return -1;
	}
	*len = file_st.st_size;

	fp = fopen(file, "rb");
	if (!fp) {
		printf("Failed to open file.\n");
		return -1;
	}

	*buf = calloc(*len, sizeof(char));
	if (*buf == NULL) {
		printf("Failed to allocate memory.\n");
		fclose(fp);
		return -1;
	}

	if (fread(*buf, sizeof(char), *len, fp) != *len) {
		printf("Failed to read data from file.\n");
		free(*buf);
		fclose(fp);
		return -1;
	}

	fclose(fp);
	return 0;
}

int main(int argc, char *argv[])
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",	/* selects the symmetric cipher */
		.salg_name = "tk(cbc(aes))"	/* this is the cipher name */
	};
	int sock_fd, ret = 0;
	bool decrypt_op = false;
	char *key_file = NULL, *blob, *algo, *file_enc, *file_dec;
	char *cipher_text, *output_text;
	struct aes_cipher vec;

	if (argc != 5) {
		print_help(argv[0]);
		return 0;
	}

	algo = argv[2];
	if (strcmp(algo, "AES-256-CBC")) {
		printf("encryption algo not supported\n");
		print_help(argv[0]);
		return -1;
	}

	/* Import black key(ECB or CCM) from black blob */
	blob = argv[1];
	ret = caam_import_black_key(blob);
	if (ret) {
		printf("Failed to import black key from black blob.\n");
		return ret;
	}

	/* Read black key from key file(KEY_NAME) */
	key_file = malloc(strlen(KEY_NAME) + strlen(KEY_LOCATION) + 1);
	if (!key_file) {
		printf("Failed to allocate memory for key file.\n");
		return -1;
	}
	strcpy(key_file, KEY_LOCATION);
	strcat(key_file, KEY_NAME);

	ret = read_file(key_file, &vec.key, &vec.klen);
	if (remove(key_file)) {
		printf("Failed to remove file %s.\n", key_file);
	}
	free(key_file);
	if (ret) {
		printf("Failed to read key file or file doesn't exist.\n");
		return ret;
	}

	/* Read iv and encrypted data from input file */
	file_enc = argv[3];
	ret = read_file(file_enc, &cipher_text, &vec.len);
	if (ret) {
		printf("Failed to read enc file or file doesn't exist.\n");
		free(vec.key);
		return ret;
	}
	vec.iv = cipher_text;
	vec.ctext = cipher_text + IV_LEN;
	vec.len = vec.len - IV_LEN;
	if (vec.len % 16 != 0) {
		printf("Error: AES Data size is not valid.\n");
		free(cipher_text);
		free(vec.key);
		return -1;
	}

	output_text = calloc(vec.len, sizeof(char));
	if (!output_text) {
		printf("Failed to allocate memory for output text.\n");
		free(cipher_text);
		free(vec.key);
		return -1;
	}

	/* tk(cbc(aes)) algorithm */
	sock_fd = get_fd_socket(sa);
	if (sock_fd < 0) {
		free(output_text);
		free(cipher_text);
		free(vec.key);
		return -1;
	}

	/* Decryption */
	ret = skcipher_crypt(sock_fd, &vec, decrypt_op, output_text);
	if (ret) {
		printf("Failed to decrypt.\n");
		goto exit;
	}

	/* Write decrypted data in output file */
	file_dec = argv[4];
	ret = store_decrypted_data(file_dec, output_text, vec.len);

exit:
	close(sock_fd);
	free(output_text);
	free(cipher_text);
	free(vec.key);

	return ret;
}
