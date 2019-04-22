/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef UTILS_H_
#define UTILS_H_

typedef struct node_
{
	char *data;
	struct node_ *next;
	struct node_ *prev;
}node;

node *init_node();
void trim_spaces(char *command);
void autocomplete(char *command);
void read_command(char **command);
char **get_contiguous_matrix(int height, int width);
void split_words(char *command, char **command_parts, int *number_of_words);
void free_memory(node *head);

#endif
