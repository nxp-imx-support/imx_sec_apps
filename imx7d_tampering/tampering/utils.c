/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdlib.h> 
#include <stdio.h>
#include <string.h>

#include "utils.h"

#define MAX_COMMAND_SIZE 256
#define CARRIAGE_RETURN 13
#define HORIZONTAL_TAB 9
#define HASHTAG 35
#define END_OF_TEXT 3
#define DEL 127
#define ESCAPE 27

node *head = NULL;
node *previous = NULL;
node *current = NULL;
node *curs = NULL;

char** get_contiguous_matrix(int height, int width)
{
	char* array = (char*)malloc(height*width*sizeof(char));
	char** matrix = (char**)malloc(height*sizeof(char*));
	for (int i = 0; i < height; i++) {
		matrix[i] = &(array[i*width]);
	}
	return matrix;
}

void trim_spaces(char* command)
{
    unsigned char i;
    unsigned char count = 1;
    
    for (i = 1; (*(command+i) != '\0') && i < 256; i++) {
	    
        if (*(command+i)!=' ' || *(command+i-1)!=' ') {
			*(command+count++) = *(command+i);
		}
    }	
    *(command+count) = '\0';
}

void split_words(char* command, char** command_parts, int* number_of_words)
{
	unsigned char index_in_word = 0;
	*(number_of_words) = 0;
	unsigned char i;
	i = *command == ' ' ? 1 : 0;
	while (*(command+i) != '\0') {
		
		if (*(number_of_words) >= 31) {
			*(command) = '\0';
			return;
		}
		
		if (*(command+i)==' ') {
			
			if (index_in_word!= 0) {	
				command_parts[*(number_of_words)][index_in_word] = '\0';
				index_in_word = 0;
				*(number_of_words) = *(number_of_words) + 1;
			}
		} else {
			command_parts[*(number_of_words)][index_in_word] = *(command+i);
			index_in_word++;
		}
		i++;
	}
	if (*(command+i-1) != ' ') {
		command_parts[*(number_of_words)][index_in_word]='\0';
		*(number_of_words) = *(number_of_words)+1;
	}
}

void read_command(char** command)
{
	if (!head){
		head = init_node();
		previous = head;
		printf("Press '#' to exit\n");
	}
	current = init_node();
	previous->next = current;
	current->prev = previous;
	curs = current;
	printf("=>");
	fflush(stdout);
	char *str = (char*)malloc(sizeof(char)*MAX_COMMAND_SIZE);
	char *tmp = (char*)malloc(sizeof(char)*MAX_COMMAND_SIZE);
	char ch;
	int i = 0;
	// Disable terminal buffering.
	// Characters will be sent to stdin as soon as they are typed
	#if QT5 == 0
	system("/bin/stty raw");
	#endif
	while(1) {
		ch = getchar();
		// When 'Enter' has been pressed with characters being taped, command is complete
		if ((ch == CARRIAGE_RETURN && i != 0) || i==MAX_COMMAND_SIZE-1) {
			break;
		// When 'Enter' has been pressed with no characters being taped, command prompt will appear again
		// and will listen for input
		}else if (ch == CARRIAGE_RETURN && i == 0){
			printf("\b\b  \n\r=>");
		// When 'Tab' has been pressed, suggested commands are shown 
		// If there is only one suggestion, it autocompletes the command
		}else if (ch == HORIZONTAL_TAB) {
			printf("\b\b\b\b\b\b");
			str[i] = 0;
			autocomplete(str);
			
			if (i == strlen(str)) {
				printf("\n\r=>%s", str);
			} else {
				printf("\r=>%s", str);
			}
			i = strlen(str);
		// When either '#' or 'End of text' is pressed, the program stops
		}else if (ch == HASHTAG || ch == END_OF_TEXT) {
			system("/bin/stty cooked");
			free_memory(head);
			free(str);
			free(tmp);
			printf("\n");
			exit(1);
		// When 'DEL' is pressed, it deletes the last characters written if it exists
		}else if (ch == DEL) {
			
			if (i) {
				printf("\b\b\b   \b\b\b");
				i--;
			} else {
				printf("\b\b  \b\b");
			}
		// When 'Escape' is pressed, it means that a special character or a combination of characters is pressed
		// Cases that are interpreted here: up/down arrow
		}else if (ch == ESCAPE) {
			// Catch the '[' 
			getchar();
			ch = getchar();
			switch(ch) {
			// Up arrow pressed
			case 'A':
				printf("\b\b\b\b    \b\b\b\b");
				
				if (curs->prev != head) {
					curs = curs->prev;
					
					if (current->data == NULL) {
						str[i] = 0;
						strcpy(tmp, str);
						current->data = tmp;
					}
					int j=0;
					while (j++ < i) 
						printf("\b");
					j=0;
					while (j++ < i) 
						printf(" ");
					j=0;
					while (j++ < i) 
						printf("\b");
					strcpy(str, curs->data);
					printf("%s", str);
					i = strlen(str);
				}
				break;
			// Down arrow pressed
			case 'B':
				printf("\b\b\b\b    \b\b\b\b"); 
				
				if (curs != current) {
					curs = curs->next;
					int j=0;
					while (j++ < i)
						printf("\b");
					j=0;
					while (j++ < i)
						printf(" ");
					j=0;
					while (j++ < i)
						printf("\b");
					strcpy(str, curs->data);
					printf("%s", str);
					i = strlen(str);
				}
				break;
			default:
				printf("\b\b\b\b    \b\b\b\b");
			}
		} else {
			current->data = NULL;
			curs = current;
			str[i] = ch;
			i++;
		} 
    }
	str[i] = 0;
	printf("\b\b  \b\b");
	// Bring back the terminal buffer
	#if QT5 == 0
	system("/bin/stty cooked");
	#endif
	printf("\n");
	current->data = str;
	previous = current;
	*(command)=str;
}

node* init_node()
{
	node *n = (node*)malloc(sizeof(node));
	n->data = NULL;
	n->next = NULL;
	n->prev = NULL;
	return n;
}

void autocomplete(char *command)
{
	static char commands[][32] = {
		{"tpsv"},
		{"tpsv showcfg"},
		{"tpsv get_sv_cfg"},
		{"tpsv set_sv_cfg"},
		{"tpsv get_tp_cfg"},
		{"tpsv set_tp_cfg"},
		{"run secsvconf"},
		{"run sectpconf"},
		{"run loadsecconf"},
		#if defined(CONFIG_IMX7)
		{"run set_passive_tamp"},
		{"run set_act_tamp"},
		{"run check_tamp_status"},
		{"run check_SRTC"}
		#endif
	};
	char *matching[32];
	int number_of_commands = sizeof(commands)/sizeof(char[32]);
	int matching_number = 0;
	for (int i=0; i < number_of_commands; i++) {
		
		if (strstr(commands[i], command)) {
			matching[matching_number++] = commands[i];
		}
	}
	if(matching_number == 1) {
		strcpy(command, matching[0]);
	} else {
		for (int i = 0; i < matching_number; i++)
			printf("\n\r%s", matching[i]);
	}
	
}

void free_memory(node *head)
{
	node *curs = head;
	while(curs->next) {
		
		if (curs != head)
			free(curs->data);
		curs = curs->next;
	}
	while(curs->prev) {
		curs = curs->prev;
		free(curs->next);
	}
	free(curs);
}
