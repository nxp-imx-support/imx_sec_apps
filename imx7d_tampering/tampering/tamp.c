/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "tpsv.h"
#include "utils.h"
#include "commands.h"

#define MAX_COMMAND_LENGHT      256
#define MAX_PARAMETERS_NUMBER   32
#define MAX_WORD_LENGTH         32

int main(int argc, char* argv[])
{
	char** command_parts = get_contiguous_matrix(MAX_PARAMETERS_NUMBER, MAX_WORD_LENGTH);
	char* command = (char*)malloc(MAX_COMMAND_LENGHT*sizeof(char));
	int number_of_parts;
	while(1) {
		read_command(&command);
		
		if (*(command+1) == '\0' || *(command+2)  == '\0') {
			printf("Unknown command\n");
			continue;
		}
		
		trim_spaces(command);
		split_words(command, command_parts, &number_of_parts);
		
		if (*command == '\0') {
			printf("Invalid number of parameters\n");
			continue;
		}
		if (!strcmp(command_parts[0], "tpsv")) {
			
			if (number_of_parts == 1) {
				//Command: tpsv
				#if defined(CONFIG_IMX7)
					print_info_MX7();
				#else
					print_info();
				#endif
			} else if (!strcmp(command_parts[1],"showcfg")) {
				//Command: tpsv showcfg
				if (number_of_parts != 2) {
					printf("Wrong parameters for tpsv showcfg\n");
				} else {
					do_show_cfg(NULL, 0, argc, argv);
				}
			} else if (!strcmp(command_parts[1],"get_sv_cfg")) {
				//Command: tpsv get_sv_cfg sec_vio_lp
				if (number_of_parts != 3) {
					printf("Wrong parameters for tpsv get_sv_cfg\n");
				} else {
					do_get_sv_cfg(NULL, 0, argc, argv, command_parts[2]);
				}
			} else if (!strcmp(command_parts[1],"set_sv_cfg")) {
				//Command: tpsv set_sv_cfg sec_vio_lp enabled non-fatal enabled
				if (number_of_parts != 6) {
					printf("Wrong parameters for tpsv set_sv_cfg\n");
				} else {
					do_set_sv_cfg(NULL, 0, argc, argv, command_parts);
				}
			} else if (!strcmp(command_parts[1],"get_tp_cfg")) {
				//Command: tpsv get_tp_cfg et_1
				if (number_of_parts != 3) {
					printf("Wrong parameters for tpsv get_tp_cfg\n");
				} else {
					do_get_tp_cfg(NULL , 0, argc, argv, command_parts[2]);
				}
			} else if (!strcmp(command_parts[1],"set_tp_cfg")) {
				//Command: tpsv set_tp_cfg tamper_4 passive enabled 0 disabled 24
				//Command: tpsv set_tp_cfg tamper_7 active_in enabled disabled 42 at_1
				//Command: tpsv set_tp_cfg at_5 active_out enabled 16 2000 3000
				if (number_of_parts != 8) {
					printf("Wrong parameters for tpsv set_tp_cfg\n");
				} else {
					if (!strcmp(command_parts[3], "passive")) {
						do_set_tp_cfg_passive(NULL , 0, argc, argv, command_parts);
					}
					#if defined(CONFIG_IMX7)
					else if (!strcmp(command_parts[3], "active_in")) {	
						do_set_tp_cfg_active_in(NULL , 0, argc, argv, command_parts);
					} else if (!strcmp(command_parts[3], "active_out")) {	
						do_set_tp_cfg_active_out(NULL , 0, argc, argv, command_parts);
					}
					#endif
					else {						
						printf("Wrong parameters for tpsv set_tp_cfg\n");
					}
				}
			} else {
				printf("Unknown tpsv command %s\n", command_parts[1]);
			}
		}
		else if (!strcmp(command_parts[0], "run")) {
			
			if (number_of_parts == 2) {
				
				if (!strcmp(command_parts[1], "secsvconf")) {
					//Command: run secsvconf
					do_run_secvconf(argc, argv);
				} else if (!strcmp(command_parts[1], "sectpconf")) {
					//Command: run sectpconf
					do_run_sectpconf(argc, argv);
				} else if (!strcmp(command_parts[1], "loadsecconf")) {
					//Command: run loadsecconf
					do_run_loadsecconf(argc, argv);
				}
				#if defined(CONFIG_IMX7)
				else if (!strcmp(command_parts[1], "set_passive_tamp")) {
					//Command: run set_passive_tamp
					do_run_set_passive_tamp(argc, argv);
				} else if (!strcmp(command_parts[1], "set_act_tamp")) {
					//Command: run set_act_tamp
					do_run_set_act_tamp(argc, argv);
				} else if (!strcmp(command_parts[1], "check_tamp_status")) {
					//Command: run check_tamp_status
					do_run_check_tamp_status(argc, argv);
				} else if (!strcmp(command_parts[1], "check_SRTC")) {
					//Command: run check_SRTC
					do_run_check_SRTC(argc, argv);
				}
				#endif
				else {
					printf("Unknown run command %s\n", command_parts[1]);
				}
			} else {
				printf("Unknown run command\n");
			}
		} else {
			printf("Unknown command\n");
		}
		fflush(stdout);
    }
    return 0;
}
