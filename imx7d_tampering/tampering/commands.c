/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>

#include "tpsv.h"
#include "utils.h"
#include "commands.h"
#include "mem.h"

#define DISP_BYTES 		0x40
#define DISP_BYTE 		0x01
	
void md(unsigned int address_offset, int n) 
{
	volatile int i;
	for (i = 0; i < 4*n; i += 4) {
		
		if (i%16 == 0) {
			
			if (i) {
				printf("\n");
			}
			printf("%x: %08x ", SNVS_BASE_ADDR+address_offset+i, read_mem(address_offset+i));
		} else {
			printf("%08x ", read_mem(address_offset+i));
		}
	}
	if ((i-4)%16 != 0)
		printf("\n");
}

void mw(unsigned int address_offset, unsigned int value)
{
	write_mem(value, address_offset);
	volatile int i = 0;
	for (i = 0; i < TIMEOUT_MAX_VAL; i++){}
}

void do_run_secvconf(int argc, char * const argv[])
{
	char** params = get_contiguous_matrix(6, 32);
	int number_of_parts;
	char commands[7][128] = { 
		{"tpsv set_sv_cfg sec_vio_0 enabled non-fatal enabled"},
		{"tpsv set_sv_cfg sec_vio_1 enabled non-fatal enabled"},
		{"tpsv set_sv_cfg sec_vio_2 enabled non-fatal enabled"},
		{"tpsv set_sv_cfg sec_vio_3 enabled non-fatal enabled"},
		{"tpsv set_sv_cfg sec_vio_4 enabled non-fatal enabled"},
		{"tpsv set_sv_cfg sec_vio_5 enabled non-fatal enabled"},
		{"tpsv set_sv_cfg sec_vio_lp enabled non-fatal enabled"} 
	};
	for (unsigned char i = 0; i < 7; i++) {
		split_words(commands[i], params, &number_of_parts);
		do_set_sv_cfg(NULL, 0, argc, argv, params);
	}
}

void do_run_sectpconf(int argc, char * const argv[])
{
	char** params = get_contiguous_matrix(8, 32);
	int number_of_parts;
	char commands[10][128] = { 
		{"tpsv set_tp_cfg et_1 passive enabled 0 disabled 0"},
		{"tpsv set_tp_cfg et_2 passive enabled 0 disabled 0"},
		{"tpsv set_tp_cfg et_3 passive enabled 0 disabled 0"},
		{"tpsv set_tp_cfg et_4 passive enabled 0 disabled 0"},
		{"tpsv set_tp_cfg et_5 passive enabled 0 disabled 0"},
		{"tpsv set_tp_cfg et_6 passive enabled 0 disabled 0"},
		{"tpsv set_tp_cfg et_7 passive enabled 0 disabled 0"},
		{"tpsv set_tp_cfg et_8 passive enabled 0 disabled 0"},
		{"tpsv set_tp_cfg et_8 passive enabled 0 disabled 0"},
		{"tpsv set_tp_cfg et_10 passive enabled 0 disabled 0"}
	};
	for (unsigned char i = 0; i < 10; i++) {
		split_words(commands[i], params, &number_of_parts);
		do_set_tp_cfg_passive(NULL, 0, argc, argv, params);
	}
}

void do_run_loadsecconf(int argc, char * const argv[]){
	do_run_secvconf(argc, argv);
	do_run_sectpconf(argc, argv);
}

#if defined(CONFIG_IMX7)
void do_run_set_passive_tamp(int argc, char * const argv[]){
	md(HPLR, DISP_BYTES);
	printf("reset PGD\n");
	
	mw(LPPGDR, LPPGDR_VAL);
	mw(LPSR, LPSR_VAL);
	mw(HPCOMR, HPCOMR_VAL);
	
	do_run_secvconf(argc, argv);
	do_run_sectpconf(argc, argv);
	md(HPLR, DISP_BYTES);
}


void do_run_set_act_tamp(int argc, char * const argv[]){

	md(HPLR, DISP_BYTES);
	mw(LPPGDR, LPPGDR_VAL);
	mw(LPSR, LPSR_VAL);
	mw(HPCOMR, HPCOMR_VAL);
	
	char** params = get_contiguous_matrix(8, 32);
	int number_of_parts;
	char commands[11][128] = { 
		{"tpsv set_sv_cfg sec_vio_lp enabled non-fatal enabled"},
		{"tpsv set_tp_cfg at_5 active_out enabled 16 43072 21845"},		
		{"tpsv set_tp_cfg et_1 active_in enabled enabled 0 at_5"},
		{"tpsv set_tp_cfg at_4 active_out enabled 16 34176 17476"},
		{"tpsv set_tp_cfg et_2 active_in enabled enabled 0 at_4"},
		{"tpsv set_tp_cfg at_3 active_out enabled 16 51712 13107"},
		{"tpsv set_tp_cfg et_3 active_in enabled enabled 0 at_3"},
		{"tpsv set_tp_cfg at_2 active_out enabled 16 39936 8738"},
		{"tpsv set_tp_cfg et_4 active_in enabled enabled 0 at_2"},
		{"tpsv set_tp_cfg at_1 active_out enabled 16 33792 4369"},
		{"tpsv set_tp_cfg et_5 active_in enabled enabled 0 at_1"}
	};
	split_words(commands[0], params, &number_of_parts);
	do_set_sv_cfg(NULL, 0, argc, argv, params);
	
	md(HPLR, DISP_BYTES);
	for (unsigned char i = 1; i < 11; i++) {
		split_words(commands[i], params, &number_of_parts);
		
		if(i%2 != 0) {
			do_set_tp_cfg_active_out(NULL, 0, argc, argv, params);
		} else {
			do_set_tp_cfg_active_in(NULL, 0, argc, argv, params);
		}
	}
	mw(LPCR, LPCR_VAL);
}


void do_run_check_tamp_status(int argc, char * const argv[])
{
	md(LPTDSR, DISP_BYTE);
	printf("\n");
	md(LPSR, DISP_BYTE);
	printf("\n");
	md(HPSVSR, DISP_BYTE);
	printf("\n");

	printf("\nZMK address and value: \n");
	md(LPZMKR0, DISP_BYTE);
	printf("\n");
}

void do_run_check_SRTC(int argc, char * const argv[])
{
	md(LPSRTCMR, DISP_BYTE);
	printf("\n");
	md(LPSRTCLR, DISP_BYTE);
	printf("\n");
}
#endif

char info1[] = 
	"Tamper and security violation configuration tool \
	\n \
	The tampers and security violations can be configured with this tool.\n\
	It is also possible to view the current configuration.\n\
	\n\
	The main functions to use are the following:\n\
	 - tpsv showcfg\n\
	 - tpsv get_sv_cfg [....]\n\
	 - tpsv set_sv_cfg [....]\n\
	 - tpsv get_tp_cfg [....]\n\
	 - tpsv set_tp_cfg [....]\n\
	\n\
	further explanation about the functions is available below:\n\
	\n\
	showcfg: Display the current configuration\n\
	\n\
	get_sv_cfg <source>: Print the configuration of a security violation. The sec_vio_X are triggered by the sec_port_X. The sec_vio_lp is triggered by the tamper detectors\n\
		source: The security violation\n\
			[sec_vio_0|sec_vio_1|sec_vio_2|sec_vio_3|sec_vio_4|sec_vio_5|sec_vio_lp]\n\
	\n\
		Ex: tpsv get_sv_cfg sec_vio_lp\n\
	\n\
	set_sv_cfg <source> <enable> <policy> <irq_enable>: Configure a security violation. NOTE: sec_vio_lp is always enabled even if diplayed otherwise\n\
		source: The security violation\n\
			[sec_port_0|sec_port_1|sec_port_2|sec_port_3|sec_port_4|sec_port_5|sec_vio_lp]\n\
		enable: If the security violation should be processed\n\
			[enabled|disabled]\n\
		policy: The effect on the internal SNVS state machine\n\
			[disabled|non-fatal|fatal]\n\
		irq_enable: If the security violation should trigger an interrupt to be handled\n\
			[enabled|disabled]\n\
	\n\
		Ex: tpsv set_sv_cfg sec_vio_lp enabled non-fatal enabled\
	\n\
	get_tp_cfg <tamper>: Display the configuration of a tamper";
	
#if defined(CONFIG_IMX7)
char info2[] = ", the polynomial and seed can't be read so a default value is displayed";
#endif

char info3[] = "\n\
		tamper: A tamper\n\
			[tamper_1(et_1)|tamper_2(et_2)";
			
#if defined(CONFIG_IMX7)
char info4[] = "|tamper_3(et_3)|tamper_4(et_4)|tamper_5(et_5)|\n\
				tamper_6(et_6)(at_1)|tamper_7(et_7)(at_2)|tamper_8(et_8)(at_3)|tamper_9(et_9)(at_4)|tamper_10(et_10)(at_5)";
#endif

char info5[] = "]\n\
	\n\
		Ex: tpsv get_tp_cfg et_1\n\
	\n\
	set_tp_cfg <tamper> <mode> [....]: Configure a tamper\n\
		tamper: A tamper\n\
			[tamper_1(et_1)|tamper_2(et_2)";
			
#if defined(CONFIG_IMX7)
char info6[] = "|tamper_3(et_3)|tamper_4(et_4)|tamper_5(et_5)|\n\
				tamper_6(et_6)(at_1)|tamper_7(et_7)(at_2)|tamper_8(et_8)(at_3)|tamper_9(et_9)(at_4)|tamper_10(et_10)(at_5)";
#endif

char info7[] = "]\n\
		mode: The type of the tamper\n\
			[passive";
			
#if defined(CONFIG_IMX7)
char info8[] = "|active_in|active_out";
#endif

char info9[] = "]\n\
	\n\
		set_tp_cfg <tamper> passive <enable> <polarity> <gf_enable> <gf_value>: Configure a passive tamper to compare against a polarity\n\
			enable: If the tamper should trigger a sev_vio_lp\n\
				[enabled|disabled]\n\
			polarity: The value on which the tamper will trigger a sev_vio_lp\n\
				[0|1]\n\
			gf_enable: If the glitch filter should be enabled\n\
				[enabled|disabled]\n\
			gf_value: The margin introduced by the glitch filter, the value is multiplied by 7,8ms\n\
				between 0 and 127\n\
	\n\
			Ex: tpsv set_tp_cfg tamper_4 passive enabled 0 disabled 24\n";
			
#if defined(CONFIG_IMX7)
	char info10[] = "\n\
		set_tp_cfg <tamper> active_in <enable> <gf_enable> <gf_value> <at_source>: Configure a tamper to compare against an active tamper\n\
			enable: If the tamper should trigger a sev_vio_lp\n\
				[enabled|disabled]\n\
			gf_enable: If the glitch filter should be enabled\n\
				[enabled|disabled]\n\
			gf_value: The margin introduced by the glitch filter, the value is multiplied by 7,8ms\n\
				between 0 and 127\n\
			at_source: An active tamper\n\
				[tamper_6(et_6)(at_1)|tamper_7(et_7)(at_2)|tamper_8(et_8)(at_3)|tamper_9(et_9)(at_4)|tamper_10(et_10)(at_5)]\n\
	\n\
			Ex: tpsv set_tp_cfg tamper_7 active_in enabled disabled 42 at_1\n\
	\n\
		set_tp_cfg <tamper> active_out <enable> <at_freq> <at_poly> <at_seed>: Configure an active tamper to generate a pattern\n\
			enable: If the tamper should generate a pattern\n\
				[enabled|disabled]\n\
			at_freq: The frequency at which each bit of the pattern must be sent\n\
				[2|4|8|16]\n\
			at_poly: The polynomial used by the LFSR\n\
				between 1 and 65535\n\
			at_seed: The initial state of the LFSR\n\
				between 1 and 65535\n\
	\n\
			Ex: tpsv set_tp_cfg at_5 active_out enabled 16 2000 3000\n\
	\n";
#endif

#if defined(CONFIG_IMX7)
void print_info_MX7() 
{
	printf("%s%s%s%s%s%s%s%s%s%s", info1, info2, info3, info4, info5, info6, info7, info8, info9, info10);
}
#endif

void print_info() 
{
	printf("%s%s%s%s%s", info1, info3, info5, info7, info9);
}

