/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef COMMANDS_H_
#define COMMANDS_H_

void do_run_secvconf(int argc, char * const argv[]);
void do_run_sectpconf(int argc, char * const argv[]);
void do_run_loadsecconf(int argc, char * const argv[]);
#if defined(CONFIG_IMX7)
void do_run_set_passive_tamp(int argc, char * const argv[]);
void do_run_set_act_tamp(int argc, char * const argv[]);
void do_run_check_tamp_status(int argc, char * const argv[]);
void do_run_check_SRTC(int argc, char * const argv[]);
#endif

void print_info_MX7();
void print_info();

#endif
