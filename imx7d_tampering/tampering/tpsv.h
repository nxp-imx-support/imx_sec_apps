/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TPSV_H_
#define TPSV_H_

#define CMD_RET_FAILURE 0
#define CMD_RET_SUCCESS 1

struct cmd_tbl_s {
	char *name;		/* Command Name			*/
	int	maxargs;	/* maximum number of arguments	*/
	int	repeatable;	/* autorepeat allowed?		*/
					/* Implementation function	*/
	int	(*cmd)(struct cmd_tbl_s *, int, int, char * const []);
	char *usage;	/* Usage message	(short)	*/
#ifdef	CONFIG_SYS_LONGHELP
	char *help;		/* Help  message	(long)	*/
#endif
#ifdef CONFIG_AUTO_COMPLETE
					/* do auto completion on the arguments */
	int	(*complete)(int argc, char * const argv[], char last_char, int maxv, char *cmdv[]);
#endif
};

typedef struct cmd_tbl_s cmd_tbl_t;

int do_show_cfg (cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[]);
int do_get_sv_cfg (cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[], char* param);
int do_set_sv_cfg (cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[], char** params);
int do_get_tp_cfg (cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[], char* param);
int do_set_tp_cfg_passive (cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[], char** params);
#if defined(CONFIG_IMX7)
int do_set_tp_cfg_active_in (cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[], char** params);
int do_set_tp_cfg_active_out (cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[], char** params);
#endif

#endif
