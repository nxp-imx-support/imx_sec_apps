/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "tpsv.h"
#include "snvs_security.h"

int do_show_cfg (cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	
	unsigned int n;

	enum hp_secvio_source_t all_secvios[] = {
		SECURITY_VIOLATION_INPUT_0,
		SECURITY_VIOLATION_INPUT_1,
		SECURITY_VIOLATION_INPUT_2,
		SECURITY_VIOLATION_INPUT_3,
		SECURITY_VIOLATION_INPUT_4,
		SECURITY_VIOLATION_INPUT_5,
		LP_SECURITY_VIOLATION,
	};
	enum lp_tamper_detector_t all_tampers[] = {
		EXTERNAL_TAMPER_1,
		EXTERNAL_TAMPER_2,
	#if defined(CONFIG_IMX7)
		EXTERNAL_TAMPER_3,
		EXTERNAL_TAMPER_4,
		EXTERNAL_TAMPER_5,
		EXTERNAL_TAMPER_6,
		EXTERNAL_TAMPER_7,
		EXTERNAL_TAMPER_8,
		EXTERNAL_TAMPER_9,
		EXTERNAL_TAMPER_10,
	#endif
	};

	/* Secviol */
	{
		struct secviol_config_t sv_conf_retrieved;
		for (n = 0; n < sizeof(all_secvios) / sizeof(all_secvios[0]); n++) {
			if (retrieve_sv_conf(&sv_conf_retrieved, all_secvios[n]) != 0) {
				return CMD_RET_FAILURE;
			}
			print_sv_conf(&sv_conf_retrieved, "Setted");
			printf("\n");
		}
	}

	/* Tamper */ 
	{
		struct tamper_config_t tp_conf_retrieved;
		for (n = 0; n < sizeof(all_tampers) / sizeof(all_tampers[0]); n++) {
			if (retrieve_tp_conf(&tp_conf_retrieved, all_tampers[n]) != 0) {
				return CMD_RET_FAILURE;
			}
			print_tp_conf(&tp_conf_retrieved, "Setted");
			printf("\n");
		}
	}
	return CMD_RET_SUCCESS;
}

TPSV_Result sv_param_get_source(const char * str, enum hp_secvio_source_t * source)
{
	bool found = false;
	if (strcmp(str, "sec_vio_0") == 0) {
		found = true;
		*source = SECURITY_VIOLATION_INPUT_0;
	} else if (strcmp(str, "sec_vio_1") == 0) {
		found = true;
		found = true;
		*source = SECURITY_VIOLATION_INPUT_1;
	} else if (strcmp(str, "sec_vio_2") == 0) {
		found = true;
		*source = SECURITY_VIOLATION_INPUT_2;
	} else if (strcmp(str, "sec_vio_3") == 0) {
		found = true;
		*source = SECURITY_VIOLATION_INPUT_3;
	} else if (strcmp(str, "sec_vio_4") == 0) {
		found = true;
		*source = SECURITY_VIOLATION_INPUT_4;
	} else if (strcmp(str, "sec_vio_5") == 0) {
		found = true;
		*source = SECURITY_VIOLATION_INPUT_5;
	} else if (strcmp(str, "sec_vio_lp") == 0) {
		found = true;
		*source = LP_SECURITY_VIOLATION;
	} else {
		error("Can't get source from input \"%s\"", str);
	}

	return (found == true)? TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

TPSV_Result sv_param_get_enable(const char * str, enum sv_enable_t * enable)
{
	bool found = false;
	if (strcmp(str, "enabled") == 0) {
		found = true;
		*enable = SV_ENABLE;
	} else if (strcmp(str, "disabled") == 0) {
		found = true;
		*enable = SV_DISABLE;
	} else {
		error("Can't get sec vio enablement from input \"%s\"", str);
	}

	return (found == true)? TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

TPSV_Result sv_param_get_policy(const char * str, enum sv_policy_t * policy)
{
	bool found = false;
	if (strcmp(str, "disabled") == 0) {
		found = true;
		*policy = POLICY_DISABLE;
	} else if (strcmp(str, "non-fatal") == 0) {
		found = true;
		*policy = POLICY_NON_FATAL;
	} else if (strcmp(str, "fatal") == 0) {
		found = true;
		*policy = POLICY_FATAL;
	} else {
		error("Can't get policy from input \"%s\"", str);
	}

	return (found == true)? TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

TPSV_Result sv_param_get_irq_enable(const char * str, enum sv_itr_enable_t * itr_enable)
{
	bool found = false;
	if (strcmp(str, "enabled") == 0) {
		found = true;
		*itr_enable = SV_ITR_ENABLE;
	} else if (strcmp(str, "disabled") == 0) {
		found = true;
		*itr_enable = SV_ITR_DISABLE;
	} else {
		error("Can't get irq enablement from input \"%s\"", str);
	}

	return (found == true)? TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}


int do_get_sv_cfg (cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[], char* param)
{
	TPSV_Result res;
	struct secviol_config_t cfg;
	enum hp_secvio_source_t source;

	res = sv_param_get_source(param, &source);
	if (res != TPSV_SUCCESS) {
		return CMD_RET_FAILURE;
	}

	res = retrieve_sv_conf(&cfg, source);
	if (res != TPSV_SUCCESS) {
		error("Can't retrieve sv conf\n");
		printf("ERROR2");
		return CMD_RET_FAILURE;
	}

	print_sv_conf(&cfg, "retrieved:");

	return CMD_RET_SUCCESS;
}

int do_set_sv_cfg (cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[], char** params)
{
	TPSV_Result res;
	struct secviol_config_t cfg;
	enum hp_secvio_source_t source;
	enum sv_enable_t enable;
	enum sv_policy_t policy;
	enum sv_itr_enable_t itr_enable;

	res = sv_param_get_source(params[2], &source);
	if (res != TPSV_SUCCESS) {
		return CMD_RET_FAILURE;
	}

	res = sv_param_get_enable(params[3], &enable);
	if (res != TPSV_SUCCESS) {
		return CMD_RET_FAILURE;
	}

	res = sv_param_get_policy(params[4], &policy);
	if (res != TPSV_SUCCESS) {
		return CMD_RET_FAILURE;
	}

	res = sv_param_get_irq_enable(params[5], &itr_enable);
	if (res != TPSV_SUCCESS) {
		return CMD_RET_FAILURE;
	}

	res = secviol_config_factory(
			&cfg,
			source,
			enable,
			policy,
			itr_enable);
	if (res != TPSV_SUCCESS) {
		error("Error building configuration\n");
		return CMD_RET_FAILURE;
	}

	res = apply_sv_conf(&cfg);
	if (res != TPSV_SUCCESS) {
		error("Error applying configuration\n");
		return CMD_RET_FAILURE;
	}

	print_sv_conf(&cfg, "Applied:");

	return CMD_RET_SUCCESS;
}


TPSV_Result tp_param_get_tamper(const char * str, enum lp_tamper_detector_t * tamper)
{
	bool found = false;
	if (strcmp(str, "et_1") == 0 || strcmp(str, "tamper_1") == 0) {
		found = true;
		*tamper = EXTERNAL_TAMPER_1;
	} else if (strcmp(str, "et_2")  == 0 || strcmp(str, "tamper_2") == 0) {
		found = true;
		*tamper = EXTERNAL_TAMPER_2;
	}
#if defined(CONFIG_IMX7)
	else if (strcmp(str, "et_3") == 0 || strcmp(str, "tamper_3") == 0) {
		found = true;
		*tamper = EXTERNAL_TAMPER_3;
	} else if (strcmp(str, "et_4") == 0 || strcmp(str, "tamper_4") == 0) {
		found = true;
		*tamper = EXTERNAL_TAMPER_4;
	} else if (strcmp(str, "et_5") == 0 || strcmp(str, "tamper_5") == 0) {
		found = true;
		*tamper = EXTERNAL_TAMPER_5;
	} else if (strcmp(str, "et_6") == 0 || strcmp(str, "tamper_6") == 0 || strcmp(str, "at_1") == 0) {
		found = true;
		*tamper = EXTERNAL_TAMPER_6;
	} else if (strcmp(str, "et_7") == 0 || strcmp(str, "tamper_7") == 0 || strcmp(str, "at_2") == 0) {
		found = true;
		*tamper = EXTERNAL_TAMPER_7;
	} else if (strcmp(str, "et_8") == 0 || strcmp(str, "tamper_8") == 0 || strcmp(str, "at_3") == 0) {
		found = true;
		*tamper = EXTERNAL_TAMPER_8;
	} else if (strcmp(str, "et_9") == 0 || strcmp(str, "tamper_9") == 0 || strcmp(str, "at_4") == 0) {
		found = true;
		*tamper = EXTERNAL_TAMPER_9;
	} else if (strcmp(str, "et_10") == 0 || strcmp(str, "tamper_10") == 0 || strcmp(str, "at_5") == 0) {
		found = true;
		*tamper = EXTERNAL_TAMPER_10;
	}
#endif 
	else {
		error("Can't get tamper from input \"%s\"", str);
	}

	return (found == true)? TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

TPSV_Result tp_param_get_enable(const char * str, enum tp_enable_t * enable)
{
	bool found = false;
	if (strcmp(str, "enabled") == 0) {
		found = true;
		*enable = TP_ENABLE;
	} else if (strcmp(str, "disabled") == 0) {
		found = true;
		*enable = TP_DISABLE;
	} else {
		error("Can't get tamper enablement from input \"%s\"", str);
	}

	return (found == true)? TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

TPSV_Result tp_param_get_polarity(const char * str, enum tp_polarity_t * pol)
{
	bool found = false;
	if (strcmp(str, "0") == 0) {
		found = true;
		*pol = POL_LOW;
	} else if (strcmp(str, "1") == 0) {
		found = true;
		*pol = POL_HIGH;
	} else {
		error("Can't get polarity from input \"%s\"", str);
	}

	return (found == true)? TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

TPSV_Result tp_param_get_gf_enable(const char * str, enum gf_enable_t * gf_ena)
{
	bool found = false;
	if (strcmp(str, "enabled") == 0) {
		found = true;
		*gf_ena = GF_ENABLED;
	} else if (strcmp(str, "disabled") == 0) {
		found = true;
		*gf_ena = GF_BYPASSED;
	} else {
		error("Can't get glitch filter enablement from input \"%s\"", str);
	}

	return (found == true)? TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

TPSV_Result tp_param_get_gf_value(const char * str, enum gf_value_t * gf_value)
{
	bool found = false;
	char * last;

	unsigned long value = strtoul(str, &last, 0);

	if (*last != '\0') {
		error("Can't get glitch filter value from input \"%s\"", str);
		return TPSV_ERROR_BAD_PARAMETERS;
	}

	if (value >= GF_VALUE_MIN && value <= GF_VALUE_MAX) {
		found = true;
		*gf_value = value;
	} else {
		error("Can't get glitch filter value from input \"%s\"", str);
	}

	return (found == true)? TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}


#if defined(CONFIG_IMX7)
TPSV_Result tp_param_get_at_tamper(const char * str, enum active_tamper_t * at_tamper)
{
	bool found = false;
	if (strcmp(str, "at_1") == 0 || strcmp(str, "et_6") == 0 || strcmp(str, "tamper_6") == 0) {
		found = true;
		*at_tamper = ACTIVE_TAMPER_1;
	} else if (strcmp(str, "at_2") == 0 || strcmp(str, "et_7")== 0 || strcmp(str, "tamper_7") == 0) {
		found = true;
		*at_tamper = ACTIVE_TAMPER_2;
	} else if (strcmp(str, "at_3") == 0 || strcmp(str, "et_8") == 0 || strcmp(str, "tamper_8") == 0) {
		found = true;
		*at_tamper = ACTIVE_TAMPER_3;
	} else if (strcmp(str, "at_4") == 0 || strcmp(str, "et_9") == 0 || strcmp(str, "tamper_9") == 0) {
		found = true;
		*at_tamper = ACTIVE_TAMPER_4;
	} else if (strcmp(str, "at_5") == 0 || strcmp(str, "et_10") == 0 || strcmp(str, "tamper_10") == 0) {
		found = true;
		*at_tamper = ACTIVE_TAMPER_5;
	} else {
		error("Can't get active tamper from input \"%s\"", str);
	}

	return (found == true)? TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

TPSV_Result tp_param_get_at_freq(const char * str, enum at_frequency_t * at_freq)
{
	bool found = false;
	if (strcmp(str, "2") == 0) {
		found = true;
		*at_freq = FREQ_2HZ;
	} else if (strcmp(str, "4") == 0) {
		found = true;
		*at_freq = FREQ_4HZ;
	} else if (strcmp(str, "8") == 0) {
		found = true;
		*at_freq = FREQ_8HZ;
	} else if (strcmp(str, "16") == 0) {
		found = true;
		*at_freq = FREQ_16HZ;
	} else {
		error("Can't get frequency from input \"%s\"", str);
	}

	return (found == true)? TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

TPSV_Result tp_param_get_at_enable(const char * str, enum at_enable_t * at_enable)
{
	bool found = false;
	if (strcmp(str, "enabled") == 0) {
		found = true;
		*at_enable = AT_ENABLE;
	} else if (strcmp(str, "disabled") == 0) {
		found = true;
		*at_enable = AT_DISABLE;
	} else {
		error("Can't get active tamper enablement from input \"%s\"", str);
	}

	return (found == true)? TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

TPSV_Result tp_param_get_at_poly(const char * str, enum at_polynomial_t * at_poly)
{
	bool found = false;
	char * last;

	unsigned long value = strtoul(str, &last, 0);

	if (*last != '\0') {
		error("Can't get polynomial from input \"%s\"", str);
		return TPSV_ERROR_BAD_PARAMETERS;
	}

	if (value >= AT_POLY_MIN && value <= AT_POLY_MAX) {
		found = true;
		*at_poly = value;
	} else {
		error("Can't get polynomial from input \"%s\"", str);
	}

	return (found == true)? TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

TPSV_Result tp_param_get_at_seed(const char * str, enum at_seed_t * at_seed)
{
	bool found = false;
	char * last;

	unsigned long value = strtoul(str, &last, 0);

	if (*last != '\0') {
		error("Can't get seed from input \"%s\"", str);
		return TPSV_ERROR_BAD_PARAMETERS;
	}

	if (value >= AT_SEED_MIN && value <= AT_SEED_MAX) {
		found = true;
		*at_seed = value;
	} else {
		error("Can't get seed from input \"%s\"", str);
	}

	return (found == true)? TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}
#endif

int do_get_tp_cfg (cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[], char* param)
{
	TPSV_Result res;
	struct tamper_config_t cfg;
	enum lp_tamper_detector_t tamper;

	res = tp_param_get_tamper(param, &tamper);
	if (res != TPSV_SUCCESS) {
		return CMD_RET_FAILURE;
	}

	res = retrieve_tp_conf(&cfg, tamper);
	if (res != TPSV_SUCCESS) {
		error("Can't retrieve tp conf\n");
		return CMD_RET_FAILURE;
	}

	print_tp_conf(&cfg, "retrieved:");

	return CMD_RET_SUCCESS;
}

int do_set_tp_cfg_passive (cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[], char** params)
{
	TPSV_Result res;
	struct tamper_config_t cfg;
	enum lp_tamper_detector_t tamper;
	enum tp_enable_t enable;
	enum tp_polarity_t pol;
	enum gf_enable_t gf_ena;
	enum gf_value_t gf_value;
	char * param;

	param = params[2];
	res = tp_param_get_tamper(param, &tamper);
	if (res != TPSV_SUCCESS) {
		return CMD_RET_FAILURE;
	}

	param = params[4];
	res = tp_param_get_enable(param, &enable);
	if (res != TPSV_SUCCESS) {
		return CMD_RET_FAILURE;
	}

	param = params[5];
	res = tp_param_get_polarity(param, &pol);
	if (res != TPSV_SUCCESS) {
		return CMD_RET_FAILURE;
	}

	param = params[6];
	res = tp_param_get_gf_enable(param, &gf_ena);
	if (res != TPSV_SUCCESS) {
		return CMD_RET_FAILURE;
	}

	param = params[7];
	res = tp_param_get_gf_value(param, &gf_value);
	if (res != TPSV_SUCCESS) {
		return CMD_RET_FAILURE;
	}

	res = tamper_config_factory(
					&cfg,
					MODE_PASSIVE,
					tamper,
					enable,
					pol,
					gf_ena,
					gf_value,
					PASSIVE_TAMPER, AT_DISABLE, FREQ_16HZ, AT_POLY_DEFAULT, AT_SEED_DEFAULT);
	if (res != TPSV_SUCCESS) {
		error("Error building configuration\n");
		return CMD_RET_FAILURE;
	}

	res = apply_tp_conf(&cfg);
	if (res != TPSV_SUCCESS) {
		error("Error applying configuration\n");
		return CMD_RET_FAILURE;
	}

	print_tp_conf(&cfg, "Applied:");

	return CMD_RET_SUCCESS;
}


#if defined(CONFIG_IMX7)
int do_set_tp_cfg_active_in (cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[], char** params)
{
	TPSV_Result res;
	struct tamper_config_t cfg;
	enum lp_tamper_detector_t tamper;
	enum tp_enable_t enable;
	enum gf_enable_t gf_ena;
	enum gf_value_t gf_value;
	enum active_tamper_t at_tamper;
	char * param;

	param = params[2];
	res = tp_param_get_tamper(param, &tamper);
	if (res != TPSV_SUCCESS) {
		return CMD_RET_FAILURE;
	}

	param = params[4];
	res = tp_param_get_enable(param, &enable);
	if (res != TPSV_SUCCESS) {
		return CMD_RET_FAILURE;
	}

	param = params[5];
	res = tp_param_get_gf_enable(param, &gf_ena);
	if (res != TPSV_SUCCESS) {
		return CMD_RET_FAILURE;
	}

	param = params[6];
	res = tp_param_get_gf_value(param, &gf_value);
	if (res != TPSV_SUCCESS) {
		return CMD_RET_FAILURE;
	}

	param = params[7];
	res = tp_param_get_at_tamper(param, &at_tamper);
	if (res != TPSV_SUCCESS) {
		return CMD_RET_FAILURE;
	}

	tamper_config_factory(
					&cfg,
					MODE_ACTIVE_IN,
					tamper,
					enable,
					POL_LOW,
					gf_ena,
					gf_value,
					at_tamper,
					AT_DISABLE, FREQ_16HZ, AT_POLY_DEFAULT, AT_SEED_DEFAULT);
	if (res != TPSV_SUCCESS) {
		error("Error building configuration\n");
		return CMD_RET_FAILURE;
	}

	res = apply_tp_conf(&cfg);
	if (res != TPSV_SUCCESS) {
		error("Error applying configuration\n");
		return CMD_RET_FAILURE;
	}

	print_tp_conf(&cfg, "Applied:");

	return CMD_RET_SUCCESS;
}

int do_set_tp_cfg_active_out (cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[], char** params)
{
	TPSV_Result res;
	struct tamper_config_t cfg;
	enum active_tamper_t at_tamper;
	enum at_frequency_t at_freq;
	enum at_enable_t at_enable;
	enum at_polynomial_t at_poly;
	enum at_seed_t at_seed;
	char * param;

	param = params[2];
	res = tp_param_get_at_tamper(param, &at_tamper);
	if (res != TPSV_SUCCESS) {
		return CMD_RET_FAILURE;
	}

	param = params[4];
	res = tp_param_get_at_enable(param, &at_enable);
	if (res != TPSV_SUCCESS) {
		return CMD_RET_FAILURE;
	}

	param = params[5];
	res = tp_param_get_at_freq(param, &at_freq);
	if (res != TPSV_SUCCESS) {
		return CMD_RET_FAILURE;
	}

	param = params[6];
	res = tp_param_get_at_poly(param, &at_poly);
	if (res != TPSV_SUCCESS) {
		return CMD_RET_FAILURE;
	}

	param = params[7];
	res = tp_param_get_at_seed(param, &at_seed);
	if (res != TPSV_SUCCESS) {
		return CMD_RET_FAILURE;
	}

	tamper_config_factory(
					&cfg,
					MODE_ACTIVE_OUT,
					at_tamper,
					TP_DISABLE, POL_LOW, GF_BYPASSED, GF_VALUE_MIN, PASSIVE_TAMPER,
					at_enable,
					at_freq,
					at_poly,
					at_seed);
	if (res != TPSV_SUCCESS) {
		error("Error building configuration\n");
		return CMD_RET_FAILURE;
	}

	res = apply_tp_conf(&cfg);
	if (res != TPSV_SUCCESS) {
		error("Error applying configuration\n");
		return CMD_RET_FAILURE;
	}

	print_tp_conf(&cfg, "Applied:");

	return CMD_RET_SUCCESS;
}
#endif

