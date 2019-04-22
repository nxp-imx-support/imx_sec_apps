/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "snvs_security.h"
#include "mem.h"

struct snvs_full* get_snvs(){
	return (struct snvs_full*) get_mem();
}

static int tamper_detected;

int tamper_detection_check(void)
{
	if (tamper_detected)
		return true;
	else
		return false;
}

struct snvs_source_mapping sec_viol_mapping[] = {
	{ "sec_vio_0", SECURITY_VIOLATION_INPUT_0},
	{ "sec_vio_1", SECURITY_VIOLATION_INPUT_1},
	{ "sec_vio_2", SECURITY_VIOLATION_INPUT_2},
	{ "sec_vio_3", SECURITY_VIOLATION_INPUT_3},
	{ "sec_vio_4", SECURITY_VIOLATION_INPUT_4},
	{ "sec_vio_5", SECURITY_VIOLATION_INPUT_5},
	{ "sec_vio_lp", LP_SECURITY_VIOLATION},
};
static inline const char * get_sec_viol_name(const enum hp_secvio_source_t source)
{
	unsigned int n;
	for (n = 0; n < sizeof(sec_viol_mapping)/sizeof(struct snvs_source_mapping); n++) {
		if (source == sec_viol_mapping[n].source_index) {
			return sec_viol_mapping[n].source_name;
		}
	}
	return "UNKNOW";
}

struct snvs_source_mapping tamper_mapping[] = {
	{ "et_1", EXTERNAL_TAMPER_1},
	{ "et_2", EXTERNAL_TAMPER_2},
#if defined(CONFIG_IMX7)
	{ "et_3", EXTERNAL_TAMPER_3},
	{ "et_4", EXTERNAL_TAMPER_4},
	{ "et_5", EXTERNAL_TAMPER_5},
	{ "et_6", EXTERNAL_TAMPER_6},
	{ "et_7", EXTERNAL_TAMPER_7},
	{ "et_8", EXTERNAL_TAMPER_8},
	{ "et_9", EXTERNAL_TAMPER_9},
	{ "et_10", EXTERNAL_TAMPER_10},
#endif
};
static inline const char * get_tamper_name(const enum lp_tamper_detector_t source)
{
	unsigned int n;
	for (n = 0; n < sizeof(tamper_mapping)/sizeof(struct snvs_source_mapping); n++) {
		if (source == tamper_mapping[n].source_index) {
			return tamper_mapping[n].source_name;
		}
	}
	return "UNKNOW";
}

static inline TPSV_Result check_sv_source(const enum hp_secvio_source_t source)
{
	unsigned int n;
	bool found = false;
	for (n = 0; n < sizeof(sec_viol_mapping)/sizeof(struct snvs_source_mapping); n++) {
		if (source == sec_viol_mapping[n].source_index) {
			found = true;
			break;
		}
	}
	return (found)? TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

static inline TPSV_Result check_sv_enable(const enum sv_enable_t enable)
{
	return (enable == SV_DISABLE || enable == SV_ENABLE)?
				TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

static inline TPSV_Result check_sv_policy(const enum sv_policy_t policy)
{
	return (policy == POLICY_DISABLE
				|| policy == POLICY_NON_FATAL
				|| policy == POLICY_FATAL)?
			TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

static inline TPSV_Result check_sv_itr_ena(const enum sv_itr_enable_t itr_ena)
{
	return (itr_ena == SV_ITR_DISABLE || itr_ena == SV_ITR_ENABLE)?
				TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

static inline TPSV_Result compare_sv_cfg(const struct secviol_config_t * sv_cfg1, const struct secviol_config_t * sv_cfg2)
{
	return (memcmp(sv_cfg1, sv_cfg2, sizeof(struct secviol_config_t)) == 0)? TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

void print_sv_conf(struct secviol_config_t * sv_cfg __maybe_unused,
									const char * text __maybe_unused)
{
	debug("%s [source: %s, ena:%s, policy:%s, itr:%s]\n",
		((text == NULL)? "" : text),
		get_sec_viol_name(sv_cfg->source),
		((sv_cfg->enable == SV_ENABLE)? "enable" : "disable"),
		((sv_cfg->policy == POLICY_NON_FATAL)? "non-fatal" : "fatal"),
		((sv_cfg->itr_ena == SV_ITR_ENABLE)? "enable" : "disable") );
}

TPSV_Result secviol_config_factory(
	struct secviol_config_t * cfg_to_build,
	enum hp_secvio_source_t source,
	enum sv_enable_t ena,
	enum sv_policy_t policy,
	enum sv_itr_enable_t itr_ena)
{
	if (cfg_to_build == NULL) {
		return TPSV_ERROR_BAD_PARAMETERS;
	}

	if (check_sv_source(source) != TPSV_SUCCESS) {
		debug("check_sv_source failed\n");
		return TPSV_ERROR_BAD_PARAMETERS;
	}
	cfg_to_build->source = source;

	if (check_sv_enable(ena) != TPSV_SUCCESS) {
		debug("check_sv_enable_t failed\n");
		return TPSV_ERROR_BAD_PARAMETERS;
	}
	if (cfg_to_build->source == LP_SECURITY_VIOLATION) {
		cfg_to_build->enable = SV_DISABLE;
	} else {
		cfg_to_build->enable = ena;
	}

	if (check_sv_policy(policy) != TPSV_SUCCESS) {
		debug("check_sv_policy failed\n");
		return TPSV_ERROR_BAD_PARAMETERS;
	}
	cfg_to_build->policy = policy;

	if (check_sv_itr_ena(itr_ena) != TPSV_SUCCESS) {
		debug("check_sv_itr_ena failed\n");
		return TPSV_ERROR_BAD_PARAMETERS;
	}
	cfg_to_build->itr_ena = itr_ena;

	return TPSV_SUCCESS;
}

static inline TPSV_Result check_tp_mode(const enum tampering_mode_t mode)
{
	return (mode == MODE_PASSIVE
#if defined(CONFIG_IMX7)
			|| mode == MODE_ACTIVE_IN
			|| mode == MODE_ACTIVE_OUT
#endif
			)?
	TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

static inline TPSV_Result check_tp_tamper(const enum lp_tamper_detector_t tamper)
{
	unsigned int n;
	bool found = false;
	for (n = 0; n < sizeof(tamper_mapping)/sizeof(struct snvs_source_mapping); n++) {
		if (tamper == tamper_mapping[n].source_index) {
			found = true;
			break;
		}
	}
	return (found)? TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

static inline TPSV_Result check_tp_enable(enum tp_enable_t enable)
{
	return (enable == TP_DISABLE || enable == TP_ENABLE)?
				TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

static inline TPSV_Result check_tp_polarity(enum tp_polarity_t pol)
{
	return (pol == POL_LOW || pol == POL_HIGH)? TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

static inline TPSV_Result check_tp_gf_enable(enum gf_enable_t gf_enable)
{
	return (gf_enable == GF_ENABLED || gf_enable == GF_BYPASSED)?
				TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

static inline TPSV_Result check_tp_gf_value(enum gf_value_t gf_value)
{
	return (gf_value >= GF_VALUE_MIN && gf_value <= GF_VALUE_MAX)?
				TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

#if defined(CONFIG_IMX7)

static inline TPSV_Result check_at_freq(enum at_frequency_t freq)
{
	return (freq == FREQ_2HZ
			|| freq == FREQ_4HZ
			|| freq == FREQ_8HZ
			|| freq == FREQ_16HZ)? TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

static inline TPSV_Result check_passive_routing(enum active_tamper_t source)
{
	return (source == PASSIVE_TAMPER)? TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

static inline TPSV_Result check_active_routing(enum active_tamper_t source)
{
	return (ACTIVE_TAMPER_1 <= source && source <= ACTIVE_TAMPER_5)? TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

static inline TPSV_Result check_at_enable(enum at_enable_t at_enable)
{
	return (at_enable == AT_DISABLE || at_enable == AT_ENABLE)?
				TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

static inline TPSV_Result can_be_active_tamper(enum lp_tamper_detector_t source)
{
	enum active_tamper_t at = source;
	return (ACTIVE_TAMPER_1 <= at && at <= ACTIVE_TAMPER_5)? TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

static inline TPSV_Result check_at_polynome(enum at_polynomial_t poly)
{
	return (poly >= AT_POLY_MIN && poly <= AT_POLY_MAX)?
				TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

static inline TPSV_Result check_at_seed(enum at_seed_t seed)
{
	return (seed >= AT_SEED_MIN && seed <= AT_SEED_MAX)?
				TPSV_SUCCESS : TPSV_ERROR_BAD_PARAMETERS;
}

#else

static inline TPSV_Result check_at_freq(unsigned int freq __unused)
{
	return TPSV_ERROR_BAD_PARAMETERS;
}

static inline TPSV_Result check_passive_routing(enum active_tamper_t source __unused)
{
	return TPSV_SUCCESS;
}

static inline TPSV_Result check_active_routing(enum active_tamper_t source __unused)
{
	return TPSV_ERROR_BAD_PARAMETERS;
}

static inline TPSV_Result can_be_active_tamper(enum active_tamper_t source __unused)
{
	return TPSV_ERROR_BAD_PARAMETERS;
}

static inline TPSV_Result check_at_enable(enum at_enable_t at_enable __unused)
{
	return TPSV_ERROR_BAD_PARAMETERS;
}

static inline TPSV_Result check_at_polynome(enum at_polynomial_t at_poly __unused)
{
	return TPSV_ERROR_BAD_PARAMETERS;
}

static inline TPSV_Result check_at_seed(enum at_seed_t at_seed __unused)
{
	return TPSV_ERROR_BAD_PARAMETERS;
}

#endif

static inline TPSV_Result compare_tp_cfg(const struct tamper_config_t * tp_cfg1, const struct tamper_config_t * tp_cfg2)
{
	if (tp_cfg1->mode          == tp_cfg2->mode
		&& tp_cfg1->tamper     == tp_cfg2->tamper
		&& tp_cfg1->enable     == tp_cfg2->enable
		&& tp_cfg1->assert_val == tp_cfg2->assert_val
		&& tp_cfg1->gf_enable  == tp_cfg2->gf_enable
		&& tp_cfg1->gf_value   == tp_cfg2->gf_value
		&& tp_cfg1->at_source  == tp_cfg2->at_source
		&& tp_cfg1->at_enable  == tp_cfg2->at_enable
		&& tp_cfg1->at_freq    == tp_cfg2->at_freq)
	{
		return TPSV_SUCCESS;
	}
	return TPSV_ERROR_BAD_PARAMETERS;
}

void print_tp_conf(struct tamper_config_t * tp_cfg __maybe_unused,
									const char * text __maybe_unused)
{
	debug("%s [mode:%s et: %s, ena:%s, assert:%d, gf:%s, val:0x%x, at:%s,\n"
		"\tat_ena:%s, f:%d, poly:0x%x (default value if read), seed:0x%x (default value if read)]\n",
		((text == NULL)? "" : text),
		(((tp_cfg->mode == MODE_PASSIVE)? "passive" : (tp_cfg->mode == MODE_ACTIVE_IN)? "active IN" : "active OUT")),
		get_tamper_name(tp_cfg->tamper),
		((tp_cfg->enable == TP_ENABLE)? "enable" : "disable"),
		tp_cfg->assert_val,
		((tp_cfg->gf_enable == GF_ENABLED)? "enable" : "bypassed"),
		tp_cfg->gf_value,
		((tp_cfg->mode == MODE_ACTIVE_IN)? get_tamper_name(tp_cfg->at_source) : "none"),
		((tp_cfg->at_enable == AT_DISABLE)? "disable" : "enable"),
		tp_cfg->at_freq,
		tp_cfg->at_poly,
		tp_cfg->at_seed);
}

TPSV_Result tamper_config_factory(
	struct tamper_config_t * cfg_to_build,
	enum tampering_mode_t mode,
	enum lp_tamper_detector_t tamper,
	enum tp_enable_t ena,
	enum tp_polarity_t assert_val,
	enum gf_enable_t gf_ena,
	enum gf_value_t gf_val,
	enum active_tamper_t at_source,
	enum at_enable_t at_enable,
	enum at_frequency_t at_freq,
	enum at_polynomial_t at_poly,
	enum at_seed_t at_seed)
{
	if (cfg_to_build == NULL) {
		return TPSV_ERROR_BAD_PARAMETERS;
	}

	cfg_to_build->mode = MODE_PASSIVE;
	cfg_to_build->tamper = EXTERNAL_TAMPER_1;
	cfg_to_build->enable = TP_DISABLE;
	cfg_to_build->assert_val = POL_LOW;
	cfg_to_build->gf_enable = GF_BYPASSED;
	cfg_to_build->gf_value = GF_VALUE_MIN;
	cfg_to_build->at_source = PASSIVE_TAMPER;
	cfg_to_build->at_freq = FREQ_16HZ;
	cfg_to_build->at_enable = AT_DISABLE;
	cfg_to_build->at_poly = AT_POLY_DEFAULT;
	cfg_to_build->at_seed = AT_SEED_DEFAULT;

	if (check_tp_mode(mode) != TPSV_SUCCESS) {
		debug("check_tp_mode failed\n");
		return TPSV_ERROR_BAD_PARAMETERS;
	}
	cfg_to_build->mode = mode;

	if (check_tp_tamper(tamper) != TPSV_SUCCESS) {
		debug("check_tp_tamper failed\n");
		return TPSV_ERROR_BAD_PARAMETERS;
	}
	cfg_to_build->tamper = tamper;

	if (mode == MODE_PASSIVE || mode == MODE_ACTIVE_IN) {
		/* Check field for passive tamper */

		if (check_tp_enable(ena) != TPSV_SUCCESS) {
			debug("check_tp_enable failed\n");
			return TPSV_ERROR_BAD_PARAMETERS;
		}
		cfg_to_build->enable = ena;

		if (check_tp_gf_enable(gf_ena) != TPSV_SUCCESS) {
			debug("check_tp_gf_enable failed\n");
			return TPSV_ERROR_BAD_PARAMETERS;
		}
		cfg_to_build->gf_enable = gf_ena;

		if (check_tp_gf_value(gf_val) != TPSV_SUCCESS) {
			debug("check_tp_gf_value failed\n");
			return TPSV_ERROR_BAD_PARAMETERS;
		}
		cfg_to_build->gf_value = gf_val;

		if (mode == MODE_PASSIVE) {
			if (check_tp_polarity(assert_val) != TPSV_SUCCESS) {
				debug("check_tp_polarity failed\n");
				return TPSV_ERROR_BAD_PARAMETERS;
			}
			cfg_to_build->assert_val = assert_val;

			if (check_passive_routing(at_source) != TPSV_SUCCESS) {
				debug("check_passive_routing failed\n");
				return TPSV_ERROR_BAD_PARAMETERS;
			}
			cfg_to_build->at_source = at_source;
		} else {
			if (check_active_routing(at_source) != TPSV_SUCCESS) {
				debug("check_active_routing failed\n");
				return TPSV_ERROR_BAD_PARAMETERS;
			}
			cfg_to_build->at_source = at_source;
		}
		cfg_to_build->at_freq = FREQ_16HZ;
	} else {
		/* Check field for active output */
		if (check_at_enable(at_enable) != TPSV_SUCCESS) {
			debug("check_at_enable failed\n");
			return TPSV_ERROR_BAD_PARAMETERS;
		}
		cfg_to_build->at_enable = at_enable;

		if (check_at_freq(at_freq) != TPSV_SUCCESS) {
			debug("check_at_freq failed\n");
			return TPSV_ERROR_BAD_PARAMETERS;
		}
		cfg_to_build->at_freq = at_freq;

		if (check_at_polynome(at_poly) != TPSV_SUCCESS) {
			debug("check_at_freq failed\n");
			return TPSV_ERROR_BAD_PARAMETERS;
		}
		cfg_to_build->at_poly = at_poly;

		if (check_at_seed(at_seed) != TPSV_SUCCESS) {
			debug("check_at_freq failed\n");
			return TPSV_ERROR_BAD_PARAMETERS;
		}
		cfg_to_build->at_seed = at_seed;
	}

	return TPSV_SUCCESS;
}

static int get_security_violation_input_source_shift(unsigned int source_index)
{
	int shift = 0;

	switch (source_index) {
	case SECURITY_VIOLATION_INPUT_0:
		shift = HP_SECVIO_ICTL_CFG0_SHIFT;
		break;
	case SECURITY_VIOLATION_INPUT_1:
		shift = HP_SECVIO_ICTL_CFG1_SHIFT;
		break;
	case SECURITY_VIOLATION_INPUT_2:
		shift = HP_SECVIO_ICTL_CFG2_SHIFT;
		break;
	case SECURITY_VIOLATION_INPUT_3:
		shift = HP_SECVIO_ICTL_CFG3_SHIFT;
		break;
	case SECURITY_VIOLATION_INPUT_4:
		shift = HP_SECVIO_ICTL_CFG4_SHIFT;
		break;
	case SECURITY_VIOLATION_INPUT_5:
		shift = HP_SECVIO_ICTL_CFG5_SHIFT;
		break;
	case LP_SECURITY_VIOLATION:
		shift = HP_SECVIO_ICTL_LPSV_SHIFT;
		break;
	default:
		error("\nINVALID SOURCE INDEX: %d\n", source_index);
		shift = -1;
	}

	return shift;
}

static unsigned int get_lp_tamper_detection_source_shift(unsigned int tamper_detector_source_index)
{
	unsigned int shift = 0;

	switch (tamper_detector_source_index) {
	case SRTC_ROLLOVER_VIOLATION:
		shift = LP_TAMPDET_SRTCR_SHIFT;
		break;
	case MC_ROLLOVER_VIOLATION:
		shift = LP_TAMPDET_MCR_SHIFT;
		break;
	case SRTC_CLOCK_TAMPER:
		shift = LP_TAMPDET_CT_SHIFT;
		break;
	case TEMPERATURE_TAMPER:
		shift = LP_TAMPDET_TT_SHIFT;
		break;
	case VOLTAGE_TAMPER:
		shift = LP_TAMPDET_VT_SHIFT;
		break;
	case WIRE_MESH_TAMPER_1:
		shift = LP_TAMPDET_WMT1_SHIFT;
		break;
	case WIRE_MESH_TAMPER_2:
		shift = LP_TAMPDET_WMT2_SHIFT;
		break;
	case EXTERNAL_TAMPER_1:
		shift = LP_TAMPDET_ET1_SHIFT;
		break;
	case EXTERNAL_TAMPER_2:
		shift = LP_TAMPDET_ET2_SHIFT;
		break;
#if defined(CONFIG_IMX7)
	case EXTERNAL_TAMPER_3:
		shift = LP_TAMPDET2_ET3_SHIFT;
		break;
	case EXTERNAL_TAMPER_4:
		shift = LP_TAMPDET2_ET4_SHIFT;
		break;
	case EXTERNAL_TAMPER_5:
		shift = LP_TAMPDET2_ET5_SHIFT;
		break;
	case EXTERNAL_TAMPER_6:
		shift = LP_TAMPDET2_ET6_SHIFT;
		break;
	case EXTERNAL_TAMPER_7:
		shift = LP_TAMPDET2_ET7_SHIFT;
		break;
	case EXTERNAL_TAMPER_8:
		shift = LP_TAMPDET2_ET8_SHIFT;
		break;
	case EXTERNAL_TAMPER_9:
		shift = LP_TAMPDET2_ET9_SHIFT;
		break;
	case EXTERNAL_TAMPER_10:
		shift = LP_TAMPDET2_ET10_SHIFT;
		break;
#endif
	default:
		error("\nINVALID SOURCE INDEX: %d\n", tamper_detector_source_index);
		shift = TPSV_ERROR_BAD_PARAMETERS;
	}

	return shift;
}

int snvs_generate_software_security_violation(unsigned int violation_source_index)
{
	int clear_bit, value;
	unsigned int address;

	switch (violation_source_index) {
	case SW_NONFATAL_VIOLATION:
		address = (unsigned int)&(get_snvs()->hp.cmd) - (unsigned int)get_snvs();
		clear_bit = HP_CMD_SW_MASK << HP_CMD_SW_SV_SHIFT;

		value = HP_SOFTWARE_SECURITY_VIOLATION << HP_CMD_SW_SV_SHIFT;

		io_update_bits(address, clear_bit, value);
		break;
	case SW_FATAL_VIOLATION:
		address = (unsigned int)&(get_snvs()->hp.cmd) - (unsigned int)get_snvs();
		clear_bit = HP_CMD_SW_MASK << HP_CMD_SW_SV_SHIFT;

		value = HP_SOFTWARE_SECURITY_VIOLATION << HP_CMD_SW_FSV_SHIFT;

		io_update_bits(address, clear_bit, value);
		break;
	case SW_LP_SECURITY_VIOLATION:
		address = (unsigned int)&(get_snvs()->hp.cmd) - (unsigned int)get_snvs();
		clear_bit = HP_CMD_SW_LPSV_MASK << HP_CMD_SW_LPSV_SHIFT;

		value = HP_SOFTWARE_SECURITY_VIOLATION << HP_CMD_SW_LPSV_SHIFT;

		io_update_bits(address, clear_bit, value);
		break;
	default:
		error("\nINVALID SOURCE INDEX: %d\n", violation_source_index);
		return TPSV_ERROR_BAD_PARAMETERS;
	}
	return TPSV_SUCCESS;
}

/*
 * @brief This API provides information about violation policy
 * of specified security violation source
 *
 * @param[in] source
 *
 * @param[out] security violation policy of specified source
 */
int snvs_get_security_violation_policy(unsigned int violation_source_index)
{
	int value;
	int shift;

	shift = get_security_violation_input_source_shift
			(violation_source_index);
	
	if (shift < 0)      
		return TPSV_ERROR_BAD_PARAMETERS;

	switch (violation_source_index) {
	case SECURITY_VIOLATION_INPUT_0:
	case SECURITY_VIOLATION_INPUT_1:
	case SECURITY_VIOLATION_INPUT_2:
	case SECURITY_VIOLATION_INPUT_3:
	case SECURITY_VIOLATION_INPUT_4:
		value = read_mem((unsigned int)&(get_snvs()->hp.secvio_ctl) - (unsigned int)get_snvs());
		value = value >> shift;
		value &= HP_SECVIO_ICTL_CFG_BIT;
		break;
	case SECURITY_VIOLATION_INPUT_5:
	case LP_SECURITY_VIOLATION:
		value = read_mem((unsigned int)&(get_snvs()->hp.secvio_ctl) - (unsigned int)get_snvs());
		value = value >> shift;
		value &= HP_SECVIO_ICTL_CFG_MASK;
		break;
	default:
		error("\nInvalid source index %d, source is not configurable.\n", violation_source_index);
		value = TPSV_ERROR_BAD_PARAMETERS;
	}
	return value;
}

/*
 * @brief This API is used to configure specified security violation source.
 *
 * @param[in] source
 * @param[in] security_type(disable, fatal, non-fatal)
 *
 * @retval TPSV_ERROR_BAD_PARAMETERS
 * @retval TPSV_SUCCESS
 *
 */
int snvs_set_security_violation_policy(unsigned int violation_source_index, int security_index)
{
	int clear_bit, value;
	unsigned int address;
	int shift;

	shift = get_security_violation_input_source_shift(
		violation_source_index);
	if (shift < 0)
		return TPSV_ERROR_BAD_PARAMETERS;

	switch (violation_source_index) {
	case SECURITY_VIOLATION_INPUT_0:
	case SECURITY_VIOLATION_INPUT_1:
	case SECURITY_VIOLATION_INPUT_2:
	case SECURITY_VIOLATION_INPUT_3:
	case SECURITY_VIOLATION_INPUT_4:
		address = (unsigned int)&(get_snvs()->hp.secvio_ctl) - (unsigned int)get_snvs();
		clear_bit = 1 << shift;

		if (security_index == HP_SECVIO_ICTL_CFG_NONFATAL)
			value = POLICY_NON_FATAL;
		else if (security_index == HP_SECVIO_ICTL_CFG_FATAL)
			value = POLICY_FATAL;
		else
			return TPSV_ERROR_BAD_PARAMETERS;

		value = value << shift;
		break;
	case SECURITY_VIOLATION_INPUT_5:
#if defined(CONFIG_IMX7)
		if (security_index == HP_SECVIO_ICTL_CFG_DISABLE)
			return TPSV_ERROR_BAD_PARAMETERS;
#endif
	case LP_SECURITY_VIOLATION:
		address = (unsigned int)&(get_snvs()->hp.secvio_ctl) - (unsigned int)get_snvs();
		clear_bit = HP_SECVIO_ICTL_CFG_MASK << shift;

		/* treated as special case,for two bit configuration */
		if (security_index == HP_SECVIO_ICTL_CFG_DISABLE)
			value = HP_SECVIO_ICTL_CFG_DISABLE;
		else if (security_index == HP_SECVIO_ICTL_CFG_NONFATAL)
			value = HP_SECVIO_ICTL_CFG_NONFATAL;
		else if (security_index == HP_SECVIO_ICTL_CFG_FATAL)
			value = HP_SECVIO_ICTL_CFG_FATAL;
		else
			return TPSV_ERROR_BAD_PARAMETERS;

		value = value << shift;
		break;
	default:
		error("\nInvalid source index, source %d is not configurable.\n", violation_source_index);
		return TPSV_ERROR_BAD_PARAMETERS;
	}

	io_update_bits(address, clear_bit, value);

	return TPSV_SUCCESS;
}

static int get_glitch_configuration(
		unsigned int tamper_detector_source_index,
		int *glitch_flag, int *glitch_length)
{
	int value;

	switch (tamper_detector_source_index) {
	case EXTERNAL_TAMPER_1:
		value = read_mem((unsigned int)&(get_snvs()->lp.tamper_filt_cfg) - (unsigned int)get_snvs());

		*glitch_length = (value & LP_TAMPFILT_EXT1_MASK)
			>> LP_TAMPFILT_EXT1_SHIFT;
		*glitch_flag = (value & LP_TAMPFILT_EXT1_EN_MASK)
			>> LP_TAMPFILT_EXT1_EN_SHIFT;
		break;
	case EXTERNAL_TAMPER_2:
		value = read_mem((unsigned int)&(get_snvs()->lp.tamper_filt_cfg) - (unsigned int)get_snvs());

		*glitch_length = (value & LP_TAMPFILT_EXT2_MASK) >>
			LP_TAMPFILT_EXT2_SHIFT;
		*glitch_flag = (value & LP_TAMPFILT_EXT2_EN_MASK) >>
			LP_TAMPFILT_EXT2_EN_SHIFT;
		break;
#if defined(CONFIG_IMX7)
	case EXTERNAL_TAMPER_3:
		value = read_mem((unsigned int)&(get_snvs()->lp.tamper_filt1_cfg) - (unsigned int)get_snvs());

		*glitch_length = (value & LP_TAMPFILT1_EXT3_MASK) >>
			LP_TAMPFILT1_EXT3_SHIFT;
		*glitch_flag = (value & LP_TAMPFILT1_EXT3_EN_MASK) >>
			LP_TAMPFILT1_EXT3_EN_SHIFT;
		break;
	case EXTERNAL_TAMPER_4:
		value = read_mem((unsigned int)&(get_snvs()->lp.tamper_filt1_cfg) - (unsigned int)get_snvs());

		*glitch_length = (value & LP_TAMPFILT1_EXT4_MASK) >>
			LP_TAMPFILT1_EXT4_SHIFT;
		*glitch_flag = (value & LP_TAMPFILT1_EXT4_EN_MASK) >>
			LP_TAMPFILT1_EXT4_EN_SHIFT;
		break;
	case EXTERNAL_TAMPER_5:
		value = read_mem((unsigned int)&(get_snvs()->lp.tamper_filt1_cfg) - (unsigned int)get_snvs());

		*glitch_length = (value & LP_TAMPFILT1_EXT5_MASK) >>
			LP_TAMPFILT1_EXT5_SHIFT;
		*glitch_flag = (value & LP_TAMPFILT1_EXT5_EN_MASK) >>
			LP_TAMPFILT1_EXT5_EN_SHIFT;
		break;
	case EXTERNAL_TAMPER_6:
		value = read_mem((unsigned int)&(get_snvs()->lp.tamper_filt1_cfg) - (unsigned int)get_snvs());

		*glitch_length = (value & LP_TAMPFILT1_EXT6_MASK) >>
			LP_TAMPFILT1_EXT6_SHIFT;
		*glitch_flag = (value & LP_TAMPFILT1_EXT6_EN_MASK) >>
			LP_TAMPFILT1_EXT6_EN_SHIFT;
		break;
	case EXTERNAL_TAMPER_7:
		value = read_mem((unsigned int)&(get_snvs()->lp.tamper_filt2_cfg) - (unsigned int)get_snvs());

		*glitch_length = (value & LP_TAMPFILT2_EXT7_MASK) >>
			LP_TAMPFILT2_EXT7_SHIFT;
		*glitch_flag = (value & LP_TAMPFILT2_EXT7_EN_MASK) >>
			LP_TAMPFILT2_EXT7_EN_SHIFT;
		break;
	case EXTERNAL_TAMPER_8:
		value = read_mem((unsigned int)&(get_snvs()->lp.tamper_filt2_cfg) - (unsigned int)get_snvs());

		*glitch_length = (value & LP_TAMPFILT2_EXT8_MASK) >>
			LP_TAMPFILT2_EXT8_SHIFT;
		*glitch_flag = (value & LP_TAMPFILT2_EXT8_EN_MASK) >>
			LP_TAMPFILT2_EXT8_EN_SHIFT;
		break;
	case EXTERNAL_TAMPER_9:
		value = read_mem((unsigned int)&(get_snvs()->lp.tamper_filt2_cfg) - (unsigned int)get_snvs());

		*glitch_length = (value & LP_TAMPFILT2_EXT7_MASK) >>
			LP_TAMPFILT2_EXT9_SHIFT;
		*glitch_flag = (value & LP_TAMPFILT2_EXT7_EN_MASK) >>
			LP_TAMPFILT2_EXT9_EN_SHIFT;
		break;
	case EXTERNAL_TAMPER_10:
		value = read_mem((unsigned int)&(get_snvs()->lp.tamper_filt2_cfg) - (unsigned int)get_snvs());

		*glitch_length = (value & LP_TAMPFILT2_EXT10_MASK) >>
			LP_TAMPFILT2_EXT10_SHIFT;
		*glitch_flag = (value & LP_TAMPFILT2_EXT10_EN_MASK) >>
			LP_TAMPFILT2_EXT10_EN_SHIFT;
		break;
#endif
	default:
		error("\nNo glitch filter for source %d\n", tamper_detector_source_index);
		*glitch_length = 0;
		*glitch_flag = 0;
	}

	return 0;
}


/*
 * @brief This API provides information about current
 * configuration of specified tamper detector source.
 *
 * @param[in] tamper detector source
 *
 * @param[out] information about specified source is
 * enabled/disabled to generate security violation
 * @param[out] glitch_flag (glitch filter is enabled or bypassed)
 * @param[out] glitch_length (glitch filter length in hex)
 */
int snvs_get_tamper_detectors_configuration(
	unsigned int tamper_detector_source_index,
	int *assert, int *glitch_flag, int *glitch_length)
{
	int value;
	unsigned int shift, shift_assert = 2;

	if (check_tp_tamper(tamper_detector_source_index) != TPSV_SUCCESS)
		return TPSV_ERROR_BAD_PARAMETERS;

#if defined(CONFIG_IMX6) || defined(CONFIG_MX6UL)

	if ((tamper_detector_source_index == EXTERNAL_TAMPER_1)
		|| (tamper_detector_source_index == EXTERNAL_TAMPER_2))
		get_glitch_configuration(tamper_detector_source_index,
			glitch_flag, glitch_length);
	else {
		error("\nNo glitch filter for this source: %d\n", tamper_detector_source_index);
		*glitch_flag = 0;
		*glitch_length = 0;
	}

	value = read_mem((unsigned int)&(get_snvs()->lp.tamper_det_cfg) - (unsigned int)get_snvs());
#elif defined(CONFIG_IMX7)

	get_glitch_configuration(tamper_detector_source_index,
		glitch_flag, glitch_length);

	if (tamper_detector_source_index <= EXTERNAL_TAMPER_2) {
		value = read_mem((unsigned int)&(get_snvs()->lp.tamper_det_cfg) - (unsigned int)get_snvs());
	} else {
		value = read_mem((unsigned int)&(get_snvs()->lp.tamper_det_cfg2) - (unsigned int)get_snvs());
		shift_assert = 8;
	}
#endif

	shift = get_lp_tamper_detection_source_shift(
		tamper_detector_source_index);
	if (shift == TPSV_ERROR_BAD_PARAMETERS)
		return TPSV_ERROR_BAD_PARAMETERS;

	value = value >> shift;

	*assert = (((value >> shift_assert) & LP_TAMPASSERT_MASK) == 0)? POL_LOW : POL_HIGH;

	value &= LP_TAMPDET_MASK;

	*glitch_flag = (*glitch_flag == 0)? GF_BYPASSED : GF_ENABLED;
	value = (value == 0)? TP_DISABLE : TP_ENABLE;

	return value;
}
//aici
static int glitch_configuration(
	unsigned int tamper_detector_source_index,
	enum gf_enable_t glitch_flag, enum gf_value_t glitch_length)
{
	unsigned int address;
	int clear_bit, value, flag;

	if (glitch_flag == GF_ENABLED)
		flag = GF_ENABLED;
	else if (glitch_flag == GF_BYPASSED)
		flag = GF_BYPASSED;
	else
		return TPSV_ERROR_BAD_PARAMETERS;

#if defined(CONFIG_IMX6) || defined(CONFIG_MX6UL)
	if ((glitch_length < 0) && (glitch_length > 31))
		return TPSV_ERROR_BAD_PARAMETERS;
#elif defined(CONFIG_IMX7)
	if ((glitch_length < 0) && (glitch_length > 127))
		return TPSV_ERROR_BAD_PARAMETERS;
#endif

	switch (tamper_detector_source_index) {
	case EXTERNAL_TAMPER_1:
		address = (unsigned int)&(get_snvs()->lp.tamper_filt_cfg) - (unsigned int)get_snvs();
		clear_bit = LP_TAMPFILT_EXT1_MASK | LP_TAMPFILT_EXT1_EN_MASK;
		value = (glitch_length << LP_TAMPFILT_EXT1_SHIFT)
				| (flag << LP_TAMPFILT_EXT1_EN_SHIFT);
		break;
	case EXTERNAL_TAMPER_2:
		address = (unsigned int)&(get_snvs()->lp.tamper_filt_cfg) - (unsigned int)get_snvs();
		clear_bit = LP_TAMPFILT_EXT2_MASK | LP_TAMPFILT_EXT2_EN_MASK;
		value = (glitch_length << LP_TAMPFILT_EXT2_SHIFT)
				| (flag << LP_TAMPFILT_EXT2_EN_SHIFT);
		break;
#if defined(CONFIG_IMX7)
	case EXTERNAL_TAMPER_3:
		address = (unsigned int)&(get_snvs()->lp.tamper_filt1_cfg) - (unsigned int)get_snvs();
		clear_bit = LP_TAMPFILT1_EXT3_MASK | LP_TAMPFILT1_EXT3_EN_MASK;
		value = (glitch_length << LP_TAMPFILT1_EXT3_SHIFT)
				| (flag << LP_TAMPFILT1_EXT3_EN_SHIFT);
		break;
	case EXTERNAL_TAMPER_4:
		address = (unsigned int)&(get_snvs()->lp.tamper_filt1_cfg) - (unsigned int)get_snvs();
		clear_bit = LP_TAMPFILT1_EXT4_MASK | LP_TAMPFILT1_EXT4_EN_MASK;
		value = (glitch_length << LP_TAMPFILT1_EXT4_SHIFT)
				| (flag << LP_TAMPFILT1_EXT4_EN_SHIFT);
		break;
	case EXTERNAL_TAMPER_5:
		address = (unsigned int)&(get_snvs()->lp.tamper_filt1_cfg) - (unsigned int)get_snvs();
		clear_bit = LP_TAMPFILT1_EXT5_MASK | LP_TAMPFILT1_EXT5_EN_MASK;
		value = (glitch_length << LP_TAMPFILT1_EXT5_SHIFT)
				| (flag << LP_TAMPFILT1_EXT5_EN_SHIFT);
		break;
	case EXTERNAL_TAMPER_6:
		address = (unsigned int)&(get_snvs()->lp.tamper_filt1_cfg) - (unsigned int)get_snvs();
		clear_bit = LP_TAMPFILT1_EXT6_MASK | LP_TAMPFILT1_EXT6_EN_MASK;
		value = (glitch_length << LP_TAMPFILT1_EXT6_SHIFT)
				| (flag << LP_TAMPFILT1_EXT6_EN_SHIFT);
		break;
	case EXTERNAL_TAMPER_7:
		address = (unsigned int)&(get_snvs()->lp.tamper_filt2_cfg) - (unsigned int)get_snvs();
		clear_bit = LP_TAMPFILT2_EXT7_MASK | LP_TAMPFILT2_EXT7_EN_MASK;
		value = (glitch_length << LP_TAMPFILT2_EXT7_SHIFT)
				| (flag << LP_TAMPFILT2_EXT7_EN_SHIFT);
		break;
	case EXTERNAL_TAMPER_8:
		address = (unsigned int)&(get_snvs()->lp.tamper_filt2_cfg) - (unsigned int)get_snvs();
		clear_bit = LP_TAMPFILT2_EXT8_MASK | LP_TAMPFILT2_EXT8_EN_MASK;
		value = (glitch_length << LP_TAMPFILT2_EXT8_SHIFT)
				| (flag << LP_TAMPFILT2_EXT8_EN_SHIFT);
		break;
	case EXTERNAL_TAMPER_9:
		address = (unsigned int)&(get_snvs()->lp.tamper_filt2_cfg) - (unsigned int)get_snvs();
		clear_bit = LP_TAMPFILT2_EXT9_MASK | LP_TAMPFILT2_EXT9_EN_MASK;
		value = (glitch_length << LP_TAMPFILT2_EXT9_SHIFT)
				| (flag << LP_TAMPFILT2_EXT9_EN_SHIFT);
		break;
	case EXTERNAL_TAMPER_10:
		address = (unsigned int)&(get_snvs()->lp.tamper_filt2_cfg) - (unsigned int)get_snvs();
		clear_bit = LP_TAMPFILT2_EXT10_MASK
			| LP_TAMPFILT2_EXT10_EN_MASK;
		value = (glitch_length << LP_TAMPFILT2_EXT10_SHIFT)
				| (flag << LP_TAMPFILT2_EXT10_EN_SHIFT);
		break;
#endif
	default:
		error("\nINVALID SOURCE INDEX: %d\n", tamper_detector_source_index);
		return TPSV_ERROR_BAD_PARAMETERS;
	}
		
	io_update_bits(address, clear_bit, value);

	return 0;
}

/*
 * @brief This API is used to configure specified tamper detector
 * source by enabling it to generate security violation whenever
 * tampering is detected.
 *
 * @param[in] tamper detector source
 * @param[in] flag(Enabled/disabled)
 * @param[in] glitch_flag(Enabled/disabled)
 * @param[in] glitch_length
 *
 * @retval TPSV_ERROR_BAD_PARAMETERS
 * @retval TPSV_SUCCESS
 *
 */
int snvs_set_tamper_detectors_configuration(
	unsigned int tamper_detector_source_index,
	int flag, int assert, int glitch_flag, int glitch_length)
{
	unsigned int address;
	int clear_bit, value;
	unsigned int shift, shift_assert = 2;

	if (check_tp_tamper(tamper_detector_source_index) != TPSV_SUCCESS)
		return TPSV_ERROR_BAD_PARAMETERS;

#if defined(CONFIG_IMX6) || defined(CONFIG_MX6UL)

	if ((tamper_detector_source_index == EXTERNAL_TAMPER_1)
		|| (tamper_detector_source_index == EXTERNAL_TAMPER_2))
		glitch_configuration(tamper_detector_source_index,
			glitch_flag, glitch_length);

	address = (unsigned int)&(get_snvs()->lp.tamper_det_cfg) - (unsigned int)get_snvs();

#elif defined(CONFIG_IMX7)

	glitch_configuration(tamper_detector_source_index,
		glitch_flag, glitch_length);

	if (tamper_detector_source_index <= EXTERNAL_TAMPER_2) {
		address = (unsigned int)&(get_snvs()->lp.tamper_det_cfg) - (unsigned int)get_snvs();
	} else {
		address = (unsigned int)&(get_snvs()->lp.tamper_det_cfg2) - (unsigned int)get_snvs();
		shift_assert = 8;
	}
#endif

	shift = get_lp_tamper_detection_source_shift(
		tamper_detector_source_index);
	if (shift == TPSV_ERROR_BAD_PARAMETERS)
		return TPSV_ERROR_BAD_PARAMETERS;

	clear_bit = 1 << shift | 1 << (shift + shift_assert);
	value = flag << shift | assert << (shift + shift_assert);

	io_update_bits(address, clear_bit, value);

	return 0;
}

#if defined(CONFIG_IMX7)
static unsigned int get_active_tamper_configuration_address(unsigned int active_tamper_index)
{
	unsigned int address;

	if (can_be_active_tamper(active_tamper_index) != TPSV_SUCCESS)
		return TPSV_ERROR_BAD_PARAMETERS;

	switch (active_tamper_index) {
	case ACTIVE_TAMPER_1:
		address = (unsigned int)&(get_snvs()->lp.act_tamper1_cfg) - (unsigned int)get_snvs();
		break;
	case ACTIVE_TAMPER_2:
		address = (unsigned int)&(get_snvs()->lp.act_tamper2_cfg) - (unsigned int)get_snvs();
		break;
	case ACTIVE_TAMPER_3:
		address = (unsigned int)&(get_snvs()->lp.act_tamper3_cfg) - (unsigned int)get_snvs();
		break;
	case ACTIVE_TAMPER_4:
		address = (unsigned int)&(get_snvs()->lp.act_tamper4_cfg) - (unsigned int)get_snvs();
		break;
	case ACTIVE_TAMPER_5:
		address = (unsigned int)&(get_snvs()->lp.act_tamper5_cfg) - (unsigned int)get_snvs();
		break;
	default:
		error("\nINVALID ACTIVE TAMPER INDEX: %d\n", active_tamper_index);
		return TPSV_ERROR_BAD_PARAMETERS;
	}
	return address;
}

static unsigned int get_external_tamper_routing_shift(unsigned int external_tamper_index)
{
	unsigned int shift;

	switch (external_tamper_index) {
	case EXTERNAL_TAMPER_1:
		shift = LP_ET1_ROUTING_CTL_SHIFT;
		break;
	case EXTERNAL_TAMPER_2:
		shift = LP_ET2_ROUTING_CTL_SHIFT;
		break;
	case EXTERNAL_TAMPER_3:
		shift = LP_ET3_ROUTING_CTL_SHIFT;
		break;
	case EXTERNAL_TAMPER_4:
		shift = LP_ET4_ROUTING_CTL_SHIFT;
		break;
	case EXTERNAL_TAMPER_5:
		shift = LP_ET5_ROUTING_CTL_SHIFT;
		break;
	case EXTERNAL_TAMPER_6:
		shift = LP_ET6_ROUTING_CTL_SHIFT;
		break;
	case EXTERNAL_TAMPER_7:
		shift = LP_ET7_ROUTING_CTL_SHIFT;
		break;
	case EXTERNAL_TAMPER_8:
		shift = LP_ET8_ROUTING_CTL_SHIFT;
		break;
	case EXTERNAL_TAMPER_9:
		shift = LP_ET9_ROUTING_CTL_SHIFT;
		break;
	case EXTERNAL_TAMPER_10:
		shift = LP_ET10_ROUTING_CTL_SHIFT;
		break;
	default:
		error("\nINVALID ACTIVE TAMPER INDEX: %d\n", external_tamper_index);
		return TPSV_ERROR_BAD_PARAMETERS;
	}

	return shift;
}

/*
 * @brief This API is used to configure the LFSR which
 * is used for specified active tamper outputs.
 *
 * @param[in] active tamper index(1-5)
 * @param[in] polynomial
 * @param[in] seed
 *
 * @retval TPSV_ERROR_BAD_PARAMETERS
 * @retval TPSV_SUCCESS
 *
 */
int snvs_set_active_tamper_configuration(
	unsigned int active_tamper_index, 
	int polynomial, int seed)
{
	unsigned int address;
	int value;

	if (active_tamper_index > ACTIVE_TAMPER_5)
		return TPSV_ERROR_BAD_PARAMETERS;

	address = get_active_tamper_configuration_address(active_tamper_index);
	if (address == TPSV_ERROR_BAD_PARAMETERS)
		return TPSV_ERROR_BAD_PARAMETERS;

	value = (polynomial << LP_AT_POLYNOMIAL_SHIFT) | seed;
	
	write_mem(value, address);

	return 0;
}

/*
 * @brief This API provides information about current control
 * settings (enable/disable) of LFSR and external pads of
 * specified active tamper.
 *
 * @param[in] active tamper index(1-5)
 *
 * @param[out] information about LFSR is enable or disabled
 * and external pads are set for input or output.
 *
 */
int snvs_get_active_tamper_control(
	unsigned int active_tamper_index,
	int *lfsr_control, int *external_pad_control)
{
	int value;

	if (active_tamper_index > ACTIVE_TAMPER_5)
		return TPSV_ERROR_BAD_PARAMETERS;

	value = read_mem((unsigned int)&(get_snvs()->lp.act_tamper_ctl) - (unsigned int)get_snvs());
	switch (active_tamper_index) {
	case ACTIVE_TAMPER_1:
		*lfsr_control = (value >> LP_AT1_EN_SHIFT) & LP_AT_EN_MASK;
		*external_pad_control = (value >> LP_AT1_PAD_EN_SHIFT)
			& LP_AT_EN_MASK;
		break;
	case ACTIVE_TAMPER_2:
		*lfsr_control = (value >> LP_AT2_EN_SHIFT) & LP_AT_EN_MASK;
		*external_pad_control = (value >> LP_AT2_PAD_EN_SHIFT)
			& LP_AT_EN_MASK;
		break;
	case ACTIVE_TAMPER_3:
		*lfsr_control = (value >> LP_AT3_EN_SHIFT) & LP_AT_EN_MASK;
		*external_pad_control = (value >> LP_AT3_PAD_EN_SHIFT)
			& LP_AT_EN_MASK;
		break;
	case ACTIVE_TAMPER_4:
		*lfsr_control = (value >> LP_AT4_EN_SHIFT) & LP_AT_EN_MASK;
		*external_pad_control = (value >> LP_AT4_PAD_EN_SHIFT)
			& LP_AT_EN_MASK;
		break;
	case ACTIVE_TAMPER_5:
		*lfsr_control = (value >> LP_AT5_EN_SHIFT) & LP_AT_EN_MASK;
		*external_pad_control = (value >> LP_AT5_PAD_EN_SHIFT)
			& LP_AT_EN_MASK;
		break;
	default:
		error("\nINVALID ACTIVE TAMPER INDEX: %d\n", active_tamper_index);
		return TPSV_ERROR_BAD_PARAMETERS;
	}

	return 0;
}

/*
 * @brief This API is used to enable the LFSR which is used for
 * specified active tamper outputs.
 *	It is also used to control external pads to enable for
 * input or output.
 *
 * @param[in] active tamper index(1-5)
 * @param[in] LFSR_flag (enable/disable)
 * @param[in] external_pad as output (enable/disable)
 *
 * @retval TPSV_ERROR_BAD_PARAMETERS
 * @retval TPSV_SUCCESS
 *
 */
int snvs_set_active_tamper_control(
	unsigned int active_tamper_index,
	int lfsr_flag, int external_pad)
{
	unsigned int address;
	int value, clear_bit;

	if (active_tamper_index > ACTIVE_TAMPER_5)
		return TPSV_ERROR_BAD_PARAMETERS;

	address = (unsigned int)&(get_snvs()->lp.act_tamper_ctl) - (unsigned int)get_snvs();
	switch (active_tamper_index) {
	case ACTIVE_TAMPER_1:
		value = (lfsr_flag << LP_AT1_EN_SHIFT)
				| (external_pad << LP_AT1_PAD_EN_SHIFT);
		clear_bit = LP_AT1_PAD_EN_MASK | LP_AT_EN_MASK;
		break;
	case ACTIVE_TAMPER_2:
		value = (lfsr_flag << LP_AT2_EN_SHIFT)
				| (external_pad << LP_AT2_PAD_EN_SHIFT);
		clear_bit = LP_AT2_PAD_EN_MASK | LP_AT2_EN_MASK;
		break;
	case ACTIVE_TAMPER_3:
		value = (lfsr_flag << LP_AT3_EN_SHIFT)
				| (external_pad << LP_AT3_PAD_EN_SHIFT);
		clear_bit = LP_AT3_PAD_EN_MASK | LP_AT3_EN_MASK;
		break;
	case ACTIVE_TAMPER_4:
		value = (lfsr_flag << LP_AT4_EN_SHIFT)
				| (external_pad << LP_AT4_PAD_EN_SHIFT);
		clear_bit = LP_AT4_PAD_EN_MASK | LP_AT4_EN_MASK;
		break;
	case ACTIVE_TAMPER_5:
		value = (lfsr_flag << LP_AT5_EN_SHIFT)
				| (external_pad << LP_AT5_PAD_EN_SHIFT);
		clear_bit = LP_AT5_PAD_EN_MASK | LP_AT5_EN_MASK;
		break;
	default:
		error("\nINVALID ACTIVE TAMPER INDEX %d\n", active_tamper_index);
		return TPSV_ERROR_BAD_PARAMETERS;
	}

	io_update_bits(address, clear_bit, value);

	return 0;
}

/*
 * @brief This API provides information about clock frequency
 * at which LFSRs run for the specified active tamper outputs.
 *
 * @param[in] active tamper index(1-5)
 *
 * @param[out] clock frequency
 *
 */
int snvs_get_active_tamper_clock_control(unsigned int active_tamper_index)
{
	int value, clock_freq;

	if (active_tamper_index > ACTIVE_TAMPER_5)
		return TPSV_ERROR_BAD_PARAMETERS;

	value = read_mem((unsigned int)&(get_snvs()->lp.act_tamper_clk_ctl) - (unsigned int)get_snvs());
	switch (active_tamper_index) {
	case ACTIVE_TAMPER_1:
		clock_freq = (value >> LP_AT1_CLK_CTL_SHIFT)
			& LP_AT_CLK_CTL_MASK;
		break;
	case ACTIVE_TAMPER_2:
		clock_freq = (value >> LP_AT2_CLK_CTL_SHIFT)
			& LP_AT_CLK_CTL_MASK;
		break;
	case ACTIVE_TAMPER_3:
		clock_freq = (value >> LP_AT3_CLK_CTL_SHIFT)
			& LP_AT_CLK_CTL_MASK;
		break;
	case ACTIVE_TAMPER_4:
		clock_freq = (value >> LP_AT4_CLK_CTL_SHIFT)
			& LP_AT_CLK_CTL_MASK;
		break;
	case ACTIVE_TAMPER_5:
		clock_freq = (value >> LP_AT5_CLK_CTL_SHIFT)
			& LP_AT_CLK_CTL_MASK;
		break;
	default:
		error("\nINVALID ACTIVE TAMPER INDEX: %d\n", active_tamper_index);
		return TPSV_ERROR_BAD_PARAMETERS;
	}

	switch(clock_freq) {
		case 0: clock_freq = FREQ_16HZ; break;
		case 1: clock_freq = FREQ_8HZ; break;
		case 2: clock_freq = FREQ_4HZ; break;
		case 3: clock_freq = FREQ_2HZ; break;
		default: clock_freq = TPSV_ERROR_BAD_PARAMETERS;
	}

	return clock_freq;
}

/*
 * @brief This API is used to define at what frequency LFSRs are run for
 * the specified active tamper outputs.
 *
 * @param[in] active tamper index(1-5)
 * @param[in] clock_frequency in hz
 *
 * @retval TPSV_ERROR_BAD_PARAMETERS
 * @retval TPSV_SUCCESS
 *
 */
int snvs_set_active_tamper_clock_control(
	unsigned int active_tamper_index, int clock_freq)
{
	int value, clear_bit;
	unsigned int address;

	if (active_tamper_index > ACTIVE_TAMPER_5)
		return TPSV_ERROR_BAD_PARAMETERS;

	switch (clock_freq) {
	case 2:
		value = LP_AT_CLK_2HZ;
		break;
	case 4:
		value = LP_AT_CLK_4HZ;
		break;
	case 8:
		value = LP_AT_CLK_8HZ;
		break;
	case 16:
		value = LP_AT_CLK_16HZ;
		break;
	default:
		error("\nInvalid clock frequency: %d\n", active_tamper_index);
		return TPSV_ERROR_BAD_PARAMETERS;
	}

	switch (active_tamper_index) {
	case ACTIVE_TAMPER_1:
		value = value << LP_AT1_CLK_CTL_SHIFT;
		clear_bit = LP_AT_CLK_CTL_MASK;
		break;
	case ACTIVE_TAMPER_2:
		value = value << LP_AT2_CLK_CTL_SHIFT;
		clear_bit = LP_AT2_CLK_CTL_MASK;
		break;
	case ACTIVE_TAMPER_3:
		value = value << LP_AT3_CLK_CTL_SHIFT;
		clear_bit = LP_AT3_CLK_CTL_MASK;
		break;
	case ACTIVE_TAMPER_4:
		value = value << LP_AT4_CLK_CTL_SHIFT;
		clear_bit = LP_AT4_CLK_CTL_MASK;
		break;
	case ACTIVE_TAMPER_5:
		value = value << LP_AT5_CLK_CTL_SHIFT;
		clear_bit = LP_AT5_CLK_CTL_MASK;
		break;
	default:
		error("\nINVALID ACTIVE TAMPER INDEX: %d\n", active_tamper_index);
		return TPSV_ERROR_BAD_PARAMETERS;
	}
	address = (unsigned int)&(get_snvs()->lp.act_tamper_clk_ctl) - (unsigned int)get_snvs();
		
	io_update_bits(address, clear_bit, value);

	return 0;
}

/*
 * @brief This API is used to define what pattern will be produced by the
 * AT configuring the polynomial and the seed
 *
 * @param[in] active tamper index(1-5)
 * @param[in] clock_frequency in hz
 *
 * @retval TPSV_ERROR_BAD_PARAMETERS
 * @retval TPSV_SUCCESS
 *
 */
int snvs_set_active_tamper_pattern(
	unsigned int active_tamper_index,
	int polynomial, int seed)
{
	unsigned int address;
	unsigned int pattern;

	switch (active_tamper_index) {
	case ACTIVE_TAMPER_1:
		address = (unsigned int)&(get_snvs()->lp.act_tamper1_cfg) - (unsigned int)get_snvs();
		break;
	case ACTIVE_TAMPER_2:
		address = (unsigned int)&(get_snvs()->lp.act_tamper2_cfg) - (unsigned int)get_snvs();
		break;
	case ACTIVE_TAMPER_3:
		address = (unsigned int)&(get_snvs()->lp.act_tamper3_cfg) - (unsigned int)get_snvs();
		break;
	case ACTIVE_TAMPER_4:
		address = (unsigned int)&(get_snvs()->lp.act_tamper4_cfg) - (unsigned int)get_snvs();
		break;
	case ACTIVE_TAMPER_5:
		address = (unsigned int)&(get_snvs()->lp.act_tamper5_cfg) - (unsigned int)get_snvs();
		break;
	default:
		error("\nINVALID ACTIVE TAMPER INDEX: %d\n", active_tamper_index);
		return TPSV_ERROR_BAD_PARAMETERS;
	}

	pattern = polynomial << 16 | seed;

	write_mem(pattern, address);

	return 0;
}

/*
 * @brief This API provides information about routing of compare value
 * for specified external tamper source.
 *
 * @param[in] external tamper index(1-10)
 *
 * @param[out] active tamper index(1-5)
 *
 */
int snvs_get_active_tamper_routing_control(
	unsigned int external_tamper_index)
{
	int value, route;
	unsigned int shift;

	if (check_tp_tamper(external_tamper_index) != TPSV_SUCCESS)
		return TPSV_ERROR_BAD_PARAMETERS;

	if ((external_tamper_index == EXTERNAL_TAMPER_9)
			|| (external_tamper_index == EXTERNAL_TAMPER_10))
		value = read_mem((unsigned int)&(get_snvs()->lp.act_tamper_routing_ctl2) - (unsigned int)get_snvs());
	else
		value = read_mem((unsigned int)&(get_snvs()->lp.act_tamper_routing_ctl1) - (unsigned int)get_snvs());

	shift = get_external_tamper_routing_shift(external_tamper_index);
	if (shift == TPSV_ERROR_BAD_PARAMETERS)
		return TPSV_ERROR_BAD_PARAMETERS;

	route = (value >> shift) & LP_ET_ROUTING_CTL_MASK;

	route = (route == PASSIVE_TAMPER)?
				PASSIVE_TAMPER : route + ACTIVE_TAMPER_1 -1;

	return route;
}


/*
 * @brief This API is used to set routing of compare value between specified
 * external tamper source (1-10) and specified active tamper (1-5)
 *
 * @param[in] external tamper index(1-10)
 * @param[in] active tamper index(1-5)
 *
 * @retval TPSV_ERROR_BAD_PARAMETERS
 * @retval TPSV_SUCCESS
 *
 */
int snvs_set_active_tamper_routing_control(
	unsigned int external_tamper_index,
	unsigned int active_tamper_index)
{
	int clear_bit, route;
	unsigned int address, shift;

	if (check_tp_tamper(external_tamper_index) != TPSV_SUCCESS)
		return TPSV_ERROR_BAD_PARAMETERS;

	if ((external_tamper_index == EXTERNAL_TAMPER_9)
			|| (external_tamper_index == EXTERNAL_TAMPER_10))
		address = (unsigned int)&(get_snvs()->lp.act_tamper_routing_ctl2) - (unsigned int)get_snvs();
	else
		address = (unsigned int)&(get_snvs()->lp.act_tamper_routing_ctl1) - (unsigned int)get_snvs();

	shift = get_external_tamper_routing_shift(external_tamper_index);
	if (shift == TPSV_ERROR_BAD_PARAMETERS)
		return TPSV_ERROR_BAD_PARAMETERS;

	clear_bit = LP_ET_ROUTING_CTL_MASK << shift;

	switch (active_tamper_index) {
	case PASSIVE_TAMPER:
		route = LP_PASSIVE_INPUT_ROUTE;
		break;
	case ACTIVE_TAMPER_1:
		route = LP_ACTIVE_TAMPER_1_ROUTE;
		break;
	case ACTIVE_TAMPER_2:
		route = LP_ACTIVE_TAMPER_2_ROUTE;
		break;
	case ACTIVE_TAMPER_3:
		route = LP_ACTIVE_TAMPER_3_ROUTE;
		break;
	case ACTIVE_TAMPER_4:
		route = LP_ACTIVE_TAMPER_4_ROUTE;
		break;
	case ACTIVE_TAMPER_5:
		route = LP_ACTIVE_TAMPER_5_ROUTE;
		break;
	default:
		error("\nINVALID ACTIVE TAMPER INDEX: %d\n", active_tamper_index);
		return TPSV_ERROR_BAD_PARAMETERS;
	}

	io_update_bits(address, clear_bit, (route << shift));

	return 0;
}
#endif

/*
 * @brief This API provides information that specified violation source is
 * enabled or disabled in LP domain.
 *
 * @param[in] source
 *
 * @param[out] Enabled/Disabled
 */
int snvs_get_security_violation_configuration(unsigned int violation_source_index)
{
	int value;
	int shift;

	/* AS only SECURITY_VIOLATION_INPUT_0 to SECURITY_VIOLATION_INPUT_5
		sources are configurable */
	if (check_sv_source(violation_source_index) != TPSV_SUCCESS)
		return TPSV_ERROR_BAD_PARAMETERS;

	shift = get_security_violation_input_source_shift(
		violation_source_index);
	if (shift < 0)
		return TPSV_ERROR_BAD_PARAMETERS;

	value = read_mem((unsigned int)&(get_snvs()->lp.secvio_ctl) - (unsigned int)get_snvs());
	value = value >> shift;
	value &= LP_SECVIO_CTL_MASK;

	return value;
}

/*
 * @brief This API is used to enable/disable specified violation
 * source in LP domain.
 *
 * @param[in] source
 * @param[in] control(Enabled/disabled)
 *
 * @retval TPSV_ERROR_BAD_PARAMETERS
 * @retval TPSV_SUCCESS
 *
 */
int snvs_set_security_violation_configuration(
	unsigned int violation_source_index, int flag)
{
	unsigned int address;
	int clear_bit, value, shift;

	/* Bypass */
	if (violation_source_index == LP_SECURITY_VIOLATION)
		return 0;

	/* AS only SECURITY_VIOLATION_INPUT_0 to SECURITY_VIOLATION_INPUT_5
		sources are configurable */
	if (check_sv_source(violation_source_index) != TPSV_SUCCESS)
		return TPSV_ERROR_BAD_PARAMETERS;

	shift = get_security_violation_input_source_shift(
		violation_source_index);
	if (shift < 0)
		return TPSV_ERROR_BAD_PARAMETERS;
	
	address = (unsigned int)&(get_snvs()->lp.secvio_ctl) - (unsigned int)get_snvs();
	clear_bit = 1 << shift;
	value = flag << shift;

	io_update_bits(address, clear_bit, value);

	return 0;
}

/*
 * @brief This API provides information about specified security violation
 * source is enable/disable to generate interrupt upon security violation
 * from LP section.
 *
 * @param[in] security violation source
 *
 * @param[out] information about specified source is enabled/disabled to
 * generate security violation
 */
int snvs_get_interrupt_generation_policy(unsigned int
	violation_source_index)
{
	int value;
	int shift;

	shift = get_security_violation_input_source_shift(
		violation_source_index);
	if (shift < 0)
		return TPSV_ERROR_BAD_PARAMETERS;

	value = read_mem((unsigned int)&(get_snvs()->hp.secvio_intcfg) - (unsigned int)get_snvs());

	if (violation_source_index == LP_SECURITY_VIOLATION)
		value = value >> HP_SECVIO_INTEN_LP_SHIFT;
	else
		value = value >> shift;

	value &= HP_SECVIO_INTEN_MASK;

	return value;
}

/*
 * @brief This API is used to enable/disable generation of the security interrupt
 * upon security violation signal from the LP section.
 *
 * @param[in] security violation source
 * @param[in] generating interrupt(Enabled/disabled)
 *
 * @retval TPSV_ERROR_BAD_PARAMETERS
 * @retval TPSV_SUCCESS
 *
 */
int snvs_set_interrupt_generation_policy(
	unsigned int violation_source_index, int flag)
{
	unsigned int address;
	int clear_bit, value, shift;

	shift = get_security_violation_input_source_shift(
		violation_source_index);
	if (shift < 0)
		return TPSV_ERROR_BAD_PARAMETERS;

	address = (unsigned int)&(get_snvs()->hp.secvio_intcfg) - (unsigned int)get_snvs();

	if (violation_source_index == LP_SECURITY_VIOLATION) {
		clear_bit = HP_SECVIO_INTEN_LP;
		value = flag << HP_SECVIO_INTEN_LP_SHIFT;
	} else {
		clear_bit = 1 << shift;
		value = flag << shift;
	}

	io_update_bits(address, clear_bit, value);

	return 0;
}

/*
 * @brief This API provides information about current system security monitor states.
 *
 * @param[out] current System security monitor state(SSM)
 */
int snvs_get_ssm_current_state(void)
{
	int value;

	value = read_mem((unsigned int)&(get_snvs()->hp.status) - (unsigned int)get_snvs());
	value = value >> HP_STATUS_SSM_ST_SHIFT;
	value &= HP_STATUS_SSM_ST_MASK;

	return value;
}

/*
 * @brief This API provides information about specified SSM state transition
 * (Secure to Trusted state transition and Soft Fail to Non-Secure transition)
 * is enabled or disabled.
 *
 * @param[in] specify state transition (Secure to Trusted state transition or
 * Soft Fail to Non-Secure transition).
 *
 * @param[out] Enable/Disable based on specified transition
 *	is enable or disable.
 */
int snvs_get_ssm_state_transition_permission(
		unsigned int transition_index)
{
	int value;
	int transition_shift;

	if ((transition_index != SECURE_TO_TRUSTED)
		&& (transition_index != SOFT_FAIL_TO_NON_SECURE))
		return TPSV_ERROR_BAD_PARAMETERS;

	value = read_mem((unsigned int)&(get_snvs()->hp.cmd) - (unsigned int)get_snvs());

	switch (transition_index) {
	case SECURE_TO_TRUSTED:
		transition_shift = HP_CMD_SSM_ST_SHIFT;
		break;
	case SOFT_FAIL_TO_NON_SECURE:
		transition_shift = HP_CMD_SSM_SFNS_SHIFT;
		break;
	default:
		error("\nINVALID transition INDEX: %d\n", transition_index);
		return TPSV_ERROR_BAD_PARAMETERS;
	}

	value = value >> transition_shift;
	value &= HP_CMD_SSM_ST_MASK;

	return value;
}

/*
 * @brief This API is used to enable or disable specified SSM state
 * transition.
 *
 * @param[in] specify state transition (Secure to Trusted state
 * transition or Soft Fail to Non-Secure transition).
 *
 * @param[in] flag (true/false). flag = true-> disable state
 * transition,flag = false -> enable state transition.
 *
 */
int snvs_set_ssm_state_transition_permission(
	unsigned int transition_index, int flag)
{
	int clear_bit, transition_shift;
	unsigned int address;

	if ((transition_index != SECURE_TO_TRUSTED)
		&& (transition_index != SOFT_FAIL_TO_NON_SECURE))
		return TPSV_ERROR_BAD_PARAMETERS;

	address = (unsigned int)&(get_snvs()->hp.cmd) - (unsigned int)get_snvs();

	switch (transition_index) {
	case SECURE_TO_TRUSTED:
		clear_bit = HP_CMD_SSM_ST_DIS;
		transition_shift = HP_CMD_SSM_ST_SHIFT;
		break;
	case SOFT_FAIL_TO_NON_SECURE:
		clear_bit = HP_CMD_SSM_SFNS_DIS;
		transition_shift = HP_CMD_SSM_SFNS_SHIFT;
		break;
	default:
		error("\nINVALID transition INDEX: %d\n", transition_index);
		return TPSV_ERROR_BAD_PARAMETERS;
	}
	/* update state transition disable bit (bit1 or bit2) */
	io_update_bits(address, clear_bit, flag << transition_shift);

	return TPSV_SUCCESS;
}

int snvs_ssm_state_transition(void)
{
	unsigned int address;

	address = (unsigned int)&(get_snvs()->hp.cmd) - (unsigned int)get_snvs();
	
	io_update_bits(address, HP_CMD_SSM_ST, HP_CMD_SSM_ST);

	return 0;
}

TPSV_Result apply_sv_conf(struct secviol_config_t * sv_conf)
{
	unsigned int source_index, policy_choice, config_choice, action_choice;
	TPSV_Result policy_res, config_res, action_res;

	if (sv_conf == NULL) {
		debug("No sv configuration to apply\n");
		return TPSV_ERROR_BAD_PARAMETERS;
	}

	source_index = sv_conf->source;
	policy_choice = sv_conf->policy;
	config_choice = sv_conf->enable;
	action_choice = sv_conf->itr_ena;

	policy_res = snvs_set_security_violation_policy(source_index, policy_choice);
	config_res = snvs_set_security_violation_configuration(source_index, config_choice);
	action_res = snvs_set_interrupt_generation_policy(source_index, action_choice);
	if (policy_res != TPSV_SUCCESS || config_res != TPSV_SUCCESS || action_res != TPSV_SUCCESS) {
		debug("%x %x %x\n", policy_res, config_res, action_res);
		return TPSV_ERROR_BAD_PARAMETERS;
	}

	return TPSV_SUCCESS;
}

TPSV_Result retrieve_sv_conf(struct secviol_config_t * sv_conf, enum hp_secvio_source_t source)
{
	unsigned int policy, config, itr;
	TPSV_Result res;
	if (sv_conf == NULL) {
		debug("No sv configuration to retrieve\n");
		return TPSV_ERROR_BAD_PARAMETERS;
	}

	policy = snvs_get_security_violation_policy(source);
	config = snvs_get_security_violation_configuration(source);
	itr = snvs_get_interrupt_generation_policy(source);
	
	if (policy == TPSV_ERROR_BAD_PARAMETERS
		|| config == TPSV_ERROR_BAD_PARAMETERS
		|| itr == TPSV_ERROR_BAD_PARAMETERS)
	{
		error("Error reading secviol config setted: %x, %x, %x", policy, config, itr);
		return TPSV_ERROR_BAD_PARAMETERS;
	}
	res = secviol_config_factory(sv_conf, source, config, policy, itr);
	if (res != TPSV_SUCCESS) {
		error("Can't build secviol config setted");
		return TPSV_ERROR_BAD_PARAMETERS;
	}
	return TPSV_SUCCESS;
}

TPSV_Result apply_tp_conf(struct tamper_config_t * tp_conf)
{
	unsigned int glitch_ena, enable, glitch_value, polarity;
	TPSV_Result tamper_res;

	if (tp_conf == NULL) {
		debug("No tp configuration to apply\n");
		return TPSV_ERROR_BAD_PARAMETERS;
	}

	enable = tp_conf->enable;
	glitch_ena = tp_conf->gf_enable;
	glitch_value = tp_conf->gf_value;
	polarity = tp_conf->assert_val;

	tamper_res = snvs_set_tamper_detectors_configuration(
				tp_conf->tamper, enable, polarity, glitch_ena, glitch_value);

	if (tamper_res != TPSV_SUCCESS) {
		debug("can't set tamper conf\n");
		return TPSV_ERROR_BAD_PARAMETERS;
	}

#if defined(CONFIG_IMX7)
	{
		TPSV_Result routing_res = snvs_set_active_tamper_routing_control(tp_conf->tamper, tp_conf->at_source);
		if (routing_res != TPSV_SUCCESS) {
			error("can't set at_source");
			return TPSV_ERROR_BAD_PARAMETERS;
		}
	}

	if (can_be_active_tamper(tp_conf->tamper) == TPSV_SUCCESS) {
		TPSV_Result res;
		unsigned int lfsr, ext_pad;

		res = snvs_set_active_tamper_pattern(tp_conf->tamper, tp_conf->at_poly, tp_conf->at_seed);
		if (res != TPSV_SUCCESS) {
			debug("Error setting pattern\n");
			return TPSV_ERROR_BAD_PARAMETERS;
		}

		res = snvs_set_active_tamper_clock_control(tp_conf->tamper, tp_conf->at_freq);
		if (res != TPSV_SUCCESS) {
			debug("Error setting freq\n");
			return TPSV_ERROR_BAD_PARAMETERS;
		}

		lfsr = ext_pad = tp_conf->at_enable;
		res = snvs_set_active_tamper_control(tp_conf->tamper, lfsr, ext_pad);
		if (res != TPSV_SUCCESS)
		{
			debug("Error setting at control\n");
			return TPSV_ERROR_BAD_PARAMETERS;
		}
	}
#endif

	return TPSV_SUCCESS;
}

TPSV_Result retrieve_tp_conf(struct tamper_config_t * tp_conf, enum lp_tamper_detector_t tamper)
{
	int mode, enable, assert, gf_ena, gf_value, at_source, at_freq, at_enable;
	TPSV_Result res;

	if (tp_conf == NULL) {
		debug("No tp configuration to retrieve\n");
		return TPSV_ERROR_BAD_PARAMETERS;
	}


	enable = snvs_get_tamper_detectors_configuration(tamper, &assert, &gf_ena, &gf_value);
	if ((unsigned int)enable == TPSV_ERROR_BAD_PARAMETERS) {
		error("Error reading tamper config setted");
		return TPSV_ERROR_BAD_PARAMETERS;
	}

	at_source = PASSIVE_TAMPER;
	at_freq = FREQ_16HZ;
	at_enable = AT_DISABLE;

	/* We determine the mode */
	mode = MODE_PASSIVE;

#if defined(CONFIG_IMX7)

	at_source = snvs_get_active_tamper_routing_control(tamper);
	if (check_active_routing(at_source) == TPSV_SUCCESS) {
		mode = MODE_ACTIVE_IN;
	}

	if (can_be_active_tamper(tamper) == TPSV_SUCCESS) {
		int lfsr, ext_pad;

		at_freq = snvs_get_active_tamper_clock_control(tamper);
		if ((unsigned int)at_freq == TPSV_ERROR_BAD_PARAMETERS) {
			error("Error reading freq setted");
			return TPSV_ERROR_BAD_PARAMETERS;
		}

		res = snvs_get_active_tamper_control(tamper, &lfsr, &ext_pad);
		if (res != TPSV_SUCCESS)
		{
			error("Error reading at control setted");
			return TPSV_ERROR_BAD_PARAMETERS;
		}

		at_enable = lfsr && ext_pad;
		if (at_enable) {
			mode = MODE_ACTIVE_OUT;
		}
	}
#endif

	res = tamper_config_factory(tp_conf, mode, tamper, enable, assert, gf_ena, gf_value, at_source, at_enable, at_freq, AT_POLY_DEFAULT, AT_SEED_DEFAULT);
	if (res != TPSV_SUCCESS) {
		error("Can't build tamper config setted");
		return TPSV_ERROR_BAD_PARAMETERS;
	}

	return TPSV_SUCCESS;
}

