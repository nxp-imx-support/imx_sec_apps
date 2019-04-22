/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SNVS_SECURITY_H_
#define SNVS_SECURITY_H_

#define pr_fmt(fmt) "security: " fmt
#define debug(fmt, args...)	printf(fmt, ##args)
#define error(fmt, args...) do {					\
		printf("ERROR: " pr_fmt(fmt) "\nat %s:%d/%s()\n",	\
			##args, __FILE__, __LINE__, __func__);		\
} while (0)
	
#define true 1
#define false 0

#define TPSV_SUCCESS 0
#define TPSV_ERROR_BAD_PARAMETERS 0xFFFFFFFF
	
typedef int bool;
typedef unsigned int u32;
typedef unsigned int TPSV_Result;
typedef unsigned char u8;

/* Full SNVS register page, including version/options */
/*
 * SNVS High Power Domain
 * Includes security violations, HA counter, RTC, alarm
 */
struct snvs_hp {
	u32 lock;		/* HPLR - HP Lock */
	u32 cmd;		/* HPCOMR - HP Command */
	u32 ctl;		/* HPCR - HP Control */
	u32 secvio_intcfg;	/* HPSICR - Security Violation Int Config */
	u32 secvio_ctl;		/* HPSVCR - Security Violation Control */
	u32 status;		/* HPSR - HP Status */
	u32 secvio_status;	/* HPSVSR - Security Violation Status */
	u32 ha_counteriv;	/* High Assurance Counter IV */
	u32 ha_counter;		/* High Assurance Counter */
	u32 rtc_msb;		/* Real Time Clock/Counter MSB */
	u32 rtc_lsb;		/* Real Time Counter LSB */
	u32 time_alarm_msb;	/* Time Alarm MSB */
	u32 time_alarm_lsb;	/* Time Alarm LSB */
};

/*
 * SNVS Low Power Domain
 * Includes glitch detector, SRTC, alarm, monotonic counter, ZMK
 */
struct snvs_lp {
	u32 lock;
	u32 ctl;
	u32 mstr_key_ctl;	/* Master Key Control */
	u32 secvio_ctl;		/* Security Violation Control */
	u32 tamper_filt_cfg;	/* Tamper Glitch Filters Configuration */
	u32 tamper_det_cfg;	/* Tamper Detectors Configuration */
	u32 status;
	u32 srtc_msb;		/* Secure Real Time Clock/Counter MSB */
	u32 srtc_lsb;		/* Secure Real Time Clock/Counter LSB */
	u32 time_alarm;		/* Time Alarm */
	u32 smc_msb;		/* Secure Monotonic Counter MSB */
	u32 smc_lsb;		/* Secure Monotonic Counter LSB */
	u32 pwr_glitch_det;	/* Power Glitch Detector */
	u32 gen_purpose;
	u8 zmk[32];		/* Zeroizable Master Key */
	u32 rsvd0;
	u32 gen_purposes[4];	/* gp0_30 to gp0_33 */
	u32 tamper_det_cfg2;	/* Tamper Detectors Configuration2 */
	u32 tamper_det_status;	/* Tamper Detectors status */
	u32 tamper_filt1_cfg;	/* Tamper Glitch Filter1 Configuration */
	u32 tamper_filt2_cfg;	/* Tamper Glitch Filter2 Configuration */
	u32 rsvd1[4];
	u32 act_tamper1_cfg;	/* Active Tamper1 Configuration */
	u32 act_tamper2_cfg;	/* Active Tamper2 Configuration */
	u32 act_tamper3_cfg;	/* Active Tamper3 Configuration */
	u32 act_tamper4_cfg;	/* Active Tamper4 Configuration */
	u32 act_tamper5_cfg;	/* Active Tamper5 Configuration */
	u32 rsvd2[3];
	u32 act_tamper_ctl;	/* Active Tamper Control */
	u32 act_tamper_clk_ctl;	/* Active Tamper Clock Control */
	u32 act_tamper_routing_ctl1;	/* Active Tamper Routing Control1 */
	u32 act_tamper_routing_ctl2;	/* Active Tamper Routing Control2 */
};

struct snvs_full {
	struct snvs_hp hp;
	struct snvs_lp lp;

	u32 rsvd[706];		/* deadspace 0x0F0-0xbf7 */

	/* Version / Revision / Option ID space - end of register page */
	u32 vid;		/* 0xbf8 HP Version ID (VID 1) */
	u32 opt_rev;		/* 0xbfc HP Options / Revision (VID 2) */
};

#define __unused __attribute__((unused))
#define __maybe_unused __attribute__((unused))

#define HP_SOFTWARE_SECURITY_VIOLATION	1

#define HP_CMD_SW_LPSV_SHIFT		10
#define HP_CMD_SW_LPSV_MASK		0x1
#define HP_CMD_SW_FSV_SHIFT		9
#define HP_CMD_SW_SV_SHIFT		8
#define HP_CMD_SW_MASK			0x3
#define HP_CMD_SW_LPSV			0x00000400
#define HP_CMD_SW_FSV			0x00000200
#define HP_CMD_SW_SV			0x00000100
#define HP_CMD_SSM_ST_MASK		0x00000001
#define HP_CMD_SSM_SFNS_SHIFT		2
#define HP_CMD_SSM_ST_SHIFT		1
#define HP_CMD_SSM_SFNS_DIS		0x00000004
#define HP_CMD_SSM_ST_DIS		0x00000002
#define HP_CMD_SSM_ST			0x00000001

#define HP_SECVIO_INTEN_MASK		0x1
#define HP_SECVIO_INTEN_LP_SHIFT	31
#define HP_SECVIO_INTEN_LP		0x80000000
#define HP_SECVIO_INTEN_SRC5		0x00000020
#define HP_SECVIO_INTEN_SRC4		0x00000010
#define HP_SECVIO_INTEN_SRC3		0x00000008
#define HP_SECVIO_INTEN_SRC2		0x00000004
#define HP_SECVIO_INTEN_SRC1		0x00000002
#define HP_SECVIO_INTEN_SRC0		0x00000001
#define HP_SECVIO_INTEN_ALL		0x8000003f

#define HP_SECVIO_ICTL_LPSV_SHIFT	30
#define HP_SECVIO_ICTL_CFG5_SHIFT	5
#define HP_SECVIO_ICTL_CFG4_SHIFT	4
#define HP_SECVIO_ICTL_CFG3_SHIFT	3
#define HP_SECVIO_ICTL_CFG2_SHIFT	2
#define HP_SECVIO_ICTL_CFG1_SHIFT	1
#define HP_SECVIO_ICTL_CFG0_SHIFT	0
#define HP_SECVIO_ICTL_CFG_BIT		0x00000001
#define HP_SECVIO_ICTL_CFG_MASK		0x3
#define HP_SECVIO_ICTL_CFG_DISABLE	0
#define HP_SECVIO_ICTL_CFG_NONFATAL	1
#define HP_SECVIO_ICTL_CFG_FATAL	2

#define HP_STATUS_SSM_ST_SHIFT		8
#define HP_STATUS_SSM_ST_MASK		0xf
#define HP_STATUS_SSM_ST_INIT		0
#define HP_STATUS_SSM_ST_HARDFAIL	1
#define HP_STATUS_SSM_ST_SOFTFAIL	3
#define HP_STATUS_SSM_ST_INITINT	8
#define HP_STATUS_SSM_ST_CHECK		9
#define HP_STATUS_SSM_ST_NONSECURE	11
#define HP_STATUS_SSM_ST_TRUSTED	13
#define HP_STATUS_SSM_ST_SECURE		15

#define HP_SECVIOST_ZMK_ECC_FAIL	0x08000000	/* write to clear */
#define HP_SECVIOST_ZMK_SYN_SHIFT	16
#define HP_SECVIOST_ZMK_SYN_MASK	(0x1ff << HP_SECVIOST_ZMK_SYN_SHIFT)
#define HP_SECVIOST_SECVIO5		0x00000020
#define HP_SECVIOST_SECVIO4		0x00000010
#define HP_SECVIOST_SECVIO3		0x00000008
#define HP_SECVIOST_SECVIO2		0x00000004
#define HP_SECVIOST_SECVIO1		0x00000002
#define HP_SECVIOST_SECVIO0		0x00000001
#define HP_SECVIOST_SECVIOMASK		0x0000003f


/* define the tampering mode */
enum tampering_mode_t {
	MODE_PASSIVE = 0,
	MODE_ACTIVE_IN = 1,
	MODE_ACTIVE_OUT = 2,
};

enum nb_param_conf {
#if defined(CONFIG_IMX7)
	NB_TAMPERS = 10,
#else
	NB_TAMPERS = 2,
#endif
	NB_PARAM_TAMPER_CONF = 6,
	NB_SECVIOLS = 7,
	NB_PARAM_SECVIOL_CONF = 4,
};

enum sw_source {
	SW_NONFATAL_VIOLATION,
	SW_FATAL_VIOLATION,
	SW_LP_SECURITY_VIOLATION,
};

/* state transition which is to be enables or disabled */
enum state_transition_source {
	SECURE_TO_TRUSTED = 29,
	SOFT_FAIL_TO_NON_SECURE,
};

/* these are type of software security violation */
enum software_security {
	SOFTWARE_NON_FATAL_SECURITY = 1,
	SOFTWARE_FATAL_SECURITY,
};

/* these are the HP security violation source */
enum hp_secvio_source_t {
	SECURITY_VIOLATION_INPUT_0 = 0,
	SECURITY_VIOLATION_INPUT_1,
	SECURITY_VIOLATION_INPUT_2,
	SECURITY_VIOLATION_INPUT_3,
	SECURITY_VIOLATION_INPUT_4,
	SECURITY_VIOLATION_INPUT_5,
	LP_SECURITY_VIOLATION,
	SCAN_EXIT_VIOLATION,
	SOFTWARE_FATAL_VIOLATION,
	SOFTWARE_NONFATAL_VIOLATION,
	BAD_MASTER_KEY_VIOLATION,
	/* FROM LP section */
	LP_POR,
};

/* enum for enable/disable security violation */
enum sv_enable_t {
	SV_DISABLE = 0,
	SV_ENABLE,
};

/* these are type of security violation */
enum sv_policy_t {
	POLICY_DISABLE = 0,
	POLICY_NON_FATAL,
	POLICY_FATAL,
};

enum sv_itr_enable_t {
	SV_ITR_DISABLE = 0,
	SV_ITR_ENABLE,
};

struct secviol_config_t {
	enum hp_secvio_source_t source;
	enum sv_enable_t enable;
	enum sv_policy_t policy;
	enum sv_itr_enable_t itr_ena;
};

/* tamper detectors */
enum lp_tamper_detector_t {
	EXTERNAL_TAMPER_1 = 0,
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
	SRTC_ROLLOVER_VIOLATION,
	MC_ROLLOVER_VIOLATION,
	SRTC_CLOCK_TAMPER,
	TEMPERATURE_TAMPER,
	VOLTAGE_TAMPER,
	WIRE_MESH_TAMPER_1,
	WIRE_MESH_TAMPER_2,
};

/* enum for enable/disable */
enum tp_enable_t {
	TP_DISABLE = 0,
	TP_ENABLE,
};

enum tp_polarity_t {
	POL_LOW,
	POL_HIGH,
};

/* enum for glitch filter configuration */
enum gf_enable_t {
	GF_BYPASSED = 0,
	GF_ENABLED,
};

enum gf_value_t {
	GF_VALUE_MIN = 0x0,
	GF_VALUE_MAX = 0x7f,
};

#if defined(CONFIG_IMX7)
/* these are the active tamper sources */
enum active_tamper_t {
	PASSIVE_TAMPER,
	ACTIVE_TAMPER_1 = EXTERNAL_TAMPER_6,
	ACTIVE_TAMPER_2 = EXTERNAL_TAMPER_7,
	ACTIVE_TAMPER_3 = EXTERNAL_TAMPER_8,
	ACTIVE_TAMPER_4 = EXTERNAL_TAMPER_9,
	ACTIVE_TAMPER_5 = EXTERNAL_TAMPER_10,
};

enum at_frequency_t {
	FREQ_2HZ = 2,
	FREQ_4HZ = 4,
	FREQ_8HZ = 8,
	FREQ_16HZ = 16,
};

enum at_enable_t {
	AT_DISABLE = 0,
	AT_ENABLE,
};

enum at_polynomial_t {
	AT_POLY_MIN = 1,
	AT_POLY_DEFAULT = 0x8400,
	AT_POLY_MAX = 0xFFFF,
};

enum at_seed_t {
	AT_SEED_MIN = 1,
	AT_SEED_DEFAULT = 0x1111,
	AT_SEED_MAX = 0xFFFF,
};

#else
enum active_tamper_t{PASSIVE_TAMPER};
enum at_frequency_t {FREQ_16HZ};
enum at_enable_t {AT_DISABLE};
enum at_polynomial_t {AT_POLY_DEFAULT = 0x8400};
enum at_seed_t {AT_SEED_DEFAULT = 0x1111};
#endif

struct tamper_config_t {
	enum tampering_mode_t mode;
	enum lp_tamper_detector_t tamper;
	enum tp_enable_t enable;
	enum tp_polarity_t assert_val;
	enum gf_enable_t gf_enable;
	enum gf_value_t gf_value;
	enum active_tamper_t at_source;
	enum at_enable_t at_enable;
	enum at_frequency_t at_freq;
	enum at_polynomial_t at_poly;
	enum at_seed_t at_seed;
};

/* structure which mapped the entered char
 * string into particular source index
 * */
struct snvs_source_mapping {
	const char *source_name;
	unsigned int source_index;
};

#define LP_SECVIO_CTL_MASK	0x01

#define LP_TAMPFILT_EXT2_EN_SHIFT	31
#define LP_TAMPFILT_EXT2_EN_MASK	(0x1 << LP_TAMPFILT_EXT2_EN_SHIFT)
#define LP_TAMPFILT_EXT2_SHIFT	24
#if defined(CONFIG_IMX6) || defined(CONFIG_MX6UL)
#define LP_TAMPFILT_EXT2_MASK	(0x1f << LP_TAMPFILT_EXT2_SHIFT)
#elif defined(CONFIG_IMX7)
#define LP_TAMPFILT_EXT2_MASK	(0x7f << LP_TAMPFILT_EXT2_SHIFT)
#endif
#define LP_TAMPFILT_EXT1_EN_SHIFT	23
#define LP_TAMPFILT_EXT1_EN_MASK	(0x1 << LP_TAMPFILT_EXT1_EN_SHIFT)
#define LP_TAMPFILT_EXT1_SHIFT	16
#if defined(CONFIG_IMX6) || defined(CONFIG_MX6UL)
#define LP_TAMPFILT_EXT1_MASK	(0x1f << LP_TAMPFILT_EXT1_SHIFT)
#elif defined(CONFIG_IMX7)
#define LP_TAMPFILT_EXT1_MASK	(0x7f << LP_TAMPFILT_EXT1_SHIFT)
#endif

#define LP_TAMPDET_MASK		1
#define LP_TAMPASSERT_MASK		1
#define LP_TAMPDET_ET2_SHIFT	10
#define LP_TAMPDET_ET1_SHIFT	9
#define LP_TAMPDET_WMT2_SHIFT	8
#define LP_TAMPDET_WMT1_SHIFT	7
#define LP_TAMPDET_VT_SHIFT	6
#define LP_TAMPDET_TT_SHIFT	5
#define LP_TAMPDET_CT_SHIFT	4
#define LP_TAMPDET_MCR_SHIFT	2
#define LP_TAMPDET_SRTCR_SHIFT	1

#if defined(CONFIG_IMX7)
#define LP_TAMPFILT1_EXT6_EN_SHIFT	31
#define LP_TAMPFILT1_EXT6_EN_MASK	(0x1 << LP_TAMPFILT1_EXT6_EN_SHIFT)
#define LP_TAMPFILT1_EXT6_SHIFT	24
#define LP_TAMPFILT1_EXT6_MASK	(0x7f << LP_TAMPFILT1_EXT6_SHIFT)
#define LP_TAMPFILT1_EXT5_EN_SHIFT	23
#define LP_TAMPFILT1_EXT5_EN_MASK	(0x1 << LP_TAMPFILT1_EXT5_EN_SHIFT)
#define LP_TAMPFILT1_EXT5_SHIFT	16
#define LP_TAMPFILT1_EXT5_MASK	(0x7f << LP_TAMPFILT1_EXT5_SHIFT)
#define LP_TAMPFILT1_EXT4_EN_SHIFT	15
#define LP_TAMPFILT1_EXT4_EN_MASK	(0x1 << LP_TAMPFILT1_EXT4_EN_SHIFT)
#define LP_TAMPFILT1_EXT4_SHIFT	8
#define LP_TAMPFILT1_EXT4_MASK	(0x7f << LP_TAMPFILT1_EXT4_SHIFT)
#define LP_TAMPFILT1_EXT3_EN_SHIFT	7
#define LP_TAMPFILT1_EXT3_EN_MASK	(0x1 << LP_TAMPFILT1_EXT3_EN_SHIFT)
#define LP_TAMPFILT1_EXT3_SHIFT	0
#define LP_TAMPFILT1_EXT3_MASK	(0x7f << LP_TAMPFILT1_EXT3_SHIFT)

#define LP_TAMPFILT2_EXT10_EN_SHIFT	31
#define LP_TAMPFILT2_EXT10_EN_MASK	(0x1 << LP_TAMPFILT2_EXT10_EN_SHIFT)
#define LP_TAMPFILT2_EXT10_SHIFT	24
#define LP_TAMPFILT2_EXT10_MASK	(0x7f << LP_TAMPFILT2_EXT10_SHIFT)
#define LP_TAMPFILT2_EXT9_EN_SHIFT	23
#define LP_TAMPFILT2_EXT9_EN_MASK	(0x1 << LP_TAMPFILT2_EXT9_EN_SHIFT)
#define LP_TAMPFILT2_EXT9_SHIFT	16
#define LP_TAMPFILT2_EXT9_MASK	(0x7f << LP_TAMPFILT2_EXT9_SHIFT)
#define LP_TAMPFILT2_EXT8_EN_SHIFT	15
#define LP_TAMPFILT2_EXT8_EN_MASK	(0x1 << LP_TAMPFILT2_EXT8_EN_SHIFT)
#define LP_TAMPFILT2_EXT8_SHIFT	8
#define LP_TAMPFILT2_EXT8_MASK	(0x7f << LP_TAMPFILT2_EXT8_SHIFT)
#define LP_TAMPFILT2_EXT7_EN_SHIFT	7
#define LP_TAMPFILT2_EXT7_EN_MASK	(0x1 << LP_TAMPFILT2_EXT7_EN_SHIFT)
#define LP_TAMPFILT2_EXT7_SHIFT	0
#define LP_TAMPFILT2_EXT7_MASK	(0x7f << LP_TAMPFILT2_EXT7_SHIFT)

#define LP_TAMPDET2_ET10_SHIFT	7
#define LP_TAMPDET2_ET9_SHIFT	6
#define LP_TAMPDET2_ET8_SHIFT	5
#define LP_TAMPDET2_ET7_SHIFT	4
#define LP_TAMPDET2_ET6_SHIFT	3
#define LP_TAMPDET2_ET5_SHIFT	2
#define LP_TAMPDET2_ET4_SHIFT	1
#define LP_TAMPDET2_ET3_SHIFT	0
#endif

#define LP_STATUS_MASK		0x001707FF
#define LP_STATUS_SCANEXIT	0x00100000	/* all write 1 clear here on */
#define LP_STATUS_EXT_SECVIO	0x00010000
#define LP_STATUS_ET2		0x00000400
#define LP_STATUS_ET1		0x00000200
#define LP_STATUS_WMT2		0x00000100
#define LP_STATUS_WMT1		0x00000080
#define LP_STATUS_VTD		0x00000040
#define LP_STATUS_TTD		0x00000020
#define LP_STATUS_CTD		0x00000010
#define LP_STATUS_PGD		0x00000008
#define LP_STATUS_MCR		0x00000004
#define LP_STATUS_SRTCR		0x00000002
#define LP_STATUS_LPTA		0x00000001

#if defined(CONFIG_IMX7)
#define LP_AT_POLYNOMIAL_SHIFT	16
#define LP_AT_MASK		0xffff

#define LP_AT5_PAD_EN_SHIFT	20
#define LP_AT5_PAD_EN_MASK	(0x1 << LP_AT5_PAD_EN_SHIFT)
#define LP_AT4_PAD_EN_SHIFT	19
#define LP_AT4_PAD_EN_MASK	(0x1 << LP_AT4_PAD_EN_SHIFT)
#define LP_AT3_PAD_EN_SHIFT	18
#define LP_AT3_PAD_EN_MASK	(0x1 << LP_AT3_PAD_EN_SHIFT)
#define LP_AT2_PAD_EN_SHIFT	17
#define LP_AT2_PAD_EN_MASK	(0x1 << LP_AT2_PAD_EN_SHIFT)
#define LP_AT1_PAD_EN_SHIFT	16
#define LP_AT1_PAD_EN_MASK	(0x1 << LP_AT1_PAD_EN_SHIFT)
#define LP_AT5_EN_SHIFT	4
#define LP_AT5_EN_MASK		(0x1 << LP_AT5_EN_SHIFT)
#define LP_AT4_EN_SHIFT	3
#define LP_AT4_EN_MASK		(0x1 << LP_AT4_EN_SHIFT)
#define LP_AT3_EN_SHIFT	2
#define LP_AT3_EN_MASK		(0x1 << LP_AT3_EN_SHIFT)
#define LP_AT2_EN_SHIFT	1
#define LP_AT2_EN_MASK		(0x1 << LP_AT2_EN_SHIFT)
#define LP_AT1_EN_SHIFT	0
#define LP_AT_EN_MASK		0x1

#define LP_AT5_CLK_CTL_SHIFT	16
#define LP_AT5_CLK_CTL_MASK		(0x3 << LP_AT5_CLK_CTL_SHIFT)
#define LP_AT4_CLK_CTL_SHIFT	12
#define LP_AT4_CLK_CTL_MASK		(0x3 << LP_AT4_CLK_CTL_SHIFT)
#define LP_AT3_CLK_CTL_SHIFT	8
#define LP_AT3_CLK_CTL_MASK		(0x3 << LP_AT3_CLK_CTL_SHIFT)
#define LP_AT2_CLK_CTL_SHIFT	4
#define LP_AT2_CLK_CTL_MASK		(0x3 << LP_AT2_CLK_CTL_SHIFT)
#define LP_AT1_CLK_CTL_SHIFT	0
#define LP_AT_CLK_CTL_MASK		0x3

#define LP_AT_CLK_16HZ	0x0
#define LP_AT_CLK_8HZ	0x1
#define LP_AT_CLK_4HZ	0x2
#define LP_AT_CLK_2HZ	0x3

#define LP_ET10_ROUTING_CTL_SHIFT	4
#define LP_ET9_ROUTING_CTL_SHIFT	0
#define LP_ET8_ROUTING_CTL_SHIFT	28
#define LP_ET7_ROUTING_CTL_SHIFT	24
#define LP_ET6_ROUTING_CTL_SHIFT	20
#define LP_ET5_ROUTING_CTL_SHIFT	16
#define LP_ET4_ROUTING_CTL_SHIFT	12
#define LP_ET3_ROUTING_CTL_SHIFT	8
#define LP_ET2_ROUTING_CTL_SHIFT	4
#define LP_ET1_ROUTING_CTL_SHIFT	0
#define LP_ET_ROUTING_CTL_MASK		0x7
#define LP_STATUS_ET_MASK		0x000000FF


#define LP_ACTIVE_TAMPER_5_ROUTE	0X5
#define LP_ACTIVE_TAMPER_4_ROUTE	0X4
#define LP_ACTIVE_TAMPER_3_ROUTE	0X3
#define LP_ACTIVE_TAMPER_2_ROUTE	0X2
#define LP_ACTIVE_TAMPER_1_ROUTE	0X1
#define LP_PASSIVE_INPUT_ROUTE	0X0
#endif

/*
 * @brief This API provides information about any tamper is detected or not
 *
 * @param[out] true if tamper detected
 * @param[out] false if no tamper detected
 *
 */
int tamper_detection_check(void);

/*
 * @brief This API provides information about violation policy of
 *	specified security violation source
 *
 * @param[in] source
 *
 * @param[out] security violation policy of specified source
 */
int snvs_get_security_violation_policy(unsigned int violation_source_index);

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
int snvs_set_security_violation_policy(
	unsigned int violation_source_index, int security_index);

/*
 * @brief This API provides information that specified violation source is
 *	enabled or disabled in LP domain.
 *
 * @param[in] source
 *
 * @param[out] Enabled/Disabled
 */
int snvs_get_security_violation_configuration(
	unsigned int violation_source_index);

/*
 * @brief This API is used to enable/disable specified violation source in
 *	LP domain.
 *
 * @param[in] source
 * @param[in] control(Enabled/disabled)
 *
 * @retval TPSV_ERROR_BAD_PARAMETERS
 * @retval TPSV_SUCCESS
 *
 */
int snvs_set_security_violation_configuration(
	unsigned int violation_source_index, int flag);

/*
 * @brief This API provides information about current configuration of
 *	specified tamper detector source.
 *
 * @param[in] tamper detector source
 *
 * @param[out] information about specified source is enabled/disabled to
 *	generate security violation
 * @param[out] glitch_flag (glitch filter is enabled or bypassed)
 * @param[out] glitch_length (glitch filter length in hex)
 */
int snvs_get_tamper_detectors_configuration(
	unsigned int tamper_detector_source_index,
		int * assert, int *glitch_flag, int *glitch_length);

/*
 * @brief This API is used to configure specified tamper detector source by
 *	enabling it to generate security violation whenever tampering is
 *	detected.
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
	unsigned int tamper_detector_source_index, int flag,
	int assert, int glitch_flag, int glitch_length);

/*
 * @brief This API is used to configure the LFSR which is used for specified
 *	active tamper outputs.
 *
 * @param[in] active tamper index(1-5)
 * @param[in] polynomial
 * @param[in] seed
 *
 * @retval TPSV_ERROR_BAD_PARAMETERS
 * @retval TPSV_SUCCESS
 *
 */
int snvs_set_active_tamper_configuration(unsigned int active_tamper_index,
	int polynomial, int seed);

/*
 * @brief This API provides information about current control settings
 *	(enable/disable) of LFSR and external pads of specified active tamper.
 *
 * @param[in] active tamper index(1-5)
 *
 * @param[out] information about LFSR is enable or disabled and external
 *	pads are set for input or output.
 *
 */
int snvs_get_active_tamper_control(unsigned int active_tamper_index,
	int *lfsr_control, int *external_pad_control);

/*
 * @brief This API is used to enable the LFSR which is used for specified
 *	active tamper outputs. It is also used to control external pads to
 *	enable for input oroutput.
 *
 * @param[in] active tamper index(1-5)
 * @param[in] LFSR_flag (enable/disable)
 * @param[in] external_pad as output (enable/disable)
 *
 * @retval TPSV_ERROR_BAD_PARAMETERS
 * @retval TPSV_SUCCESS
 *
 */
int snvs_set_active_tamper_control(unsigned int active_tamper_index,
	int lfsr_flag, int external_pad);

/*
 * @brief This API provides information about clock frequency at which LFSRs
 *	run for the specified active tamper outputs.
 *
 * @param[in] active tamper index(1-5)
 *
 * @param[out] clock frequency
 *
 */
int snvs_get_active_tamper_clock_control(unsigned int active_tamper_index);

/*
 * @brief This API is used to define at what frequency LFSRs are run for the
 *	specified active tamper outputs.
 *
 * @param[in] active tamper index(1-5)
 * @param[in] clock_frequency in hz
 *
 * @retval TPSV_ERROR_BAD_PARAMETERS
 * @retval TPSV_SUCCESS
 *
 */
int snvs_set_active_tamper_clock_control(unsigned int active_tamper_index,
	int clock_freq);

/*
 * @brief This API is used to define what pattern will be produced by the
 * AT configuring the polynomial and the seed
 *
 * @param[in] active tamper index(1-5)
 * @param[in] clock_frequency in hz
 *
 * @retval TEE_ERROR_BAD_PARAMETERS
 * @retval TEE_SUCCESS
 *
 */
int snvs_set_active_tamper_pattern(unsigned int active_tamper_index,
	int polynomial, int seed);

/*
 * @brief This API provides information about routing of compare value for
 *	specified external tamper source.
 *
 * @param[in] external tamper index(1-10)
 *
 * @param[out] active tamper index(1-5)
 *
 */
int snvs_get_active_tamper_routing_control(unsigned int external_tamper_index);

/*
 * @brief This API is used to set routing of compare value between specified
 *	external tamper source (1-10) and specified active tamper (1-5)
 *
 * @param[in] external tamper index(1-10)
 * @param[in] active tamper index(1-5)
 *
 * @retval TPSV_ERROR_BAD_PARAMETERS
 * @retval TPSV_SUCCESS
 *
 */
int snvs_set_active_tamper_routing_control(unsigned int external_tamper_index,
	unsigned int active_tamper_index);

/*
 * @brief This API provides information about specified security violation
 *	source is enable/disable to generate interrupt upon security violation
 *	from LP section.
 *
 * @param[in] security violation source
 *
 * @param[out] information about specified source is enabled/disabled to
 *	generate security violation
 */
int snvs_get_interrupt_generation_policy(unsigned int violation_source_index);

/*
 * @brief This API is used to enable/disable generation of the security interrupt
 *	upon security violation signal from the LP section.
 *
 * @param[in] security violation source
 * @param[in] generating interrupt(Enabled/disabled)
 *
 * @retval TPSV_ERROR_BAD_PARAMETERS
 * @retval TPSV_SUCCESS
 *
 */
int snvs_set_interrupt_generation_policy(unsigned int violation_source_index,
	int flag);

/*
 * @brief This API provides information about current system security monitor states.
 *
 * @param[out] current System security monitor state(SSM)
 */
int snvs_get_ssm_current_state(void);

/*
 * @brief This API provides information about specified SSM state transition
 *	(Secure to Trusted state transition and Soft Fail to
 *	Non-Secure transition) is enabled or disabled.
 *
 * @param[in] specify state transition (Secure to Trusted state transition or
 *	Soft Fail to Non-Secure transition).
 *
 * @param[out] Enable/Disable based on specified transition is enable
 *	or disable.
 */
int snvs_get_ssm_state_transition_permission(unsigned int transition_index);

/*
 * @brief This API is used to enable or disable specified SSM state transition.
 *
 * @param[in] specify state transition (Secure to Trusted state transition or
 *	Soft Fail to Non-Secure transition).
 *
 * @param[in] flag (true/false). flag = true-> disable state transition,
 *	flag = false -> enable state transition.
 *
 */
int snvs_set_ssm_state_transition_permission(unsigned int transition_index,
	int flag);

/*
 * @brief This API is used to generate software security violation.
 *
 * @param[in] software security violation source
 *
 * @retval TPSV_ERROR_BAD_PARAMETERS
 * @retval TPSV_SUCCESS
 *
 */
int snvs_generate_software_security_violation(
	unsigned int violation_source_index);

/*
 * @brief This API is used to set state transition bit in HPCOMR.
 *
 * @retval TPSV_ERROR_BAD_PARAMETERS
 * @retval TPSV_SUCCESS
 *
 */
int snvs_ssm_state_transition(void);

/*
 * @@brief This API build a tamper configuration
 *
 * @retval TPSV_ERROR_BAD_PARAMETERS
 * @retval TPSV_SUCCESS
 */
TPSV_Result tamper_config_factory(
	struct tamper_config_t * cfg_to_build,
	enum tampering_mode_t mode,
	enum lp_tamper_detector_t et,
	enum tp_enable_t ena,
	enum tp_polarity_t assert_val,
	enum gf_enable_t gf_ena,
	enum gf_value_t gf_val,
	enum active_tamper_t at_source,
	enum at_enable_t at_enable,
	enum at_frequency_t at_freq,
	enum at_polynomial_t at_poly,
	enum at_seed_t at_seed);

TPSV_Result apply_tp_conf(struct tamper_config_t * tp_conf);
TPSV_Result retrieve_tp_conf(struct tamper_config_t * tp_conf, enum lp_tamper_detector_t tamper);
void print_tp_conf(struct tamper_config_t * tp_cfg __maybe_unused,
									const char * text __maybe_unused);

/*
 * @@brief This API build a security violation configuration
 *
 * @retval TPSV_ERROR_BAD_PARAMETERS
 * @retval TPSV_SUCCESS
 */
TPSV_Result secviol_config_factory(
	struct secviol_config_t * cfg_to_build,
	enum hp_secvio_source_t source,
	enum sv_enable_t ena,
	enum sv_policy_t policy,
	enum sv_itr_enable_t itr_ena);

TPSV_Result apply_sv_conf(struct secviol_config_t * sv_conf);
TPSV_Result retrieve_sv_conf(struct secviol_config_t * sv_conf, enum hp_secvio_source_t source);
void print_sv_conf(struct secviol_config_t * sv_cfg __maybe_unused, const char * text __maybe_unused);

#endif /* SNVS_SECURITY_H_ */
