/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "board.h"

#include "pin_mux.h"
#include "clock_config.h"

#include "hab_M4.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define hab_rvt_report_event_p  ((hab_rvt_report_event_t *)HAB_RVT_REPORT_EVENT)

#define hab_rvt_report_status_p  ((hab_rvt_report_status_t *)HAB_RVT_REPORT_STATUS)	

#define hab_rvt_entry_p  ((hab_rvt_entry_t *)HAB_RVT_ENTRY)

#define hab_rvt_exit_p  ((hab_rvt_exit_t *)HAB_RVT_EXIT)

/*******************************************************************************
 * Prototypes
 ******************************************************************************/


/*******************************************************************************
 * Code
 ******************************************************************************/
/*!
 * @brief Main function
 */
enum hab_status hab_rvt_report_event(enum hab_status status, uint32_t index,
		uint8_t *event, size_t *bytes)
{
	enum hab_status ret;
	hab_rvt_report_event_t *hab_rvt_report_event_func;
	hab_rvt_report_event_func = hab_rvt_report_event_p;

	ret = hab_rvt_report_event_func(status, index, event, bytes);

	return ret;
}

enum hab_status hab_rvt_report_status(enum hab_config *config,
		enum hab_state *state)
{
	enum hab_status ret;
	hab_rvt_report_status_t *hab_rvt_report_status_func;
	hab_rvt_report_status_func = hab_rvt_report_status_p;

	ret = hab_rvt_report_status_func(config, state);

	return ret;
}

enum hab_status hab_rvt_entry(void)
{
	enum hab_status ret;
	hab_rvt_entry_t *hab_rvt_entry_func;
	hab_rvt_entry_func = hab_rvt_entry_p;

	ret = hab_rvt_entry_func();

	return ret;
}

enum hab_status hab_rvt_exit(void)
{
	enum hab_status ret;
	hab_rvt_exit_t *hab_rvt_exit_func;
	hab_rvt_exit_func = hab_rvt_exit_p;

	ret = hab_rvt_exit_func();

	return ret;
}

struct record {
	uint8_t  tag;						/* Tag */
	uint8_t  len[2];					/* Length */
	uint8_t  par;						/* Version */
	uint8_t  contents[MAX_RECORD_BYTES];/* Record Data */
	bool	 any_rec_flag;
};

char *rsn_str[] = {"RSN = HAB_RSN_ANY (0x00)\r\n",
				   "RSN = HAB_ENG_FAIL (0x30)\r\n",
				   "RSN = HAB_INV_ADDRESS (0x22)\r\n",
				   "RSN = HAB_INV_ASSERTION (0x0C)\r\n",
				   "RSN = HAB_INV_CALL (0x28)\r\n",
				   "RSN = HAB_INV_CERTIFICATE (0x21)\r\n",
				   "RSN = HAB_INV_COMMAND (0x06)\r\n",
				   "RSN = HAB_INV_CSF (0x11)\r\n",
				   "RSN = HAB_INV_DCD (0x27)\r\n",
				   "RSN = HAB_INV_INDEX (0x0F)\r\n",
				   "RSN = HAB_INV_IVT (0x05)\r\n",
				   "RSN = HAB_INV_KEY (0x1D)\r\n",
				   "RSN = HAB_INV_RETURN (0x1E)\r\n",
				   "RSN = HAB_INV_SIGNATURE (0x18)\r\n",
				   "RSN = HAB_INV_SIZE (0x17)\r\n",
				   "RSN = HAB_MEM_FAIL (0x2E)\r\n",
				   "RSN = HAB_OVR_COUNT (0x2B)\r\n",
				   "RSN = HAB_OVR_STORAGE (0x2D)\r\n",
				   "RSN = HAB_UNS_ALGORITHM (0x12)\r\n",
				   "RSN = HAB_UNS_COMMAND (0x03)\r\n",
				   "RSN = HAB_UNS_ENGINE (0x0A)\r\n",
				   "RSN = HAB_UNS_ITEM (0x24)\r\n",
				   "RSN = HAB_UNS_KEY (0x1B)\r\n",
				   "RSN = HAB_UNS_PROTOCOL (0x14)\r\n",
				   "RSN = HAB_UNS_STATE (0x09)\r\n",
				   "RSN = INVALID\r\n",
				   NULL};

char *sts_str[] = {"STS = HAB_SUCCESS (0xF0)\r\n",
				   "STS = HAB_FAILURE (0x33)\r\n",
				   "STS = HAB_WARNING (0x69)\r\n",
				   "STS = INVALID\r\n",
				   NULL};

char *eng_str[] = {"ENG = HAB_ENG_ANY (0x00)\r\n",
				   "ENG = HAB_ENG_SCC (0x03)\r\n",
				   "ENG = HAB_ENG_RTIC (0x05)\r\n",
				   "ENG = HAB_ENG_SAHARA (0x06)\r\n",
				   "ENG = HAB_ENG_CSU (0x0A)\r\n",
				   "ENG = HAB_ENG_SRTC (0x0C)\r\n",
				   "ENG = HAB_ENG_DCP (0x1B)\r\n",
				   "ENG = HAB_ENG_CAAM (0x1D)\r\n",
				   "ENG = HAB_ENG_SNVS (0x1E)\r\n",
				   "ENG = HAB_ENG_OCOTP (0x21)\r\n",
				   "ENG = HAB_ENG_DTCP (0x22)\r\n",
				   "ENG = HAB_ENG_ROM (0x36)\r\n",
				   "ENG = HAB_ENG_HDCP (0x24)\r\n",
				   "ENG = HAB_ENG_RTL (0x77)\r\n",
				   "ENG = HAB_ENG_SW (0xFF)\r\n",
				   "ENG = INVALID\r\n",
				   NULL};

char *ctx_str[] = {"CTX = HAB_CTX_ANY(0x00)\r\n",
				   "CTX = HAB_CTX_FAB (0xFF)\r\n",
				   "CTX = HAB_CTX_ENTRY (0xE1)\r\n",
				   "CTX = HAB_CTX_TARGET (0x33)\r\n",
				   "CTX = HAB_CTX_AUTHENTICATE (0x0A)\r\n",
				   "CTX = HAB_CTX_DCD (0xDD)\r\n",
				   "CTX = HAB_CTX_CSF (0xCF)\r\n",
				   "CTX = HAB_CTX_COMMAND (0xC0)\r\n",
				   "CTX = HAB_CTX_AUT_DAT (0xDB)\r\n",
				   "CTX = HAB_CTX_ASSERT (0xA0)\r\n",
				   "CTX = HAB_CTX_EXIT (0xEE)\r\n",
				   "CTX = INVALID\r\n",
				   NULL};

uint8_t hab_statuses[5] = {
	HAB_STS_ANY,
	HAB_FAILURE,
	HAB_WARNING,
	HAB_SUCCESS,
	-1
};

uint8_t hab_reasons[26] = {
	HAB_RSN_ANY,
	HAB_ENG_FAIL,
	HAB_INV_ADDRESS,
	HAB_INV_ASSERTION,
	HAB_INV_CALL,
	HAB_INV_CERTIFICATE,
	HAB_INV_COMMAND,
	HAB_INV_CSF,
	HAB_INV_DCD,
	HAB_INV_INDEX,
	HAB_INV_IVT,
	HAB_INV_KEY,
	HAB_INV_RETURN,
	HAB_INV_SIGNATURE,
	HAB_INV_SIZE,
	HAB_MEM_FAIL,
	HAB_OVR_COUNT,
	HAB_OVR_STORAGE,
	HAB_UNS_ALGORITHM,
	HAB_UNS_COMMAND,
	HAB_UNS_ENGINE,
	HAB_UNS_ITEM,
	HAB_UNS_KEY,
	HAB_UNS_PROTOCOL,
	HAB_UNS_STATE,
	-1
};

uint8_t hab_contexts[12] = {
	HAB_CTX_ANY,
	HAB_CTX_FAB,
	HAB_CTX_ENTRY,
	HAB_CTX_TARGET,
	HAB_CTX_AUTHENTICATE,
	HAB_CTX_DCD,
	HAB_CTX_CSF,
	HAB_CTX_COMMAND,
	HAB_CTX_AUT_DAT,
	HAB_CTX_ASSERT,
	HAB_CTX_EXIT,
	-1
};

uint8_t hab_engines[16] = {
	HAB_ENG_ANY,
	HAB_ENG_SCC,
	HAB_ENG_RTIC,
	HAB_ENG_SAHARA,
	HAB_ENG_CSU,
	HAB_ENG_SRTC,
	HAB_ENG_DCP,
	HAB_ENG_CAAM,
	HAB_ENG_SNVS,
	HAB_ENG_OCOTP,
	HAB_ENG_DTCP,
	HAB_ENG_ROM,
	HAB_ENG_HDCP,
	HAB_ENG_RTL,
	HAB_ENG_SW,
	-1
};

static bool is_secure_boot(void)
{
	uint32_t *reg = (uint32_t *)SEC_CONFIG1;
	
    return ( (((uint32_t)(*reg)) & ((uint32_t)SECURE_BOOT_BIT)) == ((uint32_t)SECURE_BOOT_BIT) );
}


static inline uint8_t get_idx(uint8_t *list, uint8_t tgt)
{
	uint8_t idx = 0;
	uint8_t element = list[idx];
	while (element != -1) {
		if (element == tgt)
			return idx;
		element = list[++idx];
	}
	return -1;
}

void process_event_record(uint8_t *event_data, size_t bytes)
{
	struct record *rec = (struct record *)event_data;

	PRINTF("\r\n\r\n%s", sts_str[get_idx(hab_statuses, rec->contents[0])]);
	PRINTF("%s", rsn_str[get_idx(hab_reasons, rec->contents[1])]);
	PRINTF("%s", ctx_str[get_idx(hab_contexts, rec->contents[2])]);
	PRINTF("%s", eng_str[get_idx(hab_engines, rec->contents[3])]);
}

void display_event(uint8_t *event_data, size_t bytes)
{
	uint32_t i;

	if (!(event_data && bytes > 0))
		return;

	for (i = 0; i < bytes; i++) {
		if (i == 0)
			PRINTF("\t0x%02x", event_data[i]);
		else if ((i % 8) == 0)
			PRINTF("\r\n\t0x%02x", event_data[i]);
		else
			PRINTF(" 0x%02x", event_data[i]);
	}

	process_event_record(event_data, bytes);
}

int get_hab_status(void)
{
	uint32_t index = 0; /* Loop index */
	uint8_t event_data[128]; /* Event data buffer */
	size_t bytes = sizeof(event_data); /* Event size in bytes */
	enum hab_config config = 0;
	enum hab_state state = 0;

	if (is_secure_boot())
		PRINTF("\r\nSecure boot enabled\r\n");
	else
		PRINTF("\r\nSecure boot disabled\r\n");

	/* Check HAB status */
	if (hab_rvt_report_status(&config, &state) != HAB_SUCCESS) {
		PRINTF("\r\nHAB Configuration: 0x%02x, HAB State: 0x%02x\r\n",
		       config, state);

		/* Display HAB Error events */
		while (hab_rvt_report_event(HAB_FAILURE, index, event_data,
					&bytes) == HAB_SUCCESS) {
			PRINTF("\r\n");
			PRINTF("--------- HAB Event %d -----------------\r\n",
			       index + 1);
			PRINTF("event data:\r\n");
			display_event(event_data, bytes);
			PRINTF("\r\n");
			bytes = sizeof(event_data);
			index++;
		}
	}
	/* Display message if no HAB events are found */
	else {
		PRINTF("\r\nHAB Configuration: 0x%02x, HAB State: 0x%02x\r\n",
		       config, state);
		PRINTF("No HAB Events Found!\r\n\r\n");
	}
	return 0;
}

int main(void)
{
    char ch;

    /* Init board hardware. */
    BOARD_InitPins();
    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();

    get_hab_status();

    while (1)
    {  
        ch = GETCHAR();
        PUTCHAR(ch);
    }
}
