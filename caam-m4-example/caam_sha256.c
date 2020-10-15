/*
 * Gernerate SHA256 hash using CAAM
 *
 * Copyright 2020 NXP
 *
 * SPDX-License-Identifier:	GPL-2.0+
 *
 */


#include "board.h"
#include "fsl_cache.h"
#include "pin_mux.h"
#include "clock_config.h"
#include "fsl_lpuart.h"
#include "MIMX8QX6_cm4_features.h"
#include "fsl_device_registers.h"
#include "fsl_debug_console.h"

#include "fsl_caam_internal.h"
#include "desc_constr.h"
#include <fsl_caam.h>


#define ARCH_DMA_MINALIGN	128
#define ALIGN_MASK     		~(ARCH_DMA_MINALIGN - 1)
#define SHA256_DIGEST_SIZE  32

#define ROUND(a,b)		    (((a) + (b) - 1) & ~((b) - 1))
#define arch_putl(v,a)      (*(volatile unsigned int *)(a) = (v))
#define arch_getl(a)        (*(volatile unsigned int *)(a))
#define raw_writel(v,a)     arch_putl(v,a)
#define raw_readl(a)        arch_getl(a)

static int do_cfg_jrqueue(void);
static int do_job(uint32_t *desc);

/*
 * Structures
 */
/* Definition of input ring object */
struct inring_entry {
        uint32_t desc; /* Pointer to input descriptor */
};

/* Definition of output ring object */
struct outring_entry {
        uint32_t desc;   /* Pointer to output descriptor */
        uint32_t status; /* Status of the Job Ring       */
};

/* Main job ring data structure */
struct jr_data_st {
        struct inring_entry  *inrings;
        struct outring_entry *outrings;
        uint32_t status;  /* Ring buffers init status */
        uint32_t *desc;   /* Pointer to output descriptor */
        uint32_t raw_addr[DESC_MAX_SIZE * 2];
};

uint8_t s_inring[128] __attribute__ ((aligned (ARCH_DMA_MINALIGN))) = {0};
uint8_t s_onring[128] __attribute__ ((aligned (ARCH_DMA_MINALIGN))) = {0};
uint8_t s_desc[128] __attribute__ ((aligned (ARCH_DMA_MINALIGN))) = {0};

uint32_t plain_data_addr[5] __attribute__ ((aligned (ARCH_DMA_MINALIGN)));
uint8_t out_digest[32] __attribute__ ((aligned (ARCH_DMA_MINALIGN))) = {0};
/*
 * Global variables
 */
static struct jr_data_st g_jrdata = {0};

/*
 * Local functions
 */
static void dump_error(void)
{
        int i;
        PRINTF("Dump CAAM Error\n");
        PRINTF("MCFGR 0x%08X\n", raw_readl(CAAM_MCFGR));
        PRINTF("FAR  0x%08X\n", raw_readl(CAAM_FAR));
        PRINTF("FAMR 0x%08X\n", raw_readl(CAAM_FAMR));
        PRINTF("FADR 0x%08X\n", raw_readl(CAAM_FADR));
        PRINTF("CSTA 0x%08X\n", raw_readl(CAAM_STA));
        PRINTF("RTMCTL 0x%X\n", raw_readl(CAAM_RTMCTL));
        PRINTF("RTSTATUS 0x%X\n", raw_readl(CAAM_RTSTATUS));
        PRINTF("RDSTA 0x%X\n", raw_readl(CAAM_RDSTA));

        for (i = 0; i < desc_len(g_jrdata.desc); i++)
                PRINTF("desc[%d]: 0x%08x\n", i, g_jrdata.desc[i]);
}
/*!
 * Use CAAM to generate a hash.
 *
 * @param   plain_data_addr  Location address of the plain data.
 * @param   digest_addr  Location address of the digest.
 *
 */

uint32_t caam_hash_sha()
{
		int i;
		u32 options;
        u32 ret = SUCCESS;
        u32 *hash_desc = g_jrdata.desc;
        uint32_t storelen = (uint32_t)SHA256_DIGEST_SIZE;
        /* initialize input data, this could also be sent as parameter from user */
        strcpy(plain_data_addr, "amam");
        uint32_t data_sz = 4;
        PRINTF("\r\nInput value: %s, Input size: %u\r\n", plain_data_addr, data_sz);

        /* Buffer to hold the resulting hash */
        volatile uint8_t *digest = (u8 *)(out_digest);
        /* initialize the digest array */
        memset(digest,0, SHA256_DIGEST_SIZE);
        /* prepare job descriptor */
        init_job_desc(hash_desc, 0);
        
        append_seq_in_ptr_intlen(hash_desc, plain_data_addr, data_sz, 0);
        append_seq_out_ptr_intlen(hash_desc, digest, SHA256_DIGEST_SIZE, 0);
        append_operation(hash_desc, OP_TYPE_CLASS2_ALG |
        		OP_ALG_AAI_HASH | OP_ALG_AS_INITFINAL |
				OP_ALG_ENCRYPT | OP_ALG_ICV_OFF | OP_ALG_ALGSEL_SHA256);

        options = LDST_CLASS_2_CCB | FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST2;
        append_fifo_load(hash_desc, plain_data_addr, data_sz, options);
        append_store(hash_desc, digest, storelen,
                 LDST_CLASS_2_CCB | LDST_SRCDST_BYTE_CONTEXT);

        L1CACHE_CleanInvalidateDCacheByRange((uint32_t)plain_data_addr & ALIGN_MASK, ROUND(data_sz, ARCH_DMA_MINALIGN));
        L1CACHE_CleanInvalidateDCacheByRange((uint32_t)digest & ALIGN_MASK, ROUND(storelen, ARCH_DMA_MINALIGN));
	
        ret = do_job(hash_desc);
        if (ret != SUCCESS) {
        	PRINTF("\r\nError: hash job failed 0x%x\n", ret);
        }
        else {
        	PRINTF("\r\nHash: ");
        	for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
        		PRINTF("%02x",*(((unsigned char*)digest)+i));
		}
        }
        return ret;
}

void caam_open(void)
{
        int ret;
        ret = do_cfg_jrqueue();

        if (ret != SUCCESS) {
                PRINTF("Error CAAM JR initialization\n");
                return;
        }
}

int caam_write_jrintr3(void)
{
    	volatile uint32_t *ptr_jrintr = (uint32_t *) CAAM_JRINTR3;
    	*ptr_jrintr = (uint32_t)JRINTR_JRI;
    	return 0;
}

static int do_job(uint32_t *desc)
{
        int ret;
        uint8_t err = 0;
        /* for imx8, JR0 and JR1 will be assigned to seco, so we use
         * the JR3 instead.
         */
        if (raw_readl(CAAM_IRSAR3) == 0)
                return ERROR_ANY;
        g_jrdata.inrings[0].desc = desc;
        
		L1CACHE_CleanInvalidateDCacheByRange((uint32_t)g_jrdata.inrings & ALIGN_MASK,
	                  + ROUND(DESC_MAX_SIZE, ARCH_DMA_MINALIGN));
		L1CACHE_CleanInvalidateDCacheByRange((uint32_t)desc & ALIGN_MASK,
	                  + ROUND(DESC_MAX_SIZE, ARCH_DMA_MINALIGN));
		L1CACHE_CleanInvalidateDCacheByRange((uint32_t)g_jrdata.outrings & ALIGN_MASK,
					  + ROUND(DESC_MAX_SIZE, ARCH_DMA_MINALIGN));
        
		/* Inform HW that a new JR is available */
		raw_writel(1, CAAM_IRJAR3);
		while (raw_readl(CAAM_ORSFR3) == 0)
				;

		if (desc == g_jrdata.outrings[0].desc) {
                ret = g_jrdata.outrings[0].status;
        } else {
                dump_error();
                ret = ERROR_ANY;
        }
        /* Acknowledge interrupt */
		caam_write_jrintr3();
		/* Remove the JR from the output list even if no JR caller found */
		raw_writel(1, CAAM_ORJRR3);

        return ret;
}

static int do_cfg_jrqueue(void)
{
        u32 value = 0;
        uint32_t ip_base;
        uint32_t op_base;
        uint8_t err = 0;
        /* check if already configured after relocation */
        if (g_jrdata.status == RING_RELOC_INIT)
                return 0;
        /*
         * jr configuration needs to be updated once, after relocation to ensure
         * using the right buffers.
         * When buffers are updated after relocation the flag RING_RELOC_INIT
         * is used to prevent extra updates
         */
		g_jrdata.inrings  = (struct inring_entry *)(s_inring);
		g_jrdata.outrings = (struct outring_entry *)(s_onring);
		g_jrdata.desc = (u32 *)(s_desc);
		g_jrdata.status = RING_EARLY_INIT;

		if (!g_jrdata.inrings || !g_jrdata.outrings)
			return ERROR_ANY;
		/* Configure the HW Job Rings */
		ip_base = g_jrdata.inrings;
		op_base = g_jrdata.outrings;
        /* for imx8, JR0 and JR1 will be assigned to seco, so we use
         * the JR3 instead.
        */
		raw_writel(ip_base, CAAM_IRBAR3);
		raw_writel(1, CAAM_IRSR3);

		raw_writel(op_base, CAAM_ORBAR3);
		raw_writel(1, CAAM_ORSR3);
	
		caam_write_jrintr3();
        /*
         * Configure interrupts but disable it:
         * Optimization to generate an interrupt either when there are
         * half of the job done or when there is a job done and
         * 10 clock cycles elapse without new job complete
         */
        value = 10 << BS_JRCFGR_LS_ICTT;
        value |= (1 << BS_JRCFGR_LS_ICDCT) & BM_JRCFGR_LS_ICDCT;
        value |= BM_JRCFGR_LS_ICEN;
        value |= BM_JRCFGR_LS_IMSK;
        raw_writel(value, CAAM_JRCFGR3_LS);
		return 0;
}
/*!
 * @brief Main function
 */
int main(void)
{
    	/* Init board hardware. */
    	sc_ipc_t ipc;
    	ipc = BOARD_InitRpc();
    	BOARD_InitPins(ipc);
    	BOARD_BootClockRUN();
    	BOARD_InitDebugConsole();
    	BOARD_InitMemory();
    	int ret;

    	ret = sc_pm_set_resource_power_mode(ipc, SC_R_CAAM_JR3, SC_PM_PW_MODE_ON);
    	if(ret)
        	PRINTF("ret CAAM_JR3 = %d", ret);
    	ret = sc_pm_set_resource_power_mode(ipc, SC_R_CAAM_JR3_OUT, SC_PM_PW_MODE_ON);
    	if(ret)
        	PRINTF("ret CAAM_JR3_OUT = %d", ret);

    	caam_open();
		PRINTF("\r\nSHA256 - CAAM:\r\n");
		ret = caam_hash_sha();
		if(ret != SUCCESS){
				PRINTF("\r\nError hash operation: 0x%x\n", ret);
				return 0;
		}
}
