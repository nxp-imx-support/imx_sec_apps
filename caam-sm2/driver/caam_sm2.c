/**
* SPDX-License-Identifier: GPL-2.0
*	
* Copyright 2018-2019 NXP
*
* caam_sm2.c: Kernel module which performs partial SM2 signature verification using CAAM Hardware.
* The module construct and enqueue the job descriptor to perform the following steps suing PKHA:
* - Calculate t = (r' + s') mod n, verification failed if t=0
* - Calculate the point (x1', y1')=[s']G + [t]PA
* - Calculate R=(e'+x1') modn, verification pass if yes, otherwise failed
* - Compare computed r with received r
*
* The module exposes an IOCTL call to interact with user-space software. 
* It takes as argument: Public key(xA, yA), message representative (e) and signature (r,s)
*
* Return value 1: means correct signature. 0: Incorrect signature. Otherwise: Error.
*
* THIS CODE WAS MAINLY WRITTEN FOR DEMONSTRATION PURPOSE ONLY.
* IT SHOULD NOT BE USED IN ANY CASE IN A PRODUCTION ENVIRONMENT.
*
**/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/poll.h>
#include <linux/ioctl.h>

#include <caam/compat.h>
#include <caam/jr.h>
#include <caam/regs.h>
#include <caam/intern.h>
#include <caam/error.h>
#include <caam/pdb.h>

#include <flib/rta.h> 

struct caam_sm2_verify_req;
struct caam_sm2_verify_t;

#define DEVICE_NAME "caam_sm2"

#define IOCTL_CAAM_SM2_VERIF_SIG _IOWR('c', 0, struct caam_sm2_verify_req)

#define SIG_VERIFY_STATUS 0x42
#define SIG_VERIFY_SUCCESS 1
#define SIG_VERIFY_FAIL 0
#define SIG_VERIFY_ERROR -1

#define OP_ALG_PKMODE_MOD_AMODN_UD 0x7
#define OP_ALG_PKMODE_ECC_MOD_ADD_R2_UD  (OP_ALG_PKMODE_ECC_MOD_ADD | OP_ALG_PKMODE_MOD_R2_IN)
#define CAAM_MAX_JOB_SIZE 64 
#define P_LEN 32
#define N_LEN 32
#define DOMAIN_LEN 256

struct caam_sm2_ctx_t {
	struct device *jrdev;
};

struct caam_operation_result {
	struct completion completion;
	int err;
};

static struct caam_sm2_ctx_t *caam_sm2_ctx = NULL;

struct caam_sm2_verify_req {
	u8	*e;
	u32	e_len;
	u8	*r;
	u32	r_len;
	u8	*s;
	u32	s_len;
	u8	*xA;
	u32	xA_len;
	u8	*yA;
	u32	yA_len;
};

/*
* Prototypes
*/
static int do_ioctl(struct caam_sm2_verify_t* caam_sm2_verify, struct caam_sm2_verify_req *req);
static int caam_sm2_open(struct inode* inode, struct file* filp);
static int caam_sm2_release(struct inode* inode, struct file* filp);
static u32 caam_sm2_poll(struct file *file, poll_table * wait);
static long caam_sm2_ioctl(struct file *file, u32 ioctl_num, u64 ioctl_param);
static u32 caam_sm2_verify_jobdesc(u32 *desc, struct caam_sm2_verify_t*caam_sm2_verify);

enum rta_sec_era rta_sec_era;
extern const int need_bswap;

/*
* We use the symbol names from draft-shen-sm2-ecdsa-00
*  p, a, b:  curve parameters
*  n, G:     domain parameters (domain order, generator point)
*  r, s:     signature components
*  A:        signer's public key
*  e:        The hash of user's hash (ZA) and the message.
*  
* This uses "R^2 mod p" in order to speed the ECC operations.
*/
static const char* domain =
"\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"  /* p   */
"\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x02\xFF\xFF\xFF\xFF\x00\x00\x00\x02\x00\x00\x00\x03"  /* R2p */
"\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC"  /* a   */
"\x28\xE9\xFA\x9E\x9D\x9F\x5E\x34\x4D\x5A\x9E\x4B\xCF\x65\x09\xA7\xF3\x97\x89\xF5\x15\xAB\x8F\x92\xDD\xBC\xBD\x41\x4D\x94\x0E\x93"  /* b   */
"\x32\xC4\xAE\x2C\x1F\x19\x81\x19\x5F\x99\x04\x46\x6A\x39\xC9\x94\x8F\xE3\x0B\xBF\xF2\x66\x0B\xE1\x71\x5A\x45\x89\x33\x4C\x74\xC7"  /* xG  */
"\xBC\x37\x36\xA2\xF4\xF6\x77\x9C\x59\xBD\xCE\xE3\x6B\x69\x21\x53\xD0\xA9\x87\x7C\xC6\x2A\x47\x40\x02\xDF\x32\xE5\x21\x39\xF0\xA0"  /* yG  */
"\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x72\x03\xDF\x6B\x21\xC6\x05\x2B\x53\xBB\xF4\x09\x39\xD5\x41\x23"  /* n   */
"\x1E\xB5\xE4\x12\xA2\x2B\x3D\x3B\x62\x0F\xC8\x4C\x3A\xFF\xE0\xD4\x34\x64\x50\x4A\xDE\x6F\xA2\xFA\x90\x11\x92\xAF\x7C\x11\x4F\x20"; /* R2n */

struct caam_sm2_verify_t {
	struct mutex lock;
	u32 *desc;
	u32 desc_len;
	u32 p_len;
	u32 n_len;
	u8 *domain_mem;
	u8 *xA_mem, *yA_mem;
	u8 *e_mem, *r_mem,  *s_mem;
	u8 *tmp1_mem, *tmp2_mem;
	u8 *param_mem, *tmp;
	u32 domain_len;
	caam_dma_addr_t tmp1_addr, tmp2_addr;
	caam_dma_addr_t domain_addr;
	caam_dma_addr_t e_addr, r_addr, s_addr;
	caam_dma_addr_t xA_addr, yA_addr;
	caam_dma_addr_t param_mem_addr, tmp_addr;
	u32 param_len;
};

static const struct file_operations caam_sm2_fops = { 
	.owner = THIS_MODULE,
	.open = caam_sm2_open, 
	.release = caam_sm2_release, 
	.unlocked_ioctl = caam_sm2_ioctl,
	.poll = caam_sm2_poll,
};

struct caam_job_result {
	int error;
	struct completion comp;
};

struct device *caam_sm2_get_jrdev(void)
{
	if (NULL != caam_sm2_ctx) {
		if (caam_sm2_ctx->jrdev != NULL ) {
			return caam_sm2_ctx->jrdev;
		}
	}
	return NULL;
}

/* Construct am SM2 signature verification job descriptor

Issuing job <Verify ECFP SM2 Signature>
[00] B0800039       jobhdr: stidx->[00] len=57
[01] F0000100     seqinptr: len=256
[02] FE92E280               in_ptr->@0xfe92e280
[03] 280000C0    seqfifold: skip len=192
[04] 2A080020    seqfifold: class1 pkn len=32
[05] 220C0020       fifold: class1 pka len=32
[06] FDF99DC0               ptr->@0xfdf99dc0
[07] 220D0020       fifold: class1 pkb len=32
[08] FEDA9E00               ptr->@0xfeda9e00
[09] 81800002    operation: pk MOD_ADD -> pkb
[10] A0C08042         jump: all-match[pk-zero] halt-user status=66
[11] 81820811    operation: pk COPY_SSZ pkb0->pke0
[12] F0200100     seqinptr: len=256 rto
[13] 2A080020    seqfifold: class1 pkn len=32
[14] 2A050020    seqfifold: class1 pkb1 len=32
[15] 2A030020    seqfifold: class1 pka3 len=32
[16] 2A040020    seqfifold: class1 pkb0 len=32
[17] 22000020       fifold: class1 pka0 len=32
[18] FD4510C0               ptr->@0xfd4510c0
[19] 22010020       fifold: class1 pka1 len=32
[20] FD46B100               ptr->@0xfd46b100
[21] 8181000B    operation: pk ECC_MOD_MUL_R2 -> pkb
[22] 60050020      fifostr: pkb1 len=32
[23] FD009DC0               ptr->@0xfd009dc0
[24] 60060020      fifostr: pkb2 len=32
[25] FD3DFF40               ptr->@0xfd3dff40
[26] F0200100     seqinptr: len=256 rto
[27] 28000020    seqfifold: skip len=32
[28] 2A050020    seqfifold: class1 pkb1 len=32
[29] 2A030020    seqfifold: class1 pka3 len=32
[30] 2A040020    seqfifold: class1 pkb0 len=32
[31] 2A000020    seqfifold: class1 pka0 len=32
[32] 2A010020    seqfifold: class1 pka1 len=32
[33] 02010020          key: class1-pke len=32
[34] FEDA9E00               ptr->@0xfeda9e00
[35] 8181000B    operation: pk ECC_MOD_MUL_R2 -> pkb
[36] F0200100     seqinptr: len=256 rto
[37] 28000020    seqfifold: skip len=32
[38] 2A070020    seqfifold: class1 pkb3 len=32
[39] 2A030020    seqfifold: class1 pka3 len=32
[40] 2A040020    seqfifold: class1 pkb0 len=32
[41] 22000020       fifold: class1 pka0 len=32
[42] FD009DC0               ptr->@0xfd009dc0
[43] 22010020       fifold: class1 pka1 len=32
[44] FD3DFF40               ptr->@0xfd3dff40
[45] 81810109    operation: pk ECC_MOD_ADD_R2 -> pka
[46] F0200100     seqinptr: len=256 rto
[47] 280000C0    seqfifold: skip len=192
[48] 2A080020    seqfifold: class1 pkn len=32
[49] 220D0020       fifold: class1 pkb len=32
[50] FE771BC0               ptr->@0xfe771bc0
[51] 81800102    operation: pk MOD_ADD -> pka
[52] 81800007    operation: pk MOD_AMODN -> pkb
[53] 220C0020       fifold: class1 pka len=32
[54] FDF99DC0               ptr->@0xfdf99dc0
[55] 81820002    operation: pk F2M_ADD -> pkb
[56] A0C38042         jump: any-mismatch[pk-zero] halt-user status=66
*/
static u32 caam_sm2_verify_jobdesc(u32 *desc, struct caam_sm2_verify_t *caam_sm2_verify)
{
	struct program prg;
	
	/* The typical procedure for executing a PKHA function is to use KEY and FIFO LOAD Commands
	to load the registers (usually N first) */
	
	/* Initialize job descriptor */
	PROGRAM_CNTXT_INIT(&prg, desc, 0);
	/* Add job descriptor header */
	JOB_HDR(&prg, SHR_NEVER, 0, 0, 0);
	/* Curve parameters.  Stuff together to save words in Descriptor */
	SEQINPTR(&prg, caam_sm2_verify->domain_addr, caam_sm2_verify->domain_len, 0);

	/* B5: calculate t = (r' + s') mod n, verification failed if t=0 */
	SEQFIFOLOAD(&prg, SKIP, 6 * caam_sm2_verify->p_len, 0);
	SEQFIFOLOAD(&prg, PKN, caam_sm2_verify->n_len, 0);  /* n */
	FIFOLOAD(&prg, PKA,caam_sm2_verify->r_addr, caam_sm2_verify->n_len, 0); /* r */
	FIFOLOAD(&prg, PKB,caam_sm2_verify->s_addr, caam_sm2_verify->n_len, 0); /* s */
	PKHA_OPERATION(&prg, OP_ALG_PKMODE_MOD_ADD | OP_ALG_PKMODE_OUT_B); /* (r + s) mod n */

	/* ... fail if t=0 */
	JUMP(&prg, SIG_VERIFY_STATUS, HALT_STATUS, ALL_TRUE, PK_0); /* User status means Invalid Signature */

	/* B6: calculate the point (x1', y1')=[s']G + [t]PA */
	PKHA_OPERATION(&prg, OP_ALG_PKMODE_COPY_SSZ_B_E);
	SEQINPTR(&prg, 0, caam_sm2_verify->domain_len, RTO);

	SEQFIFOLOAD(&prg, PKN,  caam_sm2_verify->p_len, 0); /* p */
	SEQFIFOLOAD(&prg, PKB1, caam_sm2_verify->p_len, 0); /* R2p */
	SEQFIFOLOAD(&prg, PKA3, caam_sm2_verify->p_len, 0); /* a */
	SEQFIFOLOAD(&prg, PKB0, caam_sm2_verify->p_len, 0); /* b */
	FIFOLOAD(&prg, PKA0, caam_sm2_verify->xA_addr, caam_sm2_verify->p_len, 0);
	FIFOLOAD(&prg, PKA1, caam_sm2_verify->yA_addr, caam_sm2_verify->p_len, 0);
	PKHA_OPERATION(&prg, OP_ALG_PKMODE_ECC_MOD_MUL_R2 | OP_ALG_PKMODE_OUT_B);
	
	/* save off [t]PA */
	FIFOSTORE(&prg,PKB1, 0, caam_sm2_verify->tmp1_addr, caam_sm2_verify->p_len, 0);
	FIFOSTORE(&prg,PKB2, 0, caam_sm2_verify->tmp2_addr, caam_sm2_verify->p_len, 0);

	SEQINPTR(&prg, 0, caam_sm2_verify->domain_len, RTO);
	SEQFIFOLOAD(&prg, SKIP, caam_sm2_verify->p_len, 0); /* p already loaded */
	SEQFIFOLOAD(&prg, PKB1, caam_sm2_verify->p_len, 0); /* R2p */
	SEQFIFOLOAD(&prg, PKA3, caam_sm2_verify->p_len, 0); /* a */
	SEQFIFOLOAD(&prg, PKB0, caam_sm2_verify->p_len, 0); /* b */
	SEQFIFOLOAD(&prg, PKA0, caam_sm2_verify->p_len, 0); /* xG */
	SEQFIFOLOAD(&prg, PKA1, caam_sm2_verify->p_len, 0); /* yG */
	KEY(&prg, PKE,0, caam_sm2_verify->s_addr, caam_sm2_verify->p_len, 0);
	PKHA_OPERATION(&prg, OP_ALG_PKMODE_ECC_MOD_MUL_R2 | OP_ALG_PKMODE_OUT_B);
	
	SEQINPTR(&prg, 0, caam_sm2_verify->domain_len , RTO);
	SEQFIFOLOAD(&prg, SKIP, caam_sm2_verify->p_len, 0); /* p already loaded*/
	SEQFIFOLOAD(&prg, PKB3, caam_sm2_verify->p_len, 0); /* R2p */
	SEQFIFOLOAD(&prg, PKA3, caam_sm2_verify->p_len, 0); /* a */
	SEQFIFOLOAD(&prg, PKB0, caam_sm2_verify->p_len, 0); /* b */
	FIFOLOAD(&prg, PKA0, caam_sm2_verify->tmp1_addr, caam_sm2_verify->p_len, 0);
	FIFOLOAD(&prg, PKA1, caam_sm2_verify->tmp2_addr, caam_sm2_verify->p_len, 0);
	PKHA_OPERATION(&prg, OP_ALG_PKMODE_ECC_MOD_ADD_R2_UD | OP_ALG_PKMODE_OUT_A);
	
	/* B7: calculate R=(e'+x1') modn, verification pass if yes, otherwise failed */

	SEQINPTR(&prg, 0, caam_sm2_verify->domain_len, RTO);
	SEQFIFOLOAD(&prg, SKIP , 6 * caam_sm2_verify->p_len, 0);
	SEQFIFOLOAD(&prg, PKN, caam_sm2_verify->n_len, 0); /* n */
	FIFOLOAD(&prg, PKB, caam_sm2_verify->e_addr, caam_sm2_verify->n_len, 0);
	PKHA_OPERATION(&prg, OP_ALG_PKMODE_MOD_ADD | OP_ALG_PKMODE_OUT_A); /* e+x1 */
	PKHA_OPERATION(&prg, OP_ALG_PKMODE_MOD_AMODN_UD | OP_ALG_PKMODE_OUT_B); /* may need extra reduction */
	FIFOLOAD(&prg, PKA, caam_sm2_verify->r_addr, caam_sm2_verify->n_len, 0);
	
	/* Compare computed r with received r */
	PKHA_OPERATION(&prg, OP_ALG_PKMODE_F2M_ADD | OP_ALG_PKMODE_OUT_B);  /* XOR function */   
	JUMP(&prg, SIG_VERIFY_STATUS, HALT_STATUS, ANY_FALSE, PK_0); /* User Status means Invalid Signature */
	
	return PROGRAM_FINALIZE(&prg);
}

static void caam_job_done(struct device *dev, u32 *desc, u32 err, void *context) {
	struct caam_job_result *res;
	u32 ssrc;
	res = context;
	
	if (err == -EINPROGRESS)
	goto out_bklogged;

	if (err) {
		dev_err(dev, "caam op done err: %x\n", err);
		ssrc = err >> JRSTA_SSRC_SHIFT;
		if(ssrc != 3) /*No JUMP error messages */
		/* print the error source name. */
		caam_jr_strstatus(dev, err);
	}
	res->error = err; /* save off the error for postprocessing */
	out_bklogged:	
	complete(&res->comp); /* mark us complete */
}

static long caam_sm2_ioctl(struct file *filp, u32 ioctl_num, u64 ioctl_param)
{
	struct device *jrdev = NULL;
	struct caam_sm2_verify_req req;
	struct caam_sm2_verify_t* caam_sm2_verify = NULL;
	int err = 0;
	
	caam_sm2_verify = filp->private_data;
	if(!caam_sm2_verify)
	return -EINVAL;
	
	jrdev = caam_sm2_get_jrdev();
	
	if(!jrdev)
	return -ENODEV;

	if (mutex_lock_interruptible(&caam_sm2_verify->lock) != 0)
	return -EINTR;
	/* 
	* Switch according to the ioctl ccaam_sm2_dev->param_memed 
	* one ioctl ccaam_sm2_dev->param_mem is implemented to verify the signature 
	*/
	switch (ioctl_num) {
	case IOCTL_CAAM_SM2_VERIF_SIG:
		if (copy_from_user(&req, (void *)ioctl_param, sizeof(struct caam_sm2_verify_req)) != 0) {
			dev_err(jrdev, "Copy from user failed");
			err = -EFAULT;
			goto out;
		}
		err =  do_ioctl(caam_sm2_verify, &req);
		break;	
	default:
		err = -EINVAL;
	}
out:
	mutex_unlock(&caam_sm2_verify->lock);
	return err;
}

static u32 caam_sm2_poll(struct file *file, poll_table * wait)
{
	return 0;
}

/*
do_ioctl() returns 
1 for a valid signature, 
0 for an invalid signature and 
err value on error. 
*/
static int do_ioctl(struct caam_sm2_verify_t* caam_sm2_verify, struct caam_sm2_verify_req *req)
{	
	struct caam_job_result verifres;
	int err;
	struct device *jrdev = NULL;
	
	jrdev = caam_sm2_get_jrdev();
	if(!jrdev)
	return -ENODEV;

	memcpy(caam_sm2_verify->r_mem, req->r, req->r_len);
	memcpy(caam_sm2_verify->s_mem, req->s, req->s_len);
	memcpy(caam_sm2_verify->e_mem, req->e, req->e_len);
	memcpy(caam_sm2_verify->xA_mem, req->xA, req->xA_len);
	memcpy(caam_sm2_verify->yA_mem, req->yA, req->yA_len);
	
	init_completion(&verifres.comp);;
	/* Enqueue the job descriptor */
	err = caam_jr_enqueue(jrdev, caam_sm2_verify->desc, caam_job_done, &verifres);
	
	if(err == -EBUSY)
	{
		pr_err("CAAM is busy\n");
		return err;
	}
	if (!err) {
		wait_for_completion(&verifres.comp);
	}

	err = verifres.error; 

	caam_jr_strstatus(jrdev, err);
	
	if((err & 0xff) == SIG_VERIFY_STATUS) /* Status means Invalid signature */
	err = SIG_VERIFY_FAIL; 
	else if(err == 0) /* Valid signature */
	err = SIG_VERIFY_SUCCESS;	
	/* return err on verifying signature error */
	
	return err;
}

static int caam_sm2_open(struct inode* inode, struct file* filp) {

	struct device *jrdev = NULL;
	struct caam_sm2_verify_t* caam_sm2_verify = NULL;
	u32 *desc;
	u32 desc_len;
	
	jrdev = caam_sm2_get_jrdev();
	if(!jrdev)
	return -ENODEV;
	
	/* space allocation for private data */
	caam_sm2_verify = kzalloc(sizeof(struct caam_sm2_verify_t),GFP_KERNEL | GFP_DMA);
	if (!caam_sm2_verify)
	{
		pr_err("Alloc caam_sm2_verify failed\n");
		return -ENOMEM;
	}
	
	caam_sm2_verify->p_len = P_LEN;
	caam_sm2_verify->n_len = N_LEN;
	caam_sm2_verify->domain_len = DOMAIN_LEN;
	
	desc = kzalloc(sizeof(u32) * CAAM_MAX_JOB_SIZE, GFP_KERNEL | GFP_DMA);
	if (!desc) {
		dev_err(jrdev, "unable to allocate memory\n");
		kfree(caam_sm2_verify);
		return -ENOMEM;
	}
	
	caam_sm2_verify->domain_mem = dma_alloc_coherent(jrdev, caam_sm2_verify->domain_len, &caam_sm2_verify->domain_addr, GFP_KERNEL | GFP_DMA);
	if(!caam_sm2_verify->domain_mem)
	{
		pr_err("Error allocating memory caam_sm2_verify->domain_mem\n");
		kfree(desc);
		kfree(caam_sm2_verify);
		return -ENOMEM;
	}
	memcpy(caam_sm2_verify->domain_mem, domain, 256);
	
	/* Holds e, r, s, xA, yA in one vector */
	caam_sm2_verify->param_len = caam_sm2_verify->n_len*3 + caam_sm2_verify->p_len*2;
	caam_sm2_verify->param_mem = dma_alloc_coherent(jrdev, caam_sm2_verify->param_len, &caam_sm2_verify->param_mem_addr, GFP_KERNEL | GFP_DMA);
	if(!caam_sm2_verify->param_mem)
	{
		pr_err("Error allocating memory caam_sm2_verify->param_mem\n");
		kfree(caam_sm2_verify->domain_mem);
		kfree(desc);
		kfree(caam_sm2_verify);
		return -ENOMEM;
	}
	
	/* Fill parameters vector */
	caam_sm2_verify->r_mem = caam_sm2_verify->param_mem;
	caam_sm2_verify->s_mem = caam_sm2_verify->r_mem + caam_sm2_verify->p_len;
	caam_sm2_verify->e_mem = caam_sm2_verify->s_mem + caam_sm2_verify->p_len;
	caam_sm2_verify->xA_mem = caam_sm2_verify->e_mem + caam_sm2_verify->p_len;
	caam_sm2_verify->yA_mem = caam_sm2_verify->xA_mem + caam_sm2_verify->p_len;

	caam_sm2_verify->tmp = dma_alloc_coherent(jrdev, caam_sm2_verify->p_len * 2, &caam_sm2_verify->tmp_addr, GFP_KERNEL | GFP_DMA);
	if(!caam_sm2_verify->tmp)
	{
		pr_err("Error allocating memory tmp\n");
		kfree(caam_sm2_verify->param_mem);
		kfree(caam_sm2_verify->domain_mem);
		kfree(desc);
		kfree(caam_sm2_verify);
		return -ENOMEM;
	}
	
	caam_sm2_verify->tmp1_mem = caam_sm2_verify->tmp;
	caam_sm2_verify->tmp2_mem = caam_sm2_verify->tmp1_mem + caam_sm2_verify->p_len;
	
	caam_sm2_verify->r_addr = caam_sm2_verify->param_mem_addr;
	caam_sm2_verify->s_addr = caam_sm2_verify->r_addr + caam_sm2_verify->n_len;
	caam_sm2_verify->e_addr = caam_sm2_verify->s_addr + caam_sm2_verify->n_len;
	caam_sm2_verify->xA_addr = caam_sm2_verify->e_addr + caam_sm2_verify->n_len;
	caam_sm2_verify->yA_addr = caam_sm2_verify->xA_addr + caam_sm2_verify->p_len;
	caam_sm2_verify->tmp1_addr = caam_sm2_verify->xA_addr;
	caam_sm2_verify->tmp2_addr = caam_sm2_verify->yA_addr;
	
	desc_len = caam_sm2_verify_jobdesc(desc, caam_sm2_verify);
	
	mutex_init(&caam_sm2_verify->lock);
	
	caam_sm2_verify->desc = desc;
	caam_sm2_verify->desc_len = desc_len;
	filp->private_data = caam_sm2_verify;
	
	return 0;
}

static int caam_sm2_release(struct inode* inode, struct file* filp) {
	
	struct device *jrdev = NULL;
	struct caam_sm2_verify_t* caam_sm2_verify = NULL;
	
	caam_sm2_verify = filp->private_data;
	
	if(!caam_sm2_verify)
	return -EINVAL;
	
	jrdev = caam_sm2_get_jrdev();
	if(!jrdev)
	return -ENODEV;
	
	/* DMA unmap caam_sm2_verify->param_mem mapped pointers */
	dma_free_coherent(jrdev, caam_sm2_verify->p_len * 2, caam_sm2_verify->tmp, caam_sm2_verify->tmp_addr);
	dma_free_coherent(jrdev, caam_sm2_verify->param_len, caam_sm2_verify->param_mem, caam_sm2_verify->param_mem_addr);
	dma_free_coherent(jrdev, caam_sm2_verify->domain_len, caam_sm2_verify->domain_mem, caam_sm2_verify->domain_addr);
	
	kfree(caam_sm2_verify->desc);
	kfree(caam_sm2_verify);
	filp->private_data = NULL;
	return 0;
}

static struct miscdevice caamsm2_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DEVICE_NAME,
	.fops = &caam_sm2_fops,
	.mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
};

/* Public Key Cryptography module initialization handler */
static int caam_sm2_init(void) {
	
	struct device *jrdev;
	struct device_node *dev_node;
	struct platform_device *pdev;
	struct device *ctrldev;
	struct caam_drv_private *priv;
	u32 cha_inst, caam_inst;
	int err;

	dev_node = of_find_compatible_node(NULL, NULL, "fsl,sec-v4.0");
	if (!dev_node) {
		dev_node = of_find_compatible_node(NULL, NULL, "fsl,sec4.0");
		if (!dev_node)
		return -ENODEV;
	}

	pdev = of_find_device_by_node(dev_node);
	if (!pdev) {
		of_node_put(dev_node);
		return -ENODEV;
	}

	ctrldev = &pdev->dev;
	priv = dev_get_drvdata(ctrldev);
	of_node_put(dev_node);

	/*
	* If priv is NULL, it's probably because the caam driver wasn't
	* properly initialized (e.g. RNG4 init failed). Thus, bail out here.
	*/
	if (!priv)
	return -ENODEV;

	/* Determine public key hardware accelerator presence. */
	cha_inst = rd_reg32(&priv->ctrl->perfmon.cha_num_ls);
	caam_inst = (cha_inst & CHA_ID_LS_PK_MASK) >> CHA_ID_LS_PK_SHIFT;
	/* Do not register functions if PKHA is not present. */
	if (!caam_inst)
	return -ENODEV;
	
	/* Allocate Job Ring device */
	jrdev = caam_jr_alloc();
	
	if (IS_ERR(jrdev)) {
		caam_sm2_ctx = NULL;
		pr_err("Job Ring Device allocation for transform failed\n");
		return PTR_ERR(jrdev);
	}
	
	caam_sm2_ctx = kmalloc(sizeof(struct caam_sm2_ctx_t), GFP_DMA | GFP_KERNEL);
	if(!caam_sm2_ctx)
	{
		pr_err("Error allocating memory for CAAM SM2 CTX\n");
		caam_jr_free(jrdev);
		return -ENOMEM;
	}

	caam_sm2_ctx->jrdev = jrdev;

	err = misc_register(&caamsm2_dev);
	if (unlikely(err)) {
		pr_err("registration of /dev/caam-sm2 failed\n");
	}

	return err;
}

static void caam_sm2_exit(void) {
	caam_jr_free(caam_sm2_get_jrdev());
	kfree(caam_sm2_ctx);
	caam_sm2_ctx = NULL;
	misc_deregister(&caamsm2_dev);
}

MODULE_DESCRIPTION("CAAM-accelerated SM2 Algorithm (Partially)");
MODULE_LICENSE("GPL");

module_init( caam_sm2_init);
module_exit( caam_sm2_exit);

