/*
* CAAM ECDSA driver with Black key support
* 
* A kernel module which exports functions to perform ECDSA operations, 
* (Sign, Verify, Key pair generation) taking advantage of CAAM's black key mechanism.
* It was mainly developed as PoC. 
* The driver can be used with any other application for demo purpose.
*
* CAAM has a rich set of built-in ECC domains, in this implementation only 
* P-192, P-224, P-256, P-384 and P-521 are supported.
* 
* The implementation can be easily extended to support more curves 
* based on curve_name for example rather than input sizes.
* Curve selection is based on inputs size, if D is 32bits size
* then P-256 curve is selected.
*
*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/errno.h>

#include <caam/compat.h>
#include <caam/intern.h>
#include <caam/desc_constr.h>
#include <caam/jr.h>
#include <caam/desc.h>

#define ECDSA_P192_LEN	24
#define ECDSA_P224_LEN	28
#define ECDSA_P256_LEN	32
#define ECDSA_P384_LEN	48
#define ECDSA_P521_LEN	66

#define ECDSA_VERIFY_SUCCESS	1
#define ECDSA_VERIFY_FAIL		0

/* If the signature is incorrect, 0x86 status code is returned */
#define ECDSA_INVA_SIG_STATUS	0x86
/* ECB-encrypted key
The bit is ignored for signature verification because only public
keys are used.*/
#define CAAM_PROTINFO_SEC_KEY	(0x01 << 2)
/* To indicate command type ALGORITHM OPERATION, PKHA OPERATION or
PROTOCOL OPERATION */
#define CAAM_PROTOP_CTYPE	(0x10u << 27)
/* When the PD (Predefined Domain) bit in the PDB is 1, the ECDSEL (Elliptic Curve
Domain Selection) field is used to select one of the built-in ECC domains*/
#define CAAM_ECDSA_PD				(0x1 <<  22)
/* P-192, secp192r1, ansix9p192r1, prime192v1, ECPRGF192Random */
#define CAAM_ECDSA_ECDSEL_P192		((0x00 & 0x7F) << 7)
/* P-224, secp224r1, ansix9p224r1, wtls12, ECPRGF224Random */
#define CAAM_ECDSA_ECDSEL_P224		((0x01 & 0x7F) << 7)
/* P-256, secp256r1, ansix9p256r1, prime256v1, ECDSA-256, ecp_group_19, ECPRGF256Random */
#define CAAM_ECDSA_ECDSEL_P256		((0x02 & 0x7F) << 7)
/* P-384, secp384r1, ansix9p384r1, ECDSA-384, ecp_group_20, ECPRGF384Random */
#define CAAM_ECDSA_ECDSEL_P384		((0x03 & 0x7F) << 7)
/* P-521, secp521r1, ansix9p521r1, ECDSA-521, ecp_group_21, ECPRGF521Random */
#define CAAM_ECDSA_ECDSEL_P521		((0x04 & 0x7F) << 7)
/* ECC Key Pair Generation */
#define CAAM_CMD_ECC_GEN_KP			(0x2 << 24)

typedef struct {
	u8 *addr_s;
	u8 *addr_f;
	u8 *addr_c;
	u8 *addr_d;
	dma_addr_t phy_addr_s;
	dma_addr_t phy_addr_f;
	dma_addr_t phy_addr_c;
	dma_addr_t phy_addr_d;
	u32 p_len;
	u32 n_len;
	u32 *desc;
}caam_ecdsa_sign_t;

typedef struct {
	u8 *addr_w;
	u8 *addr_f;
	u8 *addr_c;
	u8 *addr_d;
	/*The temporary buffer must be at least 2L bytes.*/
	u8 *addr_tmp;
	dma_addr_t phy_addr_w;
	dma_addr_t phy_addr_f;
	dma_addr_t phy_addr_c;
	dma_addr_t phy_addr_d;
	dma_addr_t phy_addr_tmp;
	u32 p_len;
	u32 n_len;
	u32 *desc;
}caam_ecdsa_verify_t;

typedef struct {
	u8 *addr_s;
	u8 *addr_w;
	dma_addr_t phy_addr_s;
	dma_addr_t phy_addr_w;
	u32 p_len;
	u32 *desc;
}caam_ecdsa_genkey_t;

/* ECDSA (PD=1) Signature Generation protocol
data block,  pointers in PDB */
struct ecdsa_sign_desc_s {
	u32 sgf; /* Use ECDSA_PDB_ definitions per above */
	caam_dma_addr_t s_dma; /* d */
	caam_dma_addr_t f_dma; /* msg repr */
	caam_dma_addr_t c_dma; /* r */
	caam_dma_addr_t d_dma; /* s */
} __packed;

struct ecdsa_verify_desc_s {
	u32 sgf;
	caam_dma_addr_t w_dma; /* Wx,y */
	caam_dma_addr_t f_dma; /* msg rep */
	caam_dma_addr_t c_dma; /* r */
	caam_dma_addr_t d_dma; /* s */
	caam_dma_addr_t tmp_dma; /* temporary data block */
} __packed;

struct ecdsa_genkey_desc_s{
	u32 sgf;
	caam_dma_addr_t s_dma;	/* s */
	caam_dma_addr_t w_dma;	/* Wx,y	*/
}__packed;

/* pk per-device context */
struct caam_ctx {
	struct device *jrdev;
};

struct caam_operation_result {
	struct completion completion;
	int err;
};

static struct caam_ctx *caam_ecdsa_ctx = NULL;

void caam_ecdsa_verify_jobdesc(u32 *desc, caam_ecdsa_verify_t *ecdsa_verify);
void caam_ecdsa_sign_jobdesc(u32 *desc, caam_ecdsa_sign_t *ecdsa_sign);
void caam_ecdsa_genkey_jobdesc(u32 *desc, caam_ecdsa_genkey_t *ecdsa_genkey);
int caam_ecdsa_verify(caam_ecdsa_verify_t *ecdsa_verify);
int caam_ecdsa_verify_deinit(caam_ecdsa_verify_t *ecdsa_verify);
int caam_ecdsa_verify_init(caam_ecdsa_verify_t *ecdsa_verify);
int caam_ecdsa_sign(caam_ecdsa_sign_t *ecdsa_sign);
int caam_ecdsa_sign_deinit(caam_ecdsa_sign_t *ecdsa_sign);
int caam_ecdsa_sign_init(caam_ecdsa_sign_t *ecdsa_sign);
int caam_ecdsa_genkey_init(caam_ecdsa_genkey_t *ecdsa_genkey);
int caam_ecdsa_genkey_deinit(caam_ecdsa_genkey_t *ecdsa_genkey);
int caam_ecdsa_genkey(caam_ecdsa_genkey_t *ecdsa_genkey);
void caam_operation_done(struct device *dev, u32 *desc, u32 err, void *context);

struct device *caam_ecdsa_get_jrdev(void)
{
	if (NULL != caam_ecdsa_ctx) {
		if (caam_ecdsa_ctx->jrdev != NULL ) {
			return caam_ecdsa_ctx->jrdev;
		}
	}
	return NULL;
}
EXPORT_SYMBOL(caam_ecdsa_get_jrdev);

int caam_pk_status(void)
{
	return NULL != caam_ecdsa_ctx ? 1:0;
}
EXPORT_SYMBOL(caam_pk_status);

int caam_ecdsa_sign_init(caam_ecdsa_sign_t *ecdsa_sign)
{
	struct device *jrdev = caam_ecdsa_ctx->jrdev;
	int ret = 0;
	size_t total_len;

	if (0 == ecdsa_sign->p_len || 0 == ecdsa_sign->n_len ||
			(ecdsa_sign->p_len != ECDSA_P192_LEN && 
			ecdsa_sign->p_len != ECDSA_P224_LEN && 
			ecdsa_sign->p_len != ECDSA_P256_LEN &&
			ecdsa_sign->p_len != ECDSA_P384_LEN && 
			ecdsa_sign->p_len != ECDSA_P521_LEN))
	return -EINVAL;
	
	ecdsa_sign->desc = kmalloc(MAX_CAAM_DESCSIZE * sizeof(u32), GFP_KERNEL | GFP_DMA);
	if (unlikely(!ecdsa_sign->desc))
	goto desc_alloc_fail;
	total_len = ecdsa_sign->p_len + ecdsa_sign->n_len * 3;
	ecdsa_sign->addr_s = dma_alloc_coherent(jrdev, total_len, &ecdsa_sign->phy_addr_s, GFP_KERNEL | GFP_DMA);
	if (unlikely(!ecdsa_sign->addr_s))
	goto q_alloc_fail;
	
	memset(ecdsa_sign->addr_s, 0, total_len);
	ecdsa_sign->addr_f = ecdsa_sign->addr_s + ecdsa_sign->p_len;
	ecdsa_sign->phy_addr_f = ecdsa_sign->phy_addr_s + ecdsa_sign->p_len;
	ecdsa_sign->addr_c = ecdsa_sign->addr_f + ecdsa_sign->n_len;
	ecdsa_sign->phy_addr_c = ecdsa_sign->phy_addr_f + ecdsa_sign->n_len;
	ecdsa_sign->addr_d = ecdsa_sign->addr_c + ecdsa_sign->n_len;
	ecdsa_sign->phy_addr_d = ecdsa_sign->phy_addr_c + ecdsa_sign->n_len;

	return ret;

	q_alloc_fail:
	kfree(ecdsa_sign->desc);
	desc_alloc_fail:
	return -ENOMEM;
}
EXPORT_SYMBOL(caam_ecdsa_sign_init);

int caam_ecdsa_sign_deinit(caam_ecdsa_sign_t *ecdsa_sign)
{
	struct device *jrdev = caam_ecdsa_ctx->jrdev;
	int ret = 0;

	dma_free_coherent(jrdev, ecdsa_sign->p_len + ecdsa_sign->n_len * 3,
	(void *)ecdsa_sign->addr_s, ecdsa_sign->phy_addr_s);
	
	kfree(ecdsa_sign->desc);
	
	return ret;
}
EXPORT_SYMBOL(caam_ecdsa_sign_deinit);

int caam_ecdsa_sign(caam_ecdsa_sign_t *ecdsa_sign)
{
	struct device *jrdev = caam_ecdsa_ctx->jrdev;
	u32 *desc = ecdsa_sign->desc;
	int ret = 0;
	struct caam_operation_result res;

	memset(desc, 0, MAX_CAAM_DESCSIZE * sizeof(u32));

	caam_ecdsa_sign_jobdesc(desc, ecdsa_sign);

	res.err = 0;
	init_completion(&res.completion);

	ret = caam_jr_enqueue(jrdev, desc, caam_operation_done, &res);
	if (!ret) {
		wait_for_completion(&res.completion);
		ret = res.err;
	}

	dma_sync_single_for_cpu(jrdev, ecdsa_sign->phy_addr_c, ecdsa_sign->n_len, DMA_FROM_DEVICE);
	dma_sync_single_for_cpu(jrdev, ecdsa_sign->phy_addr_d, ecdsa_sign->n_len, DMA_FROM_DEVICE);
	
	return ret;
}
EXPORT_SYMBOL(caam_ecdsa_sign);

int caam_ecdsa_verify_init(caam_ecdsa_verify_t *ecdsa_verify)
{
	struct device *jrdev = caam_ecdsa_ctx->jrdev;
	int ret = 0;
	size_t total_len;

	if (0 == ecdsa_verify->p_len || 0 == ecdsa_verify->n_len ||
			(ecdsa_verify->p_len != ECDSA_P192_LEN && 
			ecdsa_verify->p_len != ECDSA_P224_LEN && 
			ecdsa_verify->p_len != ECDSA_P256_LEN &&
			ecdsa_verify->p_len != ECDSA_P384_LEN && 
			ecdsa_verify->p_len != ECDSA_P521_LEN))
	return -EINVAL;

	ecdsa_verify->desc = kmalloc(MAX_CAAM_DESCSIZE * sizeof(u32), GFP_KERNEL | GFP_DMA);
	if (unlikely(!ecdsa_verify->desc))
	goto desc_alloc_fail;
	total_len = ecdsa_verify->p_len * 4 + ecdsa_verify->n_len * 3;
	ecdsa_verify->addr_w = dma_alloc_coherent(jrdev, total_len, &ecdsa_verify->phy_addr_w, GFP_KERNEL | GFP_DMA);
	if (unlikely(!ecdsa_verify->addr_w))
	goto q_alloc_fail;

	memset(ecdsa_verify->addr_w, 0, total_len);
	ecdsa_verify->addr_f = ecdsa_verify->addr_w + ecdsa_verify->p_len * 2;
	ecdsa_verify->phy_addr_f  = ecdsa_verify->phy_addr_w + ecdsa_verify->p_len * 2;
	ecdsa_verify->addr_c = ecdsa_verify->addr_f + ecdsa_verify->n_len;
	ecdsa_verify->phy_addr_c  = ecdsa_verify->phy_addr_f + ecdsa_verify->n_len;
	ecdsa_verify->addr_d = ecdsa_verify->addr_c + ecdsa_verify->n_len;
	ecdsa_verify->phy_addr_d  = ecdsa_verify->phy_addr_c + ecdsa_verify->n_len;
	ecdsa_verify->addr_tmp = ecdsa_verify->addr_d + ecdsa_verify->n_len;
	ecdsa_verify->phy_addr_tmp  = ecdsa_verify->phy_addr_d + ecdsa_verify->n_len;

	return ret;

	q_alloc_fail:
	kfree(ecdsa_verify->desc);
	desc_alloc_fail:
	return -ENOMEM;
}
EXPORT_SYMBOL(caam_ecdsa_verify_init);

int caam_ecdsa_verify_deinit(caam_ecdsa_verify_t *ecdsa_verify)
{
	struct device *jrdev = caam_ecdsa_ctx->jrdev;
	int ret = 0;

	dma_free_coherent(jrdev, ecdsa_verify->p_len * 2 + ecdsa_verify->n_len * 3, (void *)ecdsa_verify->addr_w, ecdsa_verify->phy_addr_w);
	kfree(ecdsa_verify->desc);

	return ret;
}
EXPORT_SYMBOL(caam_ecdsa_verify_deinit);

/*
-1 = Error
1 = Valid signature
0 = Invalid Signature
*/
int caam_ecdsa_verify(caam_ecdsa_verify_t *ecdsa_verify)
{
	struct device *jrdev = caam_ecdsa_ctx->jrdev;
	u32 *desc = ecdsa_verify->desc;
	int ret = 0;
	struct caam_operation_result res;

	memset(desc, 0, MAX_CAAM_DESCSIZE * sizeof(u32));

	caam_ecdsa_verify_jobdesc(desc, ecdsa_verify);
	
	res.err = 0;
	init_completion(&res.completion);

	ret = caam_jr_enqueue(jrdev, desc, caam_operation_done, &res);
	if (!ret) {
		wait_for_completion(&res.completion);
		ret = res.err;
	}
	/*If the signature is correct, caam_jr_enqueue terminates normally.*/
	if(ret == 0)
	return ECDSA_VERIFY_SUCCESS;
	else if ((res.err & 0xff) == ECDSA_INVA_SIG_STATUS)
	return ECDSA_VERIFY_FAIL;

	return ret;
}
EXPORT_SYMBOL(caam_ecdsa_verify);

int caam_ecdsa_genkey_init(caam_ecdsa_genkey_t *ecdsa_genkey)
{
	struct device *jrdev = caam_ecdsa_ctx->jrdev;
	int ret = 0;
	size_t total_len;
	
	if (0 == ecdsa_genkey->p_len ||
			(ecdsa_genkey->p_len != ECDSA_P192_LEN && 
			ecdsa_genkey->p_len != ECDSA_P224_LEN && 
			ecdsa_genkey->p_len != ECDSA_P256_LEN &&
			ecdsa_genkey->p_len != ECDSA_P384_LEN && 
			ecdsa_genkey->p_len != ECDSA_P521_LEN))
	return -EINVAL;
	
	ecdsa_genkey->desc = kmalloc(MAX_CAAM_DESCSIZE * sizeof(u32), GFP_KERNEL | GFP_DMA);
	if (unlikely(!ecdsa_genkey->desc))
	goto desc_alloc_fail;
	total_len = ecdsa_genkey->p_len * 3;
	ecdsa_genkey->addr_s = dma_alloc_coherent(jrdev, total_len, &ecdsa_genkey->phy_addr_s, GFP_KERNEL | GFP_DMA);
	if (unlikely(!ecdsa_genkey->addr_s))
	goto q_alloc_fail;
	
	memset(ecdsa_genkey->addr_s, 0, total_len);
	ecdsa_genkey->addr_w = ecdsa_genkey->addr_s + ecdsa_genkey->p_len;
	ecdsa_genkey->phy_addr_w = ecdsa_genkey->phy_addr_s + ecdsa_genkey->p_len;

	return ret;

	q_alloc_fail:
	kfree(ecdsa_genkey->desc);
	desc_alloc_fail:
	return -ENOMEM;
}
EXPORT_SYMBOL(caam_ecdsa_genkey_init);

int caam_ecdsa_genkey_deinit(caam_ecdsa_genkey_t *ecdsa_genkey)
{
	struct device *jrdev = caam_ecdsa_ctx->jrdev;
	int ret = 0;

	dma_free_coherent(jrdev, ecdsa_genkey->p_len * 3,
	(void *)ecdsa_genkey->addr_s, ecdsa_genkey->phy_addr_s);
	
	kfree(ecdsa_genkey->desc);
	
	return ret;
}
EXPORT_SYMBOL(caam_ecdsa_genkey_deinit);

int caam_ecdsa_genkey(caam_ecdsa_genkey_t *ecdsa_genkey)
{
	struct device *jrdev = caam_ecdsa_ctx->jrdev;
	u32 *desc = ecdsa_genkey->desc;
	int ret = 0;
	struct caam_operation_result res;

	memset(desc, 0, MAX_CAAM_DESCSIZE * sizeof(u32));

	caam_ecdsa_genkey_jobdesc(desc, ecdsa_genkey);

	res.err = 0;
	init_completion(&res.completion);

	ret = caam_jr_enqueue(jrdev, desc, caam_operation_done, &res);
	if (!ret) {
		wait_for_completion(&res.completion);
		ret = res.err;
	}

	dma_sync_single_for_cpu(jrdev, ecdsa_genkey->phy_addr_s, ecdsa_genkey->p_len, DMA_FROM_DEVICE);
	dma_sync_single_for_cpu(jrdev, ecdsa_genkey->phy_addr_w, ecdsa_genkey->p_len*2, DMA_FROM_DEVICE);
	
	return ret;
}
EXPORT_SYMBOL(caam_ecdsa_genkey);


void caam_ecdsa_sign_jobdesc(u32 *desc, caam_ecdsa_sign_t *ecdsa_sign)
{	
	u32 curve;
	
	init_job_desc_pdb(desc, 0, sizeof(struct ecdsa_sign_desc_s));
	
	if(ecdsa_sign->p_len == ECDSA_P256_LEN)
	curve = CAAM_ECDSA_ECDSEL_P256;
	else if(ecdsa_sign->p_len == ECDSA_P384_LEN)
	curve = CAAM_ECDSA_ECDSEL_P384;
	else
	curve = CAAM_ECDSA_ECDSEL_P521;
	
	append_cmd(desc, curve | CAAM_ECDSA_PD);
	append_ptr(desc, ecdsa_sign->phy_addr_s);
	append_ptr(desc, ecdsa_sign->phy_addr_f);
	append_ptr(desc, ecdsa_sign->phy_addr_c);	
	append_ptr(desc, ecdsa_sign->phy_addr_d);	
	append_operation(desc, CAAM_PROTOP_CTYPE | OP_TYPE_UNI_PROTOCOL |
	OP_PCLID_DSASIGN |
	OP_PCL_PKPROT_ECC |
	CAAM_PROTINFO_SEC_KEY);
	
	dma_sync_single_for_device(caam_ecdsa_ctx->jrdev, ecdsa_sign->phy_addr_s, 
	ecdsa_sign->p_len * 2 + ecdsa_sign->n_len * 2, DMA_TO_DEVICE);
}

void caam_ecdsa_verify_jobdesc(u32 *desc, caam_ecdsa_verify_t *ecdsa_verify)
{	
	u32 curve;
	init_job_desc_pdb(desc, 0, sizeof(struct ecdsa_verify_desc_s));
	if(ecdsa_verify->p_len == ECDSA_P256_LEN)
	curve = CAAM_ECDSA_ECDSEL_P256;
	else if(ecdsa_verify->p_len == ECDSA_P384_LEN)
	curve = CAAM_ECDSA_ECDSEL_P384;
	else
	curve = CAAM_ECDSA_ECDSEL_P521;
	
	append_cmd(desc, curve | CAAM_ECDSA_PD);
	append_ptr(desc, ecdsa_verify->phy_addr_w);
	append_ptr(desc, ecdsa_verify->phy_addr_f);
	append_ptr(desc, ecdsa_verify->phy_addr_c);	
	append_ptr(desc, ecdsa_verify->phy_addr_d);	
	append_ptr(desc, ecdsa_verify->phy_addr_tmp);	
	append_operation(desc, CAAM_PROTOP_CTYPE | OP_TYPE_UNI_PROTOCOL | OP_PCLID_DSAVERIFY |
	OP_PCL_PKPROT_ECC | CAAM_PROTINFO_SEC_KEY);
	
	dma_sync_single_for_device(caam_ecdsa_ctx->jrdev, ecdsa_verify->phy_addr_w, 
	ecdsa_verify->p_len * 4 + ecdsa_verify->n_len * 3, DMA_TO_DEVICE);
}

void caam_ecdsa_genkey_jobdesc(u32 *desc, caam_ecdsa_genkey_t *ecdsa_genkey)
{	
	u32 curve;
	
	init_job_desc_pdb(desc, 0, sizeof(struct ecdsa_genkey_desc_s));
	
	if(ecdsa_genkey->p_len == ECDSA_P256_LEN)
	curve = CAAM_ECDSA_ECDSEL_P256;
	else if(ecdsa_genkey->p_len == ECDSA_P384_LEN)
	curve = CAAM_ECDSA_ECDSEL_P384;
	else
	curve = CAAM_ECDSA_ECDSEL_P521;
	
	append_cmd(desc, curve | CAAM_CMD_ECC_GEN_KP);
	append_ptr(desc, ecdsa_genkey->phy_addr_s);
	append_ptr(desc, ecdsa_genkey->phy_addr_w);
	append_operation(desc, CAAM_PROTOP_CTYPE | OP_TYPE_UNI_PROTOCOL |  
	OP_PCLID_PUBLICKEYPAIR | OP_PCL_PKPROT_ECC | CAAM_PROTINFO_SEC_KEY);
	
	dma_sync_single_for_device(caam_ecdsa_ctx->jrdev,
	ecdsa_genkey->phy_addr_s, ecdsa_genkey->p_len * 3, DMA_TO_DEVICE);
}

void caam_operation_done(struct device *dev, u32 *desc, u32 err, void *context)
{
	struct caam_operation_result *res = context;
#ifdef DEBUG
	dev_err(dev, "%s %d: err 0x%x\n", __func__, __LINE__, err);
	if (err)
	caam_jr_strstatus(dev, err);
#endif
	res->err = err;
	complete(&res->completion);
}

/* Public Key Cryptography module initialization handler */
static int __init caam_ecdsa_init(void)
{	
	struct device *jrdev;
	struct device_node *dev_node;	
	struct platform_device *pdev;
	struct device *ctrldev;
	struct caam_drv_private *priv;
	u32 cha_inst, caam_inst;
	
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
	if (priv->has_seco) {
		int i = priv->first_jr_index;

		cha_inst = rd_reg32(&priv->jr[i]->perfmon.cha_num_ls);
	} else {
		cha_inst = rd_reg32(&priv->ctrl->perfmon.cha_num_ls);
	}
	caam_inst = (cha_inst & CHA_ID_LS_PK_MASK) >> CHA_ID_LS_PK_SHIFT;

	/* Do not register functions if PKHA is not present. */
	if (!caam_inst)
	return -ENODEV;
	
	jrdev = caam_jr_alloc();
	if (IS_ERR(jrdev)) {
		caam_ecdsa_ctx = NULL;
		pr_err("Job Ring Device allocation for transform failed\n");
		return PTR_ERR(jrdev);
	}
	caam_ecdsa_ctx = kmalloc(sizeof(struct caam_ctx), GFP_DMA | GFP_KERNEL);
	caam_ecdsa_ctx->jrdev = jrdev;

	return 0;
}

static void __exit caam_ecdsa_exit(void)
{
	caam_jr_free(caam_ecdsa_ctx->jrdev);
	kfree(caam_ecdsa_ctx);
	caam_ecdsa_ctx = NULL;
}

module_init(caam_ecdsa_init);
module_exit(caam_ecdsa_exit);
MODULE_DESCRIPTION("CAAM ECDSA driver with Black Key support");
MODULE_LICENSE("Dual BSD/GPL");