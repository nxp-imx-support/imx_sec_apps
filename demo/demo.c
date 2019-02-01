/**
* SPDX-License-Identifier: GPL-2.0
*	
* Copyright 2018-2019 NXP
*
* demo.c: A demo application implements an OpenSSL engine which overloads default OpenSSL SM2 signature verification
* method to use CAAM hardware via caam_sm2 driver.
* First, a key-pair are generated, then, a sample message is signed using the private key and finally the signature is verified
* using both default OpenSSL implementation and using the CAAM hardware.
*
* This demo was written for OpenSSL 1.1.1-pre9.
*
**/

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/e_os2.h>
#include <openssl/ossl_typ.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define OLDER_OPENSSL
#endif

#define IOCTL_CAAM_SM2_VERIF_SIG _IOWR('c', 0, struct caam_sm2_verify_req)

#ifdef CAAM_SM2_DEBUG
#define dbg_fprintf(args...) do { fprintf(stderr, args); fflush(stderr); } while (0)
#else
#define dbg_fprintf(args...)
#endif
#define caam_sm2_err(f,r) ERR_caam_sm2_error((f),(r),__FILE__,__LINE__)

/* Error codes */
#define CAAM_SM2_F_INIT 100
#define CAAM_SM2_F_FINISH 101
#define CAAM_SM2_F_DESTROY 102
#define CAAM_SM2_F_VERIFY_SIG 103

/* Reason codes. */
#define CAAM_SM2_R_BAD_ARG 100
#define CAAM_SM2_R_INTERNAL_ERROR 101
#define CAAM_SM2_R_BAD_CURVE 102
#define CAAM_SM2_R_BAD_SIG 103
#define CAAM_SM2_R_MALLOC 104
#define CAAM_SM2_R_BIGNUM 105
#define CAAM_SM2_R_EC 106
#define CAAM_SM2_R_INVALID_DIGEST 107
#define CAAM_SM2_R_USER_ID_TOO_LARGE 108
#define CAAM_SM2_R_UNSUPPORTED_ALGORITHM 109
#define CAAM_SM2_R_NULL_REFERENCE 110
#define CAAM_SM2_R_INVALID_ENCODING 111
#define CAAM_SM2_R_DEVICE_ERROR 112
#define CAAM_SM2_R_ALREADY_LOADED 113
#define CAAM_SM2_R_NOT_LOADED 114
/* The default user id as specified in GM/T 0009-2012 */
#define SM2_DEFAULT_USERID "1234567812345678"

#define MAJOR_NUM 100
#define IOCTL_VERIF_SIG _IOR(MAJOR_NUM, 0, char *)

/* Engine id & name used when creating the ENGINE */
static const char *engine_caam_sm2_id = "caam_sm2";
static const char *engine_caam_sm2_name = "CAAM-accelerated SM2 signature verification implementation";

static EVP_PKEY_METHOD *sm2_pmeth = NULL;

static int caam_sm2_lib_error_code = 0;
static int caam_sm2_error_init = 1;

/* /dev/caam_sm2 fd */
static int32_t file_desc = -1;

struct caam_sm2_verify_req {
	uint8_t *e;
	uint32_t e_len;
	uint8_t *r;
	uint32_t r_len;
	uint8_t *s;
	uint32_t s_len;
	uint8_t *xA;
	uint32_t xA_len;
	uint8_t *yA;
	uint32_t yA_len;
};

/* Engine constructor */
ENGINE *engine_caam_sm2(void);
/* Needed if the ENGINE is being compiled into a self-contained shared-library. */
static int bind_caam_sm2(ENGINE *e);

/* Needed if the ENGINE is being compiled into a self-contained shared-library. */
static int bind_caam_sm2(ENGINE *e);

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR
static ERR_STRING_DATA caam_sm2_str_functs[]=
{
	{ERR_PACK(0,CAAM_SM2_F_INIT,0),	    "CAAM_SM2_INIT"},
	{ERR_PACK(0,CAAM_SM2_F_FINISH,0),	    "CAAM_SM2_FINISH"},
	{ERR_PACK(0,CAAM_SM2_F_DESTROY,0),	    "CAAM_SM2_DESTROY"},
	{ERR_PACK(0,CAAM_SM2_F_VERIFY_SIG,0),	    "CAAM_SM2_F_VERIFY_SIG"},
	{0,NULL}
};

static ERR_STRING_DATA caam_sm2_str_reasons[]=
{
	{CAAM_SM2_R_BAD_ARG, "Bad argument"},
	{CAAM_SM2_R_INTERNAL_ERROR, "Internal error"},
	{CAAM_SM2_R_BAD_CURVE, "Not a SM2 curve"},
	{CAAM_SM2_R_BAD_SIG, "Bad signature"},
	{CAAM_SM2_R_MALLOC, "Memory allocation failed"},
	{CAAM_SM2_R_BIGNUM, "BIGNUM error"},
	{CAAM_SM2_R_EC, "EC error"},	
	{CAAM_SM2_R_INVALID_DIGEST, "Invalid digest"},	
	{CAAM_SM2_R_USER_ID_TOO_LARGE, "User ID too large"},
	{CAAM_SM2_R_UNSUPPORTED_ALGORITHM ,"Unsupported algorithm"},
	{CAAM_SM2_R_NULL_REFERENCE ,"Null reference"},
	{CAAM_SM2_R_INVALID_ENCODING ,"Invalid encoding"},
	{CAAM_SM2_R_DEVICE_ERROR ,"Device error"},
	{CAAM_SM2_R_ALREADY_LOADED ,"/dev/caam_sm2 already loaded"},
	{CAAM_SM2_R_NOT_LOADED ,"/dev/caam_sm2 not loaded"},
	{0,NULL}
};

#endif	

static int evp_sm2_verify(EVP_PKEY_CTX *ctx, const uint8_t *sig,
size_t sig_len, const uint8_t *tbs, size_t tbs_len);

void ERR_load_caam_sm2_strings(void)
{
	if (caam_sm2_lib_error_code == 0)
	caam_sm2_lib_error_code = ERR_get_next_error_library();

	if (caam_sm2_error_init)
	{
		caam_sm2_error_init=0;
#ifndef OPENSSL_NO_ERR
		ERR_load_strings(caam_sm2_lib_error_code,caam_sm2_str_functs);
		ERR_load_strings(caam_sm2_lib_error_code,caam_sm2_str_reasons);
#endif
	}
}

void ERR_unload_caam_sm2_strings(void)
{
	if (caam_sm2_error_init == 0)
	{
#ifndef OPENSSL_NO_ERR
		ERR_unload_strings(caam_sm2_lib_error_code,caam_sm2_str_functs);
		ERR_unload_strings(caam_sm2_lib_error_code,caam_sm2_str_reasons);
#endif
		caam_sm2_error_init = 1;
	}
}

void ERR_caam_sm2_error(int function, int reason, char *file, int line)
{
	if (caam_sm2_lib_error_code == 0)
	caam_sm2_lib_error_code=ERR_get_next_error_library();
	ERR_PUT_error(caam_sm2_lib_error_code,function,reason,file,line);
}

static int register_pkey_methods(EVP_PKEY_METHOD** meth, int nid) {

	*meth = EVP_PKEY_meth_new(nid, 0);
	if (*meth == NULL) {
		dbg_fprintf("Failure allocating PKEY methods for NID %d", nid);
		return 0;
	}
	const EVP_PKEY_METHOD* orig = EVP_PKEY_meth_find(nid);
	EVP_PKEY_meth_copy(*meth, orig);
	EVP_PKEY_meth_set_verify(*meth, NULL, evp_sm2_verify);

	return 1;
}

/*Initialisation function */
static int caam_sm2_init(ENGINE *e) {

	if (file_desc > -1) {
		caam_sm2_err(CAAM_SM2_F_INIT, CAAM_SM2_R_ALREADY_LOADED);
		goto err;
	}
	
	file_desc = open("/dev/caam_sm2",O_RDWR | O_CLOEXEC);
	if (file_desc < 0) {
		dbg_fprintf("Error opening device\n");
		caam_sm2_err(CAAM_SM2_F_VERIFY_SIG, CAAM_SM2_R_DEVICE_ERROR);
		goto err;
	}

	return 1;

err: if (file_desc > -1) {
		close(file_desc);
	}
	file_desc = -1;
	return 0;

}

/* Destructor (complements the "engine_caam_sm2()" constructor) */
static int caam_sm2_destroy(ENGINE *e) {
	if(!e)
	return 0;
	ERR_unload_caam_sm2_strings();
	return 1;
}

static int caam_sm2_finish(ENGINE *e) {
	
	if (file_desc == -1) {
		caam_sm2_err(CAAM_SM2_F_FINISH, CAAM_SM2_R_NOT_LOADED);
		goto err;
	}
	
	close(file_desc);
	file_desc = -1;

	return 1;

err: file_desc = -1;
	return 0;
}


int sm3_hash(const uint8_t *message, size_t len, uint8_t *hash, uint32_t *hash_len)
{
	EVP_MD_CTX *md_ctx;
	const EVP_MD *md;

	md = EVP_sm3();
	md_ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(md_ctx, md, NULL);
	EVP_DigestUpdate(md_ctx, message, len);
	EVP_DigestFinal_ex(md_ctx, hash, hash_len);
	EVP_MD_CTX_free(md_ctx);
	return 0;
}

/**
* SM2 signature verify method
*
* @return
*      1: correct signature
*      0: incorrect signature
*     -1: error
*/
static int sm2_sig_verify(const EC_KEY *key, const ECDSA_SIG *sig,
const BIGNUM *e)
{
	int ret = 0;
	const BIGNUM *order = EC_GROUP_get0_order(EC_KEY_get0_group(key));

	const BIGNUM *r = NULL;
	const BIGNUM *s = NULL;
	BIGNUM *xA = NULL, *yA = NULL;
	struct caam_sm2_verify_req req;
	
	BN_CTX *ctx = BN_CTX_new();
	
	if (!ctx) {
		caam_sm2_err(CAAM_SM2_F_VERIFY_SIG, CAAM_SM2_R_MALLOC);
		return 0;
	}
	
	BN_CTX_start(ctx);

	xA = BN_CTX_get(ctx);
	yA = BN_CTX_get(ctx);
	
	if (!EC_POINT_get_affine_coordinates( EC_KEY_get0_group(key), EC_KEY_get0_public_key(key), xA, yA, ctx))
	{
		caam_sm2_err(CAAM_SM2_F_VERIFY_SIG, CAAM_SM2_R_BAD_SIG);
		goto done;
	}	

	ECDSA_SIG_get0(sig, &r, &s);
	
#if 0	
	printf("e : %s\n", BN_bn2hex(e));
	printf("xA: %s\n", BN_bn2hex(xA));
	printf("yA: %s\n", BN_bn2hex(yA));	
	printf("r : %s\n", BN_bn2hex(r));
	printf("s : %s\n", BN_bn2hex(s));
#endif	
	/*
	* B1: verify whether r' in [1,n-1], verification failed if not
	* B2: vefify whether s' in [1,n-1], verification failed if not
	*/
	if (BN_cmp(r, BN_value_one()) < 0
			|| BN_cmp(s, BN_value_one()) < 0
			|| BN_cmp(order, r) <= 0
			|| BN_cmp(order, s) <= 0) {
		caam_sm2_err(CAAM_SM2_F_VERIFY_SIG, CAAM_SM2_R_BAD_SIG);
		goto done;
	}

	req.e = malloc((BN_num_bytes(e)) * sizeof(uint8_t));
	req.e_len= BN_bn2bin(e, req.e);
	
	req.r = malloc((BN_num_bytes(r)) * sizeof(uint8_t));
	req.r_len = BN_bn2bin(r, req.r);
	
	req.s = malloc((BN_num_bytes(s)) * sizeof(uint8_t));
	req.s_len = BN_bn2bin(s, req.s);
	
	req.xA = malloc((BN_num_bytes(xA)) * sizeof(uint8_t));
	req.xA_len = BN_bn2bin(xA, req.xA);

	req.yA = malloc((BN_num_bytes(yA)) * sizeof(uint8_t));
	req.yA_len = BN_bn2bin(yA, req.yA);

	ret = ioctl(file_desc, IOCTL_CAAM_SM2_VERIF_SIG, &req);

	dbg_fprintf("CAAM driver returned verification status = %d\n", ret);
	
done:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	return ret;
}

static int evp_sm2_verify(EVP_PKEY_CTX *ctx, const uint8_t *sig, size_t sig_len,
const uint8_t *tbs, size_t tbs_len)
{

	EC_KEY *eckey = NULL;
	EVP_PKEY *pkey = NULL;
	
	ECDSA_SIG *s = NULL;
	BIGNUM *e = NULL;
	uint8_t *der = NULL;
	const uint8_t *sig_ptr;
	int derlen = -1;
	int ret = -1;
	
	s = ECDSA_SIG_new();
	if (s == NULL) {
		SM2err(CAAM_SM2_F_VERIFY_SIG, CAAM_SM2_R_MALLOC);
		goto done;
	}

	sig_ptr = sig;
	if (!(s = d2i_ECDSA_SIG(NULL, &sig_ptr, sig_len))) {
		caam_sm2_err(CAAM_SM2_F_VERIFY_SIG, CAAM_SM2_R_INVALID_ENCODING);
		goto done;
	}
	/* Ensure signature uses DER and doesn't have trailing garbage */
	derlen = i2d_ECDSA_SIG(s, &der);
	if (derlen != (int)sig_len || memcmp(sig, der, derlen) != 0) {
		caam_sm2_err(CAAM_SM2_F_VERIFY_SIG, CAAM_SM2_R_INVALID_ENCODING);
		goto done;
	}
	
	e = BN_new();
	if(!e){
		caam_sm2_err(CAAM_SM2_F_VERIFY_SIG, CAAM_SM2_R_MALLOC);
		goto done;
	}
	
	if (BN_bin2bn(tbs, tbs_len, e) == NULL) {
		caam_sm2_err(CAAM_SM2_F_VERIFY_SIG, ERR_R_BN_LIB);
		goto done;
	}

	if (NULL == (pkey = EVP_PKEY_CTX_get0_pkey(ctx)))
	{
		caam_sm2_err(CAAM_SM2_F_VERIFY_SIG, CAAM_SM2_R_NULL_REFERENCE);
		goto done;
	}

	if (NULL == (eckey = EVP_PKEY_get0(pkey)))
	{
		caam_sm2_err(CAAM_SM2_F_VERIFY_SIG, CAAM_SM2_R_NULL_REFERENCE);
		goto done;
	}
	
	ret = sm2_sig_verify(eckey, s, e);

done:
	OPENSSL_free(der);
	BN_free(e);
	ECDSA_SIG_free(s);
	return ret;
}

static int
caam_sm2_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid)
{

	static int caam_sm2_pkey_nids[] = {NID_sm2};
	if (!e){
		return 0;
	}	
	if (!pmeth)
	{		
		*nids = caam_sm2_pkey_nids;
		return 1;
	}

	if (nid == NID_sm2)
	{
		*pmeth = sm2_pmeth;
		return 1;
	}

	caam_sm2_err(CAAM_SM2_F_VERIFY_SIG, CAAM_SM2_R_UNSUPPORTED_ALGORITHM);
	*pmeth = NULL;
	return 0;
}


static int bind_caam_sm2(ENGINE *e) {

	int ret = 0;				

	ERR_load_caam_sm2_strings();

	if (!register_pkey_methods(&sm2_pmeth, NID_sm2)) {
		dbg_fprintf("Could not set up engine");
		return 0;
	}
	
	if (!ENGINE_set_id(e, engine_caam_sm2_id)
			|| !ENGINE_set_name(e, engine_caam_sm2_name)
			|| !ENGINE_set_init_function(e, caam_sm2_init)
			|| !ENGINE_set_pkey_meths(e, caam_sm2_pkey_meths)
			|| !ENGINE_set_destroy_function(e, caam_sm2_destroy)
			|| !ENGINE_set_finish_function(e, caam_sm2_finish)

			) {
		dbg_fprintf("Bind caam_sm2 failed\n");
		goto end;
	}

	dbg_fprintf("%s: Bind SM2 complete\n", __FUNCTION__);
	ret = 1;
end: return ret;
}

ENGINE *engine_caam_sm2(void) {
	ENGINE *ret = ENGINE_new();
	if (!ret)
	return NULL;
	if (!bind_caam_sm2(ret)) {
		ENGINE_free(ret);
		return NULL;
	}
	return ret;
}

EVP_PKEY *gen_pkey()
{
	EVP_PKEY *pkey = NULL;
	EVP_PKEY *params = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	EVP_PKEY_CTX *kctx = NULL;
	if (!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) ||
			( EVP_PKEY_paramgen_init(pctx) != 1) ||
			(!(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_sm2))) ||
			(!(EVP_PKEY_paramgen(pctx, &params))) ||
			(!(kctx = EVP_PKEY_CTX_new(params, NULL))) ||
			(!(EVP_PKEY_keygen_init(kctx))) ||
			(!(EVP_PKEY_keygen(kctx, &pkey))) ||
			(!(EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2)))
			)
	return NULL;
	return pkey;
	EVP_PKEY_CTX_free(pctx);
	EVP_PKEY_CTX_free(kctx);
	EVP_PKEY_free(params);						
}

int sm2_sign(EVP_PKEY *pkey, const uint8_t *msg, size_t msg_len,
const uint8_t* sm2_id, size_t sm2_id_len,
uint8_t **sig, size_t *sig_len
)
{
	EVP_MD_CTX *md_ctx_sign = NULL;
	EVP_PKEY_CTX *sctx = NULL;
	size_t _sig_len;
	uint8_t *_sig = NULL;
	int ret = 0;
	
	if (!pkey || (!(md_ctx_sign = EVP_MD_CTX_new())) || (!(sctx = EVP_PKEY_CTX_new(pkey, NULL))))
	{
		fprintf(stderr, "Init error\n");
		goto done;
	}

	if (!(EVP_DigestSignInit(md_ctx_sign, NULL, EVP_sm3(), NULL, pkey)))
	goto done;

	if(!(EVP_DigestSignUpdate(md_ctx_sign, msg, msg_len)))
	goto done;

	if (!(EVP_DigestSignFinal(md_ctx_sign, NULL, &_sig_len)))
	goto done;

	if (_sig_len != (size_t)EVP_PKEY_size(pkey))
	goto done;

	if (!(_sig = OPENSSL_malloc(_sig_len)))
	goto done;

	if (!(EVP_DigestSignFinal(md_ctx_sign, _sig, &_sig_len)))
	goto done;

	*sig_len = _sig_len;
	*sig = _sig;
	ret = 1;
done:	
	EVP_PKEY_CTX_free(sctx);
	EVP_MD_CTX_free(md_ctx_sign);
	return ret;
}

static int sm2_verify_sw(EVP_PKEY *pkey, const uint8_t *msg, size_t msg_len,
const uint8_t* sm2_id, size_t sm2_id_len,
const uint8_t *sig, size_t sig_len)
{

	EVP_MD_CTX *md_ctx_verify = NULL;
	EVP_PKEY_CTX *sctx = NULL;
	int ret = 0;
	if ( 	!pkey  ||
			(!(md_ctx_verify = EVP_MD_CTX_new())) ||
			(!(sctx = EVP_PKEY_CTX_new(pkey, NULL)))
			)
	{
		fprintf(stderr, "Init error\n");
		goto done;
	}

	printf("Software-based SM2 signature verification\n");
	if (!(EVP_DigestVerifyInit(md_ctx_verify, NULL, EVP_sm3(), NULL, pkey)))
	goto done;	
	
	if (!(EVP_DigestVerifyUpdate(md_ctx_verify, msg, msg_len)))
	goto done;
	ret = EVP_DigestVerifyFinal(md_ctx_verify, sig, sig_len);
	
done:	
	EVP_PKEY_CTX_free(sctx);
	EVP_MD_CTX_free(md_ctx_verify);
	return ret;	
}

static int sm2_verify_hw(EVP_PKEY *pkey, const uint8_t *msg, size_t msg_len,
const uint8_t* sm2_id, size_t sm2_id_len,
const uint8_t *sig, size_t sig_len)
{
	ENGINE *eng = NULL;
	EVP_MD_CTX *md_ctx_verify = NULL;
	EVP_PKEY_CTX *sctx = NULL;
	int ret = 0;

	ERR_load_crypto_strings();
	
	eng = engine_caam_sm2();
	if(!eng){
		fprintf(stderr, "Error init CAAM SM2 Engine: %s\n", ERR_reason_error_string (ERR_get_error ()));
		goto done;
	}
	
	if(ENGINE_init (eng) < 0)
	{
		fprintf(stderr, "Error init CAAM SM2 Engine: %s\n", ERR_reason_error_string (ERR_get_error ()));
		goto done;
	}
	
	if(!ENGINE_register_pkey_meths(eng)){
		fprintf(stderr, "Error: %s\n", ERR_reason_error_string(ERR_get_error()));
		goto done;
	}

	if (!pkey || !EVP_PKEY_set1_engine(pkey,eng)||
			(!(md_ctx_verify = EVP_MD_CTX_new())) ||
			(!(sctx = EVP_PKEY_CTX_new(pkey, NULL)))){
		fprintf(stderr, "Init error\n");
		goto done;
	}
	printf("Hardware-based SM2 signature verification\n");
	if (!(EVP_DigestVerifyInit(md_ctx_verify, NULL, EVP_sm3(), NULL, pkey)))
	goto done;	
	
	if (!(EVP_DigestVerifyUpdate(md_ctx_verify, msg,msg_len)))
	goto done;
	ret = EVP_DigestVerifyFinal(md_ctx_verify, sig, sig_len);
	
done:	
	EVP_PKEY_CTX_free(sctx);
	EVP_MD_CTX_free(md_ctx_verify);
	if(eng)
	ENGINE_free (eng);
	return ret;	
}


int main()
{
	static const uint8_t message[] = { 'c', 'a', 'a', 'm' };
	uint8_t sm2_id[] = {1, 2, 3, 4, 'l', 'e', 't', 't', 'e', 'r'};
	EVP_PKEY *pkey = NULL;
	size_t sig_len = 0;
	uint8_t *sig = NULL;
	/* verification method SW||HW*/
	char *meth = NULL;
	uint32_t i;
	int ret = 0;
	
	int (*verif_ptr)(EVP_PKEY *, const uint8_t *, size_t,  const uint8_t*, size_t, const uint8_t *, size_t );

	if(!( pkey = gen_pkey()))
		goto done;
	
	if( !sm2_sign(pkey, message, sizeof(message), sm2_id, sizeof(sm2_id), &sig, &sig_len))
		goto done;

	for(i = 0; i < 2; i++)
	{
		verif_ptr = (i == 0) ? sm2_verify_sw: sm2_verify_hw;
		meth = (i == 0) ? "SW": "HW";
		ret = (*verif_ptr)(pkey, message, sizeof(message),  sm2_id, sizeof(sm2_id), sig, sig_len);
		if (ret == 1)
		printf("[%s] Signature verification success\n", meth);
		else if(ret == 0)
		printf("[%s]Signature verification failure\n", meth);
		else
		printf("[%s] Signature verification error\n", meth);
		
	}

done:
	EVP_PKEY_free(pkey);
	OPENSSL_free(sig);
	return ret;
}