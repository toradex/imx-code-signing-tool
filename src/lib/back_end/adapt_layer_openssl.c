// SPDX-License-Identifier: BSD-3-Clause
/*
 * (c) Freescale Semiconductor, Inc. 2011-2015. All rights reserved.
 * Copyright 2018-2020, 2022-2024 NXP
 */

/*===========================================================================*/
/**
    @file    adapt_layer_openssl.c

    @brief   Implements Code Signing Tool's Adaptation Layer API for the
             Freescale reference Code Signing Tool.  This file may be
             replaced in implementations using a Hardware Security Module
             or a client/server based infrastructure.
 */

/*===========================================================================
                                INCLUDE FILES
=============================================================================*/
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <strings.h>
#include "ssl_wrapper.h"
#include <string.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include "adapt_layer.h"
#include "ssl_backend.h"
#include "openssl_helper.h"
#include "pkey.h"
#include "csf.h"

#if (defined _WIN32 || defined __CYGWIN__) && defined USE_APPLINK
#include <openssl/applink.c>
#endif
/*===========================================================================
                                 LOCAL MACROS
=============================================================================*/
#define MAX_CMS_DATA                4096   /**< Max bytes in CMS_ContentInfo */
#define MAX_LINE_CHARS              1024   /**< Max. chars in output line    */

/*===========================================================================
                  LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
=============================================================================*/

/*===========================================================================
                          LOCAL FUNCTION PROTOTYPES
=============================================================================*/

/** Generate RSA signature Data
 *
 * Generates an RSA signature for the given data file, signer
 * certificate, hash algorithm, and signature type (PSS or PKCS#1 v1.5).
 * The signature data is returned in a buffer provided by caller.
 *
 * @param[in] in_file string containing path to file with data to sign
 *
 * @param[in] key pointer to signing key
 *
 * @param[in] hash_alg hash algorithm from #hash_alg_t
 *
 * @param[out] sig_buf signature data buffer
 *
 * @param[in,out] sig_buf_bytes On input, contains size of @a sig_buf in bytes,
 *                              On output, contains size of signature in bytes.
 *
 * @param[in] sig_type signature type from #rsa_sig_t
 *
 * @pre @a in_file, @a key, @a sig_buf and @a sig_buf_bytes
 *         must not be NULL.
 *
 * @post On success @a sig_buf is updated to hold the resulting signature and
 *       @a sig_buf_bytes is updates to hold the length of the signature in
 *       bytes
 *
 * @retval #CAL_SUCCESS API completed its task successfully
 *
 * @retval #CAL_CRYPTO_API_ERROR An Openssl related error has occured
 */
static int32_t gen_sig_data_rsa(const char *in_file, EVP_PKEY *key,
				hash_alg_t hash_alg, uint8_t *sig_buf,
				size_t *sig_buf_bytes, rsa_sig_t sig_type);

/** Generate CMS Signature Data
 *
 * Generates a CMS signature for the given data file, signer certificate, and
 * hash algorithm. The signature data is returned in a buffer provided by
 * caller.  Note that sign_data cannot be used here since that function
 * requires an input buffer as an argument.  For large files it becomes
 * unreasonable to allocate a contigous block of memory.
 *
 * @param[in] in_file string containing path to file with data to sign
 *
 * @param[in] cert pointer to signer certificate
 *
 * @param[in] key pointer to signer key
 *
 * @param[in] hash_alg hash algorithm from #hash_alg_t
 *
 * @param[out] sig_buf signature data buffer
 *
 * @param[in,out] sig_buf_bytes On input, contains size of @a sig_buf in bytes,
 *                              On output, contains size of signature in bytes.
 *
 * @pre @a in_file, @a cert, @a key, @a sig_buf and @a sig_buf_bytes
 *         must not be NULL.
 *
 * @post On success @a sig_buf is updated to hold the resulting signature and
 *       @a sig_buf_bytes is updates to hold the length of the signature in
 *       bytes
 *
 * @retval #CAL_SUCCESS API completed its task successfully, error code
 * otherwise.
 */
static int32_t gen_sig_data_cms(const char *in_file, X509 *cert,
				EVP_PKEY *key, hash_alg_t hash_alg,
				uint8_t *sig_buf, size_t *sig_buf_bytes);

/** Generate Dilithium signature Data
 *
 * Generates a Dilithium signature for the given data file, private
 * key, and, hash algorithm. The signature data is returned in a buffer
 * provided by caller.
 *
 * @param[in] in_file string containing path to file with data to sign
 *
 * @param[in] key pointer to signing key
 *
 * @param[in] hash_alg hash algorithm from #hash_alg_t
 *
 * @param[out] sig_buf signature data buffer
 *
 * @param[in,out] sig_buf_bytes On input, contains size of @a sig_buf in bytes,
 *                              On output, contains size of signature in bytes.
 *
 * @pre @a in_file, @a key, @a sig_buf and @a sig_buf_bytes
 *         must not be NULL.
 *
 * @post On success @a sig_buf is updated to hold the resulting signature and
 *       @a sig_buf_bytes is updates to hold the length of the signature in
 *       bytes
 *
 * @retval #CAL_SUCCESS API completed its task successfully
 *
 * @retval #CAL_CRYPTO_API_ERROR An Openssl related error has occured
 */
static int32_t gen_sig_data_dilithium(const char *in_file, EVP_PKEY *key,
                                      hash_alg_t hash_alg, uint8_t *sig_buf,
                                      size_t *sig_buf_bytes);

/** Generate ML-DSA algorithm signature Data
 *
 * Generates a ML-DSA signature for the given data file, private
 * key, and, hash algorithm. The signature data is returned in a buffer
 * provided by caller.
 *
 * @param[in] in_file string containing path to file with data to sign
 *
 * @param[in] key pointer to signing key
 *
 * @param[in] hash_alg hash algorithm from #hash_alg_t
 *
 * @param[out] sig_buf signature data buffer
 *
 * @param[in,out] sig_buf_bytes On input, contains size of @a sig_buf in bytes,
 *                              On output, contains size of signature in bytes.
 *
 * @pre @a in_file, @a key, @a sig_buf and @a sig_buf_bytes
 *         must not be NULL.
 *
 * @post On success @a sig_buf is updated to hold the resulting signature and
 *       @a sig_buf_bytes is updates to hold the length of the signature in
 *       bytes
 *
 * @retval #CAL_SUCCESS API completed its task successfully
 *
 * @retval #CAL_CRYPTO_API_ERROR An Openssl related error has occured
 */
static int32_t gen_sig_data_mldsa(const char *in_file, EVP_PKEY *key,
                                  hash_alg_t hash_alg, uint8_t *sig_buf,
                                  size_t *sig_buf_bytes);

/** Generate hybrid signature data
 *
 * Generates a hybrid signature for the given data file, private
 * key, and, hash algorithm.
 * The signature data is returned in a buffers provided by caller.
 *
 * @param[in] in_file string containing path to file with data to sign
 *
 * @param[in] key pointer to signing key
 *
 * @param[in] hash_alg hash algorithm from #hash_alg_t
 *
 * @param[out] sig_buf0 signature data buffer for classical part
 *
 * @param[in,out] sig0_buf_bytes On input, contains size of @a sig0_buf in
 * bytes, On output, contains size of signature in bytes.
 *
 * @param[out] sig_buf1 signature data buffer for pqc part
 *
 * @param[in,out] sig1_buf_bytes On input, contains size of @a sig0_buf in
 * bytes, On output, contains size of signature in bytes.
 *
 * @pre @a in_file, @a key, @a sig0_buf, @a sig0_buf_bytes, @a sig1_buf and @a
 * sig1_buf_bytes must not be NULL.
 *
 * @post On success @a sig0_buf and @a sig1_buf are updated to hold the
 * resulting signature and
 *       @a sig0_buf_bytes and @a sig1_buf_bytes are updated to hold the length
 * of the signature in bytes of respectively classical and pqc parts.
 *
 * @retval #CAL_SUCCESS API completed its task successfully
 *
 * @retval #CAL_CRYPTO_API_ERROR An Openssl related error has occured
 */
static int32_t gen_sig_data_hybrid(const char *in_file, EVP_PKEY *key,
                                   hash_alg_t hash_alg, uint8_t *sig0_buf,
                                   size_t *sig0_buf_bytes, uint8_t *sig1_buf,
                                   size_t *sig1_buf_bytes);

/** Copies CMS Content Info with encrypted or signature data to buffer
 *
 * @param[in] cms CMS Content Info
 *
 * @param[in] bio_in input bio
 *
 * @param[out] data_buffer address to data buffer
 *
 * @param[in] data_buffer_size max size, [out] return size
 *
 * @param[in] flags CMS Flags
 *
 * @returns CAL_SUCCESS upon success
 *
 * @returns CAL_CRYPTO_API_ERROR when openssl BIO API fail
 */
int32_t cms_to_buf(CMS_ContentInfo *cms, BIO * bio_in, uint8_t * data_buffer,
                            size_t * data_buffer_size, int32_t flags);

/** generate_dek_key
 *
 * Uses openssl API to generate a random 128 bit AES key
 *
 * @param[out] key buffer to store the key data
 *
 * @param[in] len length of the key to generate
 *
 * @post if successful the random bytes are placed into output buffer
 *
 * @pre  #openssl_initialize has been called previously
 *
 * @returns if successful function returns location CAL_SUCCESS.
 */
int32_t generate_dek_key(uint8_t * key, int32_t len);

/**  write_plaintext_dek_key
 *
 * Writes the provide DEK to the give path. It will be encrypted
 * under the certificate file if provided.
 *
 * @param[in] key input key data
 *
 * @param[in] key_bytes length of the input key
 *
 * @param[in] cert_file  certificate to encrypt the DEK
 *
 * @param[in] enc_file  destination file
 *
 * @post if successful the dek is written to the file
 *
 * @returns if successful function returns location CAL_SUCCESS.
 */
int32_t write_plaintext_dek_key(uint8_t * key, size_t key_bytes,
                        const char * cert_file, const char * enc_file);

/** encrypt_dek_key
 *
 * Uses openssl API to encrypt the key. Saves the encrypted structure to a file
 *
 * @param[in] key input key data
 *
 * @param[in] key_bytes length of the input key
 *
 * @param[in] cert filename of the RSA certificate, dek will be encrypted with
 *
 * @param[in] file encrypted data saved in the file
 *
 * @post if successful the file is created with the encrypted data
 *
 * @pre  #openssl_initialize has been called previously
 *
 * @returns if successful function returns location CAL_SUCCESS.
 */
int32_t encrypt_dek_key(uint8_t * key, size_t key_bytes,
                const char * cert_file, const char * enc_file);

/** Display error message
 *
 * Displays error message to STDERR
 *
 * @param[in] err Error string to display
 *
 * @pre  @a err is not NULL
 *
 * @post None
 */
static void
display_error(const char *err);

/*===========================================================================
                               GLOBAL VARIABLES
=============================================================================*/

/*===========================================================================
                               LOCAL FUNCTIONS
=============================================================================*/

/*--------------------------
  gen_sig_data_rsa
---------------------------*/
int32_t gen_sig_data_rsa(const char *in_file, EVP_PKEY *key,
			 hash_alg_t hash_alg, uint8_t *sig_buf,
			 size_t *sig_buf_bytes, rsa_sig_t sig_type)
{
	const EVP_MD *md = NULL;
	uint8_t *hash_msg = NULL;
	int32_t hash_msg_size = 0;
	uint8_t *enc_sig = NULL;
	size_t enc_sig_size = 0;
	char err_str[MAX_ERR_STR_BYTES] = { 0 };
	EVP_PKEY_CTX *ctx = NULL;
	int32_t ret = CAL_CRYPTO_API_ERROR;

	/* Get the digest method based on the provided hash algorithm */
	md = EVP_get_digestbyname(get_digest_name(hash_alg));

	if (!md)
		return CAL_INVALID_ARGUMENT;

	hash_msg_size = HASH_BYTES_MAX;
	hash_msg = OPENSSL_malloc(HASH_BYTES_MAX);
	if (hash_msg == NULL)
		return CAL_INSUFFICIENT_MEMORY;

	/* Generate hash data of data from in_file */
	if (calculate_hash(in_file, hash_alg, hash_msg,
			   &hash_msg_size) != CAL_SUCCESS) {
		ret = CAL_CRYPTO_API_ERROR;
		goto out;
	}

	/* Create signing context. */
	ctx = EVP_PKEY_CTX_new(key, NULL);
	if (ctx == NULL) {
		ret = CAL_INSUFFICIENT_MEMORY;
		goto out;
	}

	/* Initialize context for signing and set options. */
	if (EVP_PKEY_sign_init(ctx) <= 0) {
		ret = CAL_CRYPTO_API_ERROR;
		goto out;
	}

	/* Set padding based on signature type */
	switch(sig_type) {
	case RSA_SIG_PKCS1:
		if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
			EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0) {
			ret = CAL_CRYPTO_API_ERROR;
			goto out;
		}
		break;
	case RSA_SIG_PSS:
		if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
			EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0) {
			ret = CAL_CRYPTO_API_ERROR;
			goto out;
		}
		break;
	default:
		ret = CAL_INVALID_ARGUMENT;
		goto out;
	}

	/* Determine the buffer size needed for the signature */
	if (EVP_PKEY_sign(ctx, NULL, &enc_sig_size,
			  hash_msg, hash_msg_size) <= 0) {
		snprintf(err_str, MAX_ERR_STR_BYTES-1,
			 "Cannot determine signature length");
		display_error(err_str);
		ret = CAL_CRYPTO_API_ERROR;
		goto out;
	}

	/* Allocate memory for signature. */
	enc_sig = OPENSSL_malloc(enc_sig_size);
	if (enc_sig == NULL) {
		ret = CAL_INSUFFICIENT_MEMORY;
		goto out;
	}

	/* Generate the signature */
	if (EVP_PKEY_sign(ctx, enc_sig, &enc_sig_size,
			  hash_msg, hash_msg_size) <= 0) {
		snprintf(err_str, MAX_ERR_STR_BYTES-1,
			 "Cannot create signature");
		display_error(err_str);
		ret = CAL_CRYPTO_API_ERROR;
		goto out;
	}

	/* Check if the signature fits into the provided buffer */
	if (enc_sig_size > *sig_buf_bytes) {
		snprintf(err_str, MAX_ERR_STR_BYTES-1,
		"Generated signature too large for allocated buffer");
		display_error(err_str);
		ret = CAL_INVALID_SIG_DATA_SIZE;
		goto out;
	}

	/* Copy the signature into the provided buffer */
	*sig_buf_bytes = enc_sig_size;
	memcpy(sig_buf, enc_sig, enc_sig_size);

	ret = CAL_SUCCESS;

out:
	if (ctx)
		EVP_PKEY_CTX_free(ctx);
	if (hash_msg)
		OPENSSL_free(hash_msg);
	if (enc_sig)
		OPENSSL_free(enc_sig);

	return ret;
}

/*--------------------------
  cms_to_buf
---------------------------*/
int32_t cms_to_buf(CMS_ContentInfo *cms, BIO * bio_in, uint8_t * data_buffer,
                            size_t * data_buffer_size, int32_t flags)
{
    int32_t err_value = CAL_SUCCESS;
    BIO * bio_out = NULL;
    BUF_MEM buffer_memory;            /**< Used with BIO functions */

    buffer_memory.length = 0;
    buffer_memory.data = (char*)data_buffer;
    buffer_memory.max = *data_buffer_size;

    do {
        if (!(bio_out = BIO_new(BIO_s_mem()))) {
            display_error("Unable to allocate CMS signature result memory");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        BIO_set_mem_buf(bio_out, &buffer_memory, BIO_NOCLOSE);

        /* Convert cms to der format */
        if (!i2d_CMS_bio_stream(bio_out, cms, bio_in, flags)) {
            display_error("Unable to convert CMS signature to DER format");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Get the size of bio out in data_buffer_size */
        *data_buffer_size = BIO_ctrl_pending(bio_out);
    }while(0);

    if (bio_out)
        BIO_free(bio_out);
    return err_value;
}

/*--------------------------
  gen_sig_data_cms
---------------------------*/
int32_t gen_sig_data_cms(const char *in_file, X509 *cert,
			 EVP_PKEY *key, hash_alg_t hash_alg,
			 uint8_t *sig_buf, size_t *sig_buf_bytes)
{
    BIO             *bio_in = NULL;   /**< BIO for in_file data */
    CMS_ContentInfo *cms = NULL;      /**< Ptr used with openssl API */
    const EVP_MD    *sign_md = NULL;  /**< Ptr to digest name */
    int32_t err_value = CAL_SUCCESS;  /**< Used for return value */
    /** Array to hold error string */
    char err_str[MAX_ERR_STR_BYTES];
    /* flags set to match Openssl command line options for generating
     *  signatures
     */
    int32_t         flags = CMS_DETACHED | CMS_NOCERTS |
                            CMS_NOSMIMECAP | CMS_BINARY;

    /* Set signature message digest alg */
    sign_md = EVP_get_digestbyname(get_digest_name(hash_alg));
    if (sign_md == NULL) {
        display_error("Invalid hash digest algorithm");
        return CAL_INVALID_ARGUMENT;
    }

    do
    {
        /* Read Data to be signed */
        if (!(bio_in = BIO_new_file(in_file, "rb"))) {
            snprintf(err_str, MAX_ERR_STR_BYTES-1,
                     "Cannot open data file %s", in_file);
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Generate CMS Signature - can only use CMS_sign if default
         * MD is used which is SHA1 */
        flags |= CMS_PARTIAL;

        cms = CMS_sign(NULL, NULL, NULL, bio_in, flags);
        if (!cms) {
            display_error("Failed to initialize CMS signature");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        if (!CMS_add1_signer(cms, (X509 *)cert, key,
			     sign_md, flags)) {
            display_error("Failed to generate CMS signature");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Finalize the signature */
        if (!CMS_final(cms, bio_in, NULL, flags)) {
            display_error("Failed to finalize CMS signature");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Write CMS signature to output buffer - DER format */
        err_value = cms_to_buf(cms, bio_in, sig_buf, sig_buf_bytes, flags);
    } while(0);

    /* Print any Openssl errors */
    if (err_value != CAL_SUCCESS) {
        ERR_print_errors_fp(stderr);
    }

    /* Close everything down */
    if (cms)      CMS_ContentInfo_free(cms);
    if (bio_in)   BIO_free(bio_in);

    return err_value;
}

/*--------------------------
  gen_sig_data_ecdsa
---------------------------*/
int32_t gen_sig_data_ecdsa(const char *in_file, EVP_PKEY *key,
			   hash_alg_t hash_alg, uint8_t *sig_buf,
			   size_t *sig_buf_bytes)
{
    BIO          *bio_in    = NULL;          /**< BIO for in_file data    */
    size_t       key_size   = 0;             /**< n of bytes of key param */
    const EVP_MD *sign_md   = NULL;          /**< Digest name             */
    uint8_t      *hash      = NULL;          /**< Hash data of in_file    */
    int32_t      hash_bytes = 0;             /**< Length of hash buffer   */
    uint8_t      *sign      = NULL;          /**< Signature data in DER   */
    uint8_t      *r = NULL, *s = NULL;       /**< Raw signature data R&S  */
    size_t       bn_bytes = 0;               /**< Length of R,S big num   */
    ECDSA_SIG    *sign_dec  = NULL;          /**< Raw signature data R|S  */
    int32_t      err_value  = CAL_SUCCESS;   /**< Return value            */
    char         err_str[MAX_ERR_STR_BYTES]; /**< Error string            */
    const BIGNUM *sig_r, *sig_s;             /**< signature numbers defined as OpenSSL BIGNUM */
    size_t     sign_bytes = 0;             /**< Length of DER signature */
    EVP_PKEY_CTX *ecdsa_sign_ctx = NULL;

    /* Set signature message digest alg */
    sign_md = EVP_get_digestbyname(get_digest_name(hash_alg));
    if (sign_md == NULL) {
        display_error("Invalid hash digest algorithm");
        return CAL_INVALID_ARGUMENT;
    }

    do
    {
        /* Read Data to be signed */
        if (!(bio_in = BIO_new_file(in_file, "rb"))) {
            snprintf(err_str, MAX_ERR_STR_BYTES,
                     "Cannot open data file %s", in_file);
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Generate hash of data from in_file */
        hash_bytes = HASH_BYTES_MAX;
        hash = OPENSSL_malloc(HASH_BYTES_MAX);

        err_value = calculate_hash(in_file, hash_alg, hash, &hash_bytes);
        if (err_value != CAL_SUCCESS) {
            break;
        }

        /* Create signing context. */
        ecdsa_sign_ctx = EVP_PKEY_CTX_new(key, NULL);
        if (ecdsa_sign_ctx == NULL
        || EVP_PKEY_sign_init(ecdsa_sign_ctx)<= 0) {
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Determine buffer length */
        if (EVP_PKEY_sign(ecdsa_sign_ctx, NULL, &sign_bytes, hash,
                          hash_bytes) <= 0)
        {
            display_error("Failed to determine buffer length");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Allocate memory for signature. */
        sign = OPENSSL_malloc(sign_bytes);
        if (sign == NULL) {
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        if(EVP_PKEY_sign(ecdsa_sign_ctx, sign, &sign_bytes, hash, hash_bytes)<= 0){
            display_error("Failed to generate ECDSA signature");
            err_value = CAL_CRYPTO_API_ERROR;
            break ;
        }

        sign_dec = d2i_ECDSA_SIG(NULL, (const uint8_t **) &sign, sign_bytes);
        if (NULL == sign_dec) {
            display_error("Failed to decode ECDSA signature");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Copy R|S to sig_buf */
        memset(sig_buf, 0, *sig_buf_bytes);

        key_size = EVP_PKEY_bits(key) >> 3;
        if (EVP_PKEY_bits(key) & 0x7) key_size += 1; /* Valid for P-521 */

        if ((key_size * 2) > *sig_buf_bytes){
            display_error("Signature buffer too small");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }
        *sig_buf_bytes = key_size * 2;

        ECDSA_SIG_get0(sign_dec, &sig_r, &sig_s);

        r = get_bn(sig_r, &bn_bytes);
        if (!r)
        {
            display_error("Error extracting data from r");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }
        memcpy(sig_buf + (key_size - bn_bytes),
               r,
               bn_bytes);
        free(r);

        s = get_bn(sig_s, &bn_bytes);
        if (!s)
        {
            display_error("Error extracting data from s");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }
        memcpy(sig_buf + key_size + (key_size - bn_bytes),
               s,
               bn_bytes);
        free(s);
    } while(0);

    /* Print any Openssl errors */
    if (err_value != CAL_SUCCESS) {
        ERR_print_errors_fp(stderr);
    }

    /* Close everything down */
    if (ecdsa_sign_ctx) EVP_PKEY_CTX_free(ecdsa_sign_ctx);
    if (bio_in) BIO_free(bio_in);

    return err_value;
}
#if CST_WITH_PQC

/*--------------------------
  gen_sig_data_dilithium
---------------------------*/
int32_t gen_sig_data_dilithium(const char *in_file, EVP_PKEY *key,
                               hash_alg_t hash_alg, uint8_t *sig_buf,
                               size_t *sig_buf_bytes)
{
    BIO *bio_in = NULL;              /**< BIO for in_file data    */
    size_t key_size = 0;             /**< n of bytes of key param */
    const EVP_MD *sign_md = NULL;    /**< Digest name             */
    uint8_t *hash = NULL;            /**< Hash data of in_file    */
    int32_t hash_bytes = 0;          /**< Length of hash buffer   */
    uint8_t *sign = NULL;            /**< Signature data in DER   */
    int32_t err_value = CAL_SUCCESS; /**< Return value            */
    char err_str[MAX_ERR_STR_BYTES]; /**< Error string            */
    size_t sign_bytes = 0;           /**< Length of DER signature */
    EVP_PKEY_CTX *sign_ctx = NULL;   /**< PQC algorithm key context */

    /* Set signature message digest alg */
    sign_md = EVP_get_digestbyname(get_digest_name(hash_alg));
    if (sign_md == NULL)
    {
        display_error("Invalid hash digest algorithm");
        return CAL_INVALID_ARGUMENT;
    }

    do
    {
        /* Read Data to be signed */
        if (!(bio_in = BIO_new_file(in_file, "rb")))
        {
            snprintf(err_str, MAX_ERR_STR_BYTES, "Cannot open data file %s",
                     in_file);
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Generate hash of data from in_file */
        hash_bytes = HASH_BYTES_MAX;
        hash = OPENSSL_malloc(HASH_BYTES_MAX);

        err_value = calculate_hash(in_file, hash_alg, hash, &hash_bytes);
        if (err_value != CAL_SUCCESS)
        {
            break;
        }

        /* Create signing context. */
        sign_ctx = EVP_PKEY_CTX_new(key, NULL);
        if (sign_ctx == NULL || EVP_PKEY_sign_init(sign_ctx) <= 0)
        {
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Determine buffer length */
        if (EVP_PKEY_sign(sign_ctx, NULL, &sign_bytes, hash, hash_bytes) <= 0)
            ;

        if (sign_bytes > *sig_buf_bytes)
        {
            display_error("Signature buffer too small");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Allocate memory for signature. */
        sign = OPENSSL_malloc(sign_bytes);
        if (sign == NULL)
        {
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        if (EVP_PKEY_sign(sign_ctx, sign, &sign_bytes, hash, hash_bytes) <= 0)
        {
            display_error("Failed to generate quantum-safe signature");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Copy signature to sig_buf */
        memcpy(sig_buf, sign, sign_bytes);
        *sig_buf_bytes = sign_bytes;

    } while (0);

    /* Print any Openssl errors */
    if (err_value != CAL_SUCCESS)
    {
        ERR_print_errors_fp(stderr);
    }

    /* Close everything down */
    if (sign_ctx)
        EVP_PKEY_CTX_free(sign_ctx);
    if (bio_in)
        BIO_free(bio_in);

    return err_value;
}

/*--------------------------
  gen_sig_data_mldsa
---------------------------*/
int32_t gen_sig_data_mldsa(const char *in_file, EVP_PKEY *key,
                           hash_alg_t hash_alg, uint8_t *sig_buf,
                           size_t *sig_buf_bytes)
{
    BIO *bio_in = NULL;              /**< BIO for in_file data    */
    size_t key_size = 0;             /**< n of bytes of key param */
    const EVP_MD *sign_md = NULL;    /**< Digest name             */
    uint8_t *hash = NULL;            /**< Hash data of in_file    */
    int32_t hash_bytes = 0;          /**< Length of hash buffer   */
    uint8_t *sign = NULL;            /**< Signature data in DER   */
    int32_t err_value = CAL_SUCCESS; /**< Return value            */
    char err_str[MAX_ERR_STR_BYTES]; /**< Error string            */
    size_t sign_bytes = 0;           /**< Length of DER signature */
    EVP_PKEY_CTX *sign_ctx = NULL;   /**< PQC algorithm key context */

    /* Set signature message digest alg */
    sign_md = EVP_get_digestbyname(get_digest_name(hash_alg));
    if (sign_md == NULL)
    {
        display_error("Invalid hash digest algorithm");
        return CAL_INVALID_ARGUMENT;
    }

    do
    {
        /* Read Data to be signed */
        if (!(bio_in = BIO_new_file(in_file, "rb")))
        {
            snprintf(err_str, MAX_ERR_STR_BYTES, "Cannot open data file %s",
                     in_file);
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Generate hash of data from in_file */
        hash_bytes = HASH_BYTES_MAX;
        hash = OPENSSL_malloc(HASH_BYTES_MAX);

        err_value = calculate_hash(in_file, hash_alg, hash, &hash_bytes);
        if (err_value != CAL_SUCCESS)
        {
            break;
        }

        /* Create signing context. */
        sign_ctx = EVP_PKEY_CTX_new(key, NULL);
        if (sign_ctx == NULL || EVP_PKEY_sign_init(sign_ctx) <= 0)
        {
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Determine buffer length */
        if (EVP_PKEY_sign(sign_ctx, NULL, &sign_bytes, hash, hash_bytes) <= 0)
            ;

        if (sign_bytes > *sig_buf_bytes)
        {
            display_error("Signature buffer too small");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Allocate memory for signature. */
        sign = OPENSSL_malloc(sign_bytes);
        if (sign == NULL)
        {
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        if (EVP_PKEY_sign(sign_ctx, sign, &sign_bytes, hash, hash_bytes) <= 0)
        {
            display_error("Failed to generate quantum-safe signature");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Copy signature to sig_buf */
        memcpy(sig_buf, sign, sign_bytes);
        *sig_buf_bytes = sign_bytes;

    } while (0);

    /* Print any Openssl errors */
    if (err_value != CAL_SUCCESS)
    {
        ERR_print_errors_fp(stderr);
    }

    /* Close everything down */
    if (sign_ctx)
        EVP_PKEY_CTX_free(sign_ctx);
    if (bio_in)
        BIO_free(bio_in);

    return err_value;
}

/*--------------------------
  gen_sig_data_hybrid
---------------------------*/
int32_t gen_sig_data_hybrid(const char *in_file, EVP_PKEY *key,
                            hash_alg_t hash_alg, uint8_t *sig0_buf,
                            size_t *sig0_buf_bytes, uint8_t *sig1_buf,
                            size_t *sig1_buf_bytes)
{
    int32_t err_value = CAL_SUCCESS; /**< Return value            */
    EVP_PKEY *classical_key =
        NULL; /**< EVP public key of the classical part of an hybrid key */
    EVP_PKEY *pqc_key = NULL; /**< EVP public key of the quantum-resistant
                                      part of an hybrid key */

    if (!in_file || !key || !sig0_buf || !sig0_buf_bytes || !sig1_buf ||
        !sig1_buf_bytes)
    {
        display_error("Invalid arguments");
        return CAL_INVALID_ARGUMENT;
    }

    if (partition_hybrid_key(get_libctx(), key, &classical_key, &pqc_key) != 1)
    {
        display_error("Can't extract classical and quantum-resistant keys from "
                      "the given hybrid key");
    }

    /* Sign with classical algorithm */
    switch (EVP_PKEY_id(classical_key))
    {
        case EVP_PKEY_RSA:
            err_value =
                gen_sig_data_rsa(in_file, classical_key, hash_alg, sig0_buf,
                                 sig0_buf_bytes, RSA_SIG_PKCS1);
            break;
        case EVP_PKEY_RSA_PSS:
            err_value = gen_sig_data_rsa(in_file, classical_key, hash_alg,
                                         sig0_buf, sig0_buf_bytes, RSA_SIG_PSS);
            break;
        case EVP_PKEY_EC:
            err_value = gen_sig_data_ecdsa(in_file, classical_key, hash_alg,
                                           sig0_buf, sig0_buf_bytes);
            break;
    }

    if (err_value == CAL_SUCCESS)
    {
        /* Sign with quantum-resistant algorithm  */
        if (EVP_PKEY_is_a(pqc_key, "dilithium3") ||
            EVP_PKEY_is_a(pqc_key, "dilithium5"))
        {
            err_value = gen_sig_data_dilithium(in_file, pqc_key, hash_alg,
                                               sig1_buf, sig1_buf_bytes);
        }
        else if (EVP_PKEY_is_a(pqc_key, "mldsa65") ||
                 EVP_PKEY_is_a(pqc_key, "mldsa87"))
        {
            err_value = gen_sig_data_mldsa(in_file, pqc_key, hash_alg, sig1_buf,
                                           sig1_buf_bytes);
        }
        else
        {
            display_error("Unsupported post-quantum algorithm");
        }
    }

    return err_value;
}
#endif /* CST_WITH_PQC */

/*--------------------------
  error
---------------------------*/
void
display_error(const char *err)
{
    fprintf(stderr, "Error: %s\n", err);
}

/*--------------------------
  calculate_sig_buf_size
---------------------------*/
#define SIG_BUF_FIXED_DATA_SIZE 217

int32_t
calculate_sig_buf_size(const char *cert_file) {
    X509 *cert;
    EVP_PKEY *public_key;
    int key_length = 0;
    int sn_length = 0;
    char *issuer_name;
    int issuer_name_length = 0;

    /* Calculate Signature Size for padding purposes in CSF binary:
    *     It has been experimentally evalutated and noted that the variables in
    *     signature size is related to three entries in the CMS format. This is
    *     only considering signatures from the keys created from the CST PKI
    *     scripts.
    *
    *     The fixed size of the CMS structure was experimentally
    *     determined to be 217 bytes.
    *
    *     The three entries that appear to alter the size:
    *         Serial Number (SN)
    *         CA Certificate Name
    *         RSA Encryption  (this size is equal to key size in bytes)
    *
    *     Given the above the current approach to calculating the signature size:
    *
    *         <fixed size (217)> + <SN Size> + <CA Name Size> + <RSA Data Size>
    */
    /* Gather Signing Key Details */
    cert = read_certificate(cert_file);
    public_key = X509_get_pubkey(cert);
    key_length = PKEY_GET_SIZE(public_key);

    /**
     * OpenSSL strips leading zeros when calculating the length of the serial
     * number in the ASN1_INTEGER structure: X509_get_serialNumber(cert)->length;
     * To handle this case, we modify the approach to manually compute the serial
     * number length based on the number of bytes of DER representation.
     */
    sn_length = get_certificate_serial_number_length(cert);

    issuer_name = X509_NAME_oneline(X509_get_issuer_name(cert),NULL, 0);
    issuer_name_length = strlen(issuer_name);

    return (SIG_BUF_FIXED_DATA_SIZE + key_length + sn_length + issuer_name_length);
}

/*--------------------------
  export_habv4_signature_request
---------------------------*/
int32_t export_habv4_signature_request(const char *in_file,
                                       const char *cert_file, uint8_t *sig_buf,
                                       size_t *sig_buf_bytes)
{
    FILE *sig_req_fp = NULL;
    int unique_ident[2] = {0};
    FILE *in_file_fp = NULL;
    FILE *cpy_data_fp = NULL;
    char tmp_filename[80] = {0};
    long in_data_size = 0;
    int tmp = 0;

    if (!in_file || !cert_file || !sig_buf || !sig_buf_bytes)
    {
        fprintf(stderr, "ERROR: Null input parameter provided.\n");
        return -EINVAL;
    }

    /* Open data file */
    if (!(in_file_fp = fopen(in_file, "rb")))
    {
        fprintf(stderr, "ERROR: Unable to open input file %s. errno: %d\n",
                in_file, errno);
        return -ENOENT;
    }

    /* Determine the data file size */
    if (fseek(in_file_fp, 0L, SEEK_END) == -1)
    {
        perror("ERROR: Unable to seek to end of file");
        fclose(in_file_fp);
        return -EIO;
    }
    if ((in_data_size = ftell(in_file_fp)) < 0) {
        perror("ERROR: Unable to determine file size");
        fclose(in_file_fp);
        return -EIO;
    }

    /* Set the fp to the beginning of the data file */
    if (fseek(in_file_fp, 0L, SEEK_SET) == -1)
    {
        perror("ERROR: Unable to rewind file");
        fclose(in_file_fp);
        return -EIO;
    }

    /* Create the output data file name */
    if (snprintf(tmp_filename, sizeof(tmp_filename), "data_%s", in_file) >=
        (int) sizeof(tmp_filename))
    {
        fprintf(stderr, "ERROR: Temporary filename too long.\n");
        fclose(in_file_fp);
        return -EINVAL;
    }

    /* Copy the data file to the output data file */
    if (!(cpy_data_fp = fopen(tmp_filename, "wb")))
    {
        fprintf(stderr, "ERROR: Unable to open output file %s. errno: %d\n",
                tmp_filename, errno);
        fclose(in_file_fp);
        return -EIO;
    }

    while (in_data_size--)
    {
        tmp = fgetc(in_file_fp);
        if (tmp == EOF)
        {
            if (ferror(in_file_fp))
            {
                perror("ERROR: Reading input file");
                break;
            }
            if (feof(in_file_fp))
            {
                break;
            }
        }

        if (fputc(tmp, cpy_data_fp) == EOF)
        {
            perror("ERROR: Writing to output file");
            fclose(in_file_fp);
            fclose(cpy_data_fp);
            return -EIO;
        }
    }

    /* Create unique identifier */
    unique_ident[0] = rand();
    unique_ident[1] = rand();

    /* Add entry to signing request file for new data file */
    if (!(sig_req_fp = fopen("sig_request.txt", "a")))
    {
        fprintf(stderr,
                "ERROR: Unable to open signing request file. errno: %d\n",
                errno);
        fclose(in_file_fp);
        fclose(cpy_data_fp);
        return -EIO;
    }
    if (fseek(sig_req_fp, 0L, SEEK_END) == -1)
    {
        perror("ERROR: Unable to seek to end of signing request file");
        fclose(in_file_fp);
        fclose(cpy_data_fp);
        fclose(sig_req_fp);
        return -EIO;
    }

    fprintf(sig_req_fp, "Signing Request:\n");
    fprintf(sig_req_fp, "%s\n", tmp_filename);
    fprintf(sig_req_fp, "unique tag: %08x%08x\n", unique_ident[1],
            unique_ident[0]);

    /* Close all files */
    fclose(in_file_fp);
    fclose(cpy_data_fp);
    fclose(sig_req_fp);

    /* Handle signature buffer size */
    if ((g_sig_size > 0) && (g_sig_size <= SIGNATURE_BUFFER_SIZE))
    {
        *sig_buf_bytes = g_sig_size;
    }
    else
    {
        *sig_buf_bytes = calculate_sig_buf_size(cert_file);
    }

    memset(sig_buf, 0, *sig_buf_bytes);
    memcpy(sig_buf, unique_ident, sizeof(unique_ident));

    return 0;
}

/*--------------------------
  export_signature_request
---------------------------*/
int32_t export_signature_request(const char *in_file,
                                 const char *cert_file)
{
#define WRITE_LINE()                                                       \
    if (strlen(line) != fwrite(line, 1, strlen(line), sig_req))            \
    {                                                                      \
        snprintf(err_str, MAX_ERR_STR_BYTES, "Unable to write to file %s", \
                 SIG_REQ_FILENAME);                                        \
        display_error(err_str);                                            \
        fclose(sig_req);                                                   \
        return CAL_CRYPTO_API_ERROR;                                       \
    }

    char err_str[MAX_ERR_STR_BYTES]; /**< Used in preparing error message  */
    FILE *sig_req = NULL;            /**< Output signing request           */
    char line[MAX_LINE_CHARS];       /**< Used in preparing output message */

    sig_req = fopen(SIG_REQ_FILENAME, "a");
    if (NULL ==  sig_req) {
        snprintf(err_str, MAX_ERR_STR_BYTES,
                 "Unable to create file %s", SIG_REQ_FILENAME);
        display_error(err_str);
        return CAL_CRYPTO_API_ERROR;
    }

    snprintf(line, MAX_LINE_CHARS,
             "[Signing request]\r\n");
    WRITE_LINE();
    snprintf(line, MAX_LINE_CHARS,
             "Signing certificate = %s\r\n", cert_file);
    WRITE_LINE();
    snprintf(line, MAX_LINE_CHARS,
             "Data to be signed   = %s\r\n\r\n", in_file);
    WRITE_LINE();

    fclose(sig_req);

    return CAL_SUCCESS;
}

/*===========================================================================
                              GLOBAL FUNCTIONS
=============================================================================*/

/*--------------------------
  ssl_gen_sig_data
---------------------------*/
int32_t ssl_gen_sig_data(const char *in_file, const char *cert_file,
                         hash_alg_t hash_alg, sig_fmt_t sig_fmt,
                         uint8_t *sig0_buf, size_t *sig0_buf_bytes,
                         uint8_t *sig1_buf, size_t *sig1_buf_bytes,
                         func_mode_t mode)
{
	int32_t ret = CAL_SUCCESS; /**< Used for return value */
	char *key_file = NULL;    /**< Mem ptr for key filename */
	EVP_PKEY *key = NULL;
	X509 *cert = NULL;
	char err_str[MAX_ERR_STR_BYTES] = { 0 };

	/* Check for valid arguments */
    if (!in_file || !cert_file || !sig0_buf || !sig0_buf_bytes)
        return CAL_INVALID_ARGUMENT;

    if ((mode == MODE_HSM) && (IS_AHAB(g_target)))
        return export_signature_request(in_file, cert_file);
    if ((mode == MODE_HSM) && (IS_HAB(g_target)))
        return export_habv4_signature_request(in_file, cert_file, sig0_buf,
                                              sig0_buf_bytes);

    /* Determine private key filename from given certificate filename */
    key_file = malloc(strlen(cert_file)+1);
	if (!key_file)
		return CAL_INSUFFICIENT_MEMORY;

	ret = get_key_file(cert_file, key_file);
	if (ret != CAL_SUCCESS) {
		free(key_file);
		return CAL_FILE_NOT_FOUND;
	}

	/* Read certificate */
	cert = read_certificate(cert_file);
	if (!cert) {
		snprintf(err_str, MAX_ERR_STR_BYTES-1,
			 "Cannot open certificate file %s", cert_file);
		display_error(err_str);
		free(key_file);
		return CAL_CRYPTO_API_ERROR;
	}

	/* Read the key */
	key = read_private_key(key_file,
			(pem_password_cb *)get_passcode_to_key_file, key_file);
	if (!key) {
		snprintf(err_str, MAX_ERR_STR_BYTES-1,
			"Cannot open key file %s", key_file);
		display_error(err_str);
		return CAL_CRYPTO_API_ERROR;
	}

	if (sig_fmt == SIG_FMT_PKCS1) {
        ret = gen_sig_data_rsa(in_file, key, hash_alg, sig0_buf, sig0_buf_bytes,
                               RSA_SIG_PKCS1);
    }
    else if (sig_fmt == SIG_FMT_RSA_PSS)
    {
        ret = gen_sig_data_rsa(in_file, key, hash_alg, sig0_buf, sig0_buf_bytes,
                               RSA_SIG_PSS);
    }
    else if (sig_fmt == SIG_FMT_CMS)
    {
        ret = gen_sig_data_cms(in_file, cert, key, hash_alg, sig0_buf,
                               sig0_buf_bytes);
    }
    else if (sig_fmt == SIG_FMT_ECDSA)
    {
        ret = gen_sig_data_ecdsa(in_file, key, hash_alg, sig0_buf,
                                 sig0_buf_bytes);
    }
#if CST_WITH_PQC
    else if (sig_fmt == SIG_FMT_DILITHIUM)
    {
        ret = gen_sig_data_dilithium(in_file, key, hash_alg, sig0_buf,
                                     sig0_buf_bytes);
    }
    else if (sig_fmt == SIG_FMT_MLDSA)
    {
        ret = gen_sig_data_mldsa(in_file, key, hash_alg, sig0_buf,
                                 sig0_buf_bytes);
    }
    else if (sig_fmt == SIG_FMT_HYBRID)
    {
        ret = gen_sig_data_hybrid(in_file, key, hash_alg, sig0_buf,
                                  sig0_buf_bytes, sig1_buf, sig1_buf_bytes);
    }
#endif
    else
    {
        free(key_file);
		display_error("Invalid signature format");
		return CAL_INVALID_ARGUMENT;
    }

    if (key)
		EVP_PKEY_free(key);
	if (cert)
		X509_free(cert);

	free(key_file);
	return ret;
}

int32_t engine_gen_sig_data(const char *in_file, const char *cert_ref,
                            hash_alg_t hash_alg, sig_fmt_t sig_fmt,
                            uint8_t *sig0_buf, size_t *sig0_buf_bytes,
                            uint8_t *sig1_buf, size_t *sig1_buf_bytes,
                            func_mode_t mode)
{
	/* Engine configuration */
	struct engine_ctx *ctx = NULL;
	/* Certificate and private key */
	X509 *cert = NULL;
	EVP_PKEY *key = NULL;
	/* Operation completed successfully */
	int32_t ret = CAL_SUCCESS;

	/* Check for valid arguments */
    if (!in_file || !cert_ref || !sig0_buf || !sig0_buf_bytes)
        return CAL_INVALID_ARGUMENT;

    /* Allocate new context */
	ctx = engine_ctx_new();

	if (ctx == NULL) {
		ret = CAL_CRYPTO_API_ERROR;
		goto out;
	}

	/* Initialize the context */
	if (!engine_ctx_init(ctx)) {
		ret = CAL_CRYPTO_API_ERROR;
		goto out;
	}

	cert = ENGINE_load_certificate(ctx->engine, cert_ref);
	if (!cert) {
		ret = CAL_CRYPTO_API_ERROR;
		goto out;
	}
#ifdef DEBUG
	X509_print_fp(stdout, cert);
#endif

	key = ENGINE_load_key(ctx->engine, cert_ref);

	if (key == NULL) {
		ret = CAL_CRYPTO_API_ERROR;
		goto out;
	}

	/*
	 * OpenSSL expects EVP_PKEY to contain the ec_point. PKCS#11 does not
	 * return the ec_point as an attribute for private key.
	 */
	if (EVP_PKEY_base_id(key) == EVP_PKEY_RSA) {
		ret = X509_check_private_key(cert, key);
		if (!ret) {
			ret = CAL_CRYPTO_API_ERROR;
			goto out;
		}
	}

	switch (sig_fmt) {
	case SIG_FMT_ECDSA:
        ret = gen_sig_data_ecdsa(in_file, key, hash_alg, sig0_buf,
                                 sig0_buf_bytes);
        break;
    case SIG_FMT_PKCS1:
        ret = gen_sig_data_rsa(in_file, key, hash_alg, sig0_buf, sig0_buf_bytes,
                               RSA_SIG_PKCS1);
        break;
    case SIG_FMT_CMS:
        ret = gen_sig_data_cms(in_file, cert, key, hash_alg, sig0_buf,
                               sig0_buf_bytes);
        break;
    case SIG_FMT_RSA_PSS:
        ret = gen_sig_data_rsa(in_file, key, hash_alg, sig0_buf, sig0_buf_bytes,
                               RSA_SIG_PSS);
        break;
    default:
		display_error("Invalid signature format");
		ret =  CAL_INVALID_ARGUMENT;
		break;
	}

out:
	if (ctx) {
		/*
		 * Destroy the context: ctx_finish is not called here
		 * since ENGINE_finish cleanups the engine instance.
		 * Calling ctx_destroy next will lead to null pointer
		 * dereference.
		 */
		engine_ctx_destroy(ctx);
	}

	if (ret)
		ERR_print_errors_fp(stderr);
	if (cert)
		X509_free(cert);
	if (key)
		EVP_PKEY_free(key);

	return ret;
}

/*--------------------------
  generate_dek_key
---------------------------*/
int32_t generate_dek_key(uint8_t * key, int32_t len)
{
    if (gen_random_bytes(key, len) != CAL_SUCCESS) {
        return CAL_CRYPTO_API_ERROR;
    }

    return CAL_SUCCESS;
}

/*--------------------------
  write_plaintext_dek_key
---------------------------*/
int32_t write_plaintext_dek_key(uint8_t * key, size_t key_bytes,
                const char * cert_file, const char * enc_file)
{
    int32_t err_value = CAL_SUCCESS;  /**< Return value */
    char err_str[MAX_ERR_STR_BYTES];  /**< Used in preparing error message */
    FILE *fh = NULL;                  /**< File handle used with file api */
#ifdef DEBUG
    int32_t i = 0;                    /**< Used in for loops */
#endif

    UNUSED(cert_file);

    do {
        /* Save the buffer into enc_file */
        if ((fh = fopen(enc_file, "wb")) == NULL) {
            snprintf(err_str, MAX_ERR_STR_BYTES-1,
                     "Unable to create binary file %s", enc_file);
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }
        if (fwrite(key, 1, key_bytes, fh) !=
            key_bytes) {
            snprintf(err_str, MAX_ERR_STR_BYTES-1,
                     "Unable to write to binary file %s", enc_file);
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            fclose(fh);
            break;
        }
        fclose(fh);
   } while(0);

    return err_value;
}


/*--------------------------
  encrypt_dek_key
---------------------------*/
int32_t encrypt_dek_key(uint8_t * key, size_t key_bytes,
                const char * cert_file, const char * enc_file)
{
    X509            *cert = NULL;     /**< Ptr to X509 certificate read data */
    STACK_OF(X509) *recips = NULL;    /**< Ptr to X509 stack */
    CMS_ContentInfo *cms = NULL;      /**< Ptr to cms structure */
    const EVP_CIPHER *cipher = NULL;  /**< Ptr to EVP_CIPHER */
    int32_t err_value = CAL_SUCCESS;  /**< Return value */
    char err_str[MAX_ERR_STR_BYTES];  /**< Used in preparing error message */
    BIO *bio_key = NULL;              /**< Bio for the key data to encrypt */
    uint8_t * enc_buf = NULL;         /**< Ptr for encoded key data */
    FILE *fh = NULL;                  /**< File handle used with file api */
    size_t cms_info_size = MAX_CMS_DATA; /**< Size of cms content info*/
#ifdef DEBUG
    int32_t i = 0;                    /**< Used in for loops */
#endif

    do {
        /* Read the certificate from cert_file */
        cert = read_certificate(cert_file);
        if (!cert) {
            snprintf(err_str, MAX_ERR_STR_BYTES-1,
                     "Cannot open certificate file %s", cert_file);
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Create recipient STACK and add recipient cert to it */
        recips = sk_X509_new_null();

        if (!recips || !sk_X509_push(recips, cert)) {
            snprintf(err_str, MAX_ERR_STR_BYTES-1,
                     "Cannot instantiate object STACK_OF(%s)", cert_file);
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /*
         * sk_X509_pop_free will free up recipient STACK and its contents
         * so set cert to NULL so it isn't freed up twice.
         */
        cert = NULL;

        /* Instantiate correct cipher */
        if (key_bytes == (AES_KEY_LEN_128 / BYTE_SIZE_BITS))
            cipher = EVP_aes_128_cbc();
        else if (key_bytes == (AES_KEY_LEN_192 / BYTE_SIZE_BITS))
            cipher = EVP_aes_192_cbc();
        else if (key_bytes == (AES_KEY_LEN_256 / BYTE_SIZE_BITS))
            cipher = EVP_aes_256_cbc();
        if (cipher == NULL) {
            snprintf(err_str, MAX_ERR_STR_BYTES-1,
                     "Invalid cipher used for encrypting key %s", enc_file);
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Allocate memory buffer BIO for input key */
        bio_key = BIO_new_mem_buf(key, key_bytes);
        if (!bio_key) {
            display_error("Unable to allocate BIO memory");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Encrypt content of the key with certificate */
        cms = CMS_encrypt(recips, bio_key, cipher, CMS_BINARY|CMS_STREAM);
        if (cms == NULL) {
            snprintf(err_str, MAX_ERR_STR_BYTES-1,
                     "Failed to encrypt key data");
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Finalize the CMS content info structure */
        if (!CMS_final(cms, bio_key, NULL,  CMS_BINARY|CMS_STREAM)) {
            snprintf(err_str, MAX_ERR_STR_BYTES-1,
                     "Failed to finalize cms data");
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Alloc mem to convert cms to binary and save it into enc_file */
        enc_buf = malloc(MAX_CMS_DATA);
        if (enc_buf == NULL) {
            snprintf(err_str, MAX_ERR_STR_BYTES-1,
                     "Failed to allocate memory");
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Copy cms info into enc_buf */
        err_value = cms_to_buf(cms, bio_key, enc_buf, &cms_info_size,
            CMS_BINARY);

        /* Save the buffer into enc_file */
        if ((fh = fopen(enc_file, "wb")) == NULL) {
            snprintf(err_str, MAX_ERR_STR_BYTES-1,
                     "Unable to create binary file %s", enc_file);
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }
        if (fwrite(enc_buf, 1, cms_info_size, fh) !=
            cms_info_size) {
            snprintf(err_str, MAX_ERR_STR_BYTES-1,
                     "Unable to write to binary file %s", enc_file);
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            fclose(fh);
            break;
        }
        fclose(fh);
#ifdef DEBUG
        printf("Encoded key ;");
        for(i=0; i<key_bytes; i++) {
            printf("%02x ", enc_buf[i]);
        }
        printf("\n");
#endif
    } while(0);

    if (cms)
        CMS_ContentInfo_free(cms);
    if (cert)
        X509_free(cert);
    if (recips)
        sk_X509_pop_free(recips, X509_free);
    if (bio_key)
        BIO_free(bio_key);
    return err_value;
}

/*--------------------------
  gen_auth_encrypted_data
---------------------------*/
int32_t gen_auth_encrypted_data(const char* in_file,
                     const char* out_file,
                     aead_alg_t aead_alg,
                     uint8_t *aad,
                     size_t aad_bytes,
                     uint8_t *nonce,
                     size_t nonce_bytes,
                     uint8_t *mac,
                     size_t mac_bytes,
                     size_t key_bytes,
                     const char* cert_file,
                     const char* key_file,
                     int reuse_dek)
{
    int32_t err_value = CAL_SUCCESS;         /**< status of function calls */
    char err_str[MAX_ERR_STR_BYTES];         /**< Array to hold error string */
    static uint8_t key[MAX_AES_KEY_LENGTH];  /**< Buffer for random key */
    static uint8_t key_init_done = 0;        /**< Status of key initialization */
    FILE *fh = NULL;                         /**< Used with files */
    long file_size = 0;                      /**< Size of in_file */
    unsigned char *plaintext = NULL;                /**< Array to read file data */
    int32_t bytes_read;
#ifdef DEBUG
    int32_t i;                                        /**< used in for loops */
#endif
    uint8_t nonce_temp[nonce_bytes];
    int32_t j = 1;

    do {
        if (AES_CCM == aead_alg) { /* HAB4 */
            /* Test random byte generation twice for functional confirmation */
            do {
                /* Generate Nonce */
                err_value = gen_random_bytes((uint8_t*)nonce, nonce_bytes);
                if (err_value != CAL_SUCCESS) {
                    snprintf(err_str, MAX_ERR_STR_BYTES-1,
                                "Failed to get nonce");
                    display_error(err_str);
                    err_value = CAL_CRYPTO_API_ERROR;
                    break;
                }
                /* Copy nonce in temp variable to compare in next iteration */
                if (1 == j) {
                    memcpy(&nonce_temp, nonce, nonce_bytes);
                }
                else {
                    /* If random numbers in two iterations are equal, throw an error */
                    if (!memcmp(&nonce_temp, nonce, nonce_bytes)) {
                        snprintf(err_str, MAX_ERR_STR_BYTES-1,
                                    "Invalid nonce generated");
                        display_error(err_str);
                        err_value = CAL_CRYPTO_API_ERROR;
                        break;
                    }
                }
            } while (j--);
        }
        /* Exit this loop if error encountered in random bytes generation */
        if (err_value != CAL_SUCCESS)
            break;
#ifdef DEBUG
        printf("nonce bytes: ");
        for(i=0; i<nonce_bytes; i++) {
            printf("%02x ", nonce[i]);
        }
        printf("\n");
#endif
        if (0 == key_init_done) {
            if (reuse_dek) {
                fh = fopen(key_file, "rb");
                if (fh == NULL) {
                    snprintf(err_str, MAX_ERR_STR_BYTES-1,
                        "Unable to open dek file %s", key_file);
                    display_error(err_str);
                    err_value = CAL_FILE_NOT_FOUND;
                    break;
                }
                /* Read encrypted data into input_buffer */
                bytes_read = fread(key, 1, key_bytes, fh);
                if (bytes_read == 0) {
                    snprintf(err_str, MAX_ERR_STR_BYTES-1,
                        "Cannot read file %s", key_file);
                    display_error(err_str);
                    err_value = CAL_FILE_NOT_FOUND;
                    fclose(fh);
                    break;
                }
                fclose(fh);
            }
            else {
                /* Generate random aes key to use it for encrypting data */
                    err_value = generate_dek_key(key, key_bytes);
                    if (err_value) {
                        snprintf(err_str, MAX_ERR_STR_BYTES-1,
                                    "Failed to generate random key");
                        display_error(err_str);
                        err_value = CAL_CRYPTO_API_ERROR;
                        break;
                    }
            }

#ifdef DEBUG
            printf("random key : ");
            for (i=0; i<key_bytes; i++) {
                printf("%02x ", key[i]);
            }
            printf("\n");
#endif
            if (cert_file!=NULL) {
                /* Encrypt key using cert file and save it in the key_file */
                err_value = encrypt_dek_key(key, key_bytes, cert_file, key_file);
                if (err_value) {
                    snprintf(err_str, MAX_ERR_STR_BYTES-1,
                            "Failed to encrypt and save key");
                    display_error(err_str);
                    err_value = CAL_CRYPTO_API_ERROR;
                    break;
                }
            } else {
                /* Save key in the key_file */
                err_value = write_plaintext_dek_key(key, key_bytes, cert_file, key_file);
                if (err_value) {
                    snprintf(err_str, MAX_ERR_STR_BYTES-1,
                            "Failed to save key");
                    display_error(err_str);
                    err_value = CAL_CRYPTO_API_ERROR;
                    break;
                }
            }

            key_init_done = 1;
        }

        /* Get the size of in_file */
        fh = fopen(in_file, "rb");
        if (fh == NULL) {
            snprintf(err_str, MAX_ERR_STR_BYTES-1,
                     "Unable to open binary file %s", in_file);
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }
        if (fseek(fh, 0, SEEK_END) != 0)
        {
            display_error("Failed to seek to the end of the file.");
            err_value = CAL_FILE_NOT_FOUND;
            fclose(fh);
            break;
        }
        file_size = ftell(fh);
        if (file_size < 0)
        {
            display_error("Failed to determine file size.");
            err_value = CAL_FILE_NOT_FOUND;
            fclose(fh);
            break;
        }

        plaintext = (unsigned char*)malloc(file_size);;
        if (plaintext == NULL) {
            snprintf(err_str, MAX_ERR_STR_BYTES-1,
                         "Not enough allocated memory" );
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            fclose(fh);
            break;
        }
        fclose(fh);

        fh = fopen(in_file, "rb");
        if (fh == NULL) {
            snprintf(err_str, MAX_ERR_STR_BYTES-1,
                         "Cannot open file %s", in_file);
            display_error(err_str);
            err_value = CAL_FILE_NOT_FOUND;
            break;
        }

        /* Read encrypted data into input_buffer */
        bytes_read = fread(plaintext, 1, file_size, fh);
        fclose(fh);
        /* Reached EOF? */
        if (bytes_read == 0) {
            snprintf(err_str, MAX_ERR_STR_BYTES-1,
                         "Cannot read file %s", out_file);
            display_error(err_str);
            err_value = CAL_FILE_NOT_FOUND;
           break;
        }

        if (AES_CCM == aead_alg) { /* HAB4 */
            err_value = encryptccm(plaintext, file_size, aad, aad_bytes,
                                key, key_bytes, nonce, nonce_bytes, out_file,
                                mac, mac_bytes, &err_value, err_str);
        }
        else if (AES_CBC == aead_alg) { /* AHAB */
            err_value = encryptcbc(plaintext, file_size, key, key_bytes, nonce,
                                   out_file, &err_value, err_str);
        }
        else {
            err_value = CAL_INVALID_ARGUMENT;
        }
        if (err_value == CAL_NO_CRYPTO_API_ERROR) {
            printf("Encryption not enabled\n");
            break;
        }
    } while(0);

    /* Clean up */

    free(plaintext);

    return err_value;
}
