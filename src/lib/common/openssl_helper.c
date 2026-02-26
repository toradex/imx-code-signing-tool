// SPDX-License-Identifier: BSD-3-Clause
/*
 * (c) Freescale Semiconductor, Inc. 2011, 2012. All rights reserved.
 * Copyright 2018-2020, 2022-2025 NXP
 */

/*===========================================================================*/
/**
    @file    openssl_helper.c

    @brief   Provide helper functions to ease openssl tasks. Mainly to
                provide common code for several tools.
 */

/*===========================================================================
                                INCLUDE FILES
=============================================================================*/
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include "openssl_helper.h"
#include "err.h"
#include "version.h"
#include <openssl/rand.h>
#include <openssl/rsa.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/provider.h>
#endif

/*===========================================================================
                               LOCAL CONSTANTS
=============================================================================*/

/*===========================================================================
                                 LOCAL MACROS
=============================================================================*/

/*===========================================================================
                  LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
=============================================================================*/

/*============================================================================
                           GLOBAL VARIABLE DECLARATIONS
=============================================================================*/

static OSSL_LIB_CTX *g_libctx = NULL;

extern OSSL_provider_init_fn oqs_provider_init;

/*===========================================================================
                               OPENSSL 1.0.2 SUPPORT
=============================================================================*/

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)

static void *
OPENSSL_zalloc(size_t num)
{
    void *ret = OPENSSL_malloc(num);

    if (ret != NULL) {
        memset(ret, 0, num);
    }
    return ret;
}

void
ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
    if (pr != NULL) {
        *pr = sig->r;
    }
    if (ps != NULL) {
        *ps = sig->s;
    }
}

int
ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    if (r == NULL || s == NULL) {
        return 0;
    }
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;
    return 1;
}

void
EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
    EVP_MD_CTX_cleanup(ctx);
    OPENSSL_free(ctx);
}

EVP_MD_CTX *
EVP_MD_CTX_new(void)
{
    return OPENSSL_zalloc(sizeof(EVP_MD_CTX));
}

EC_KEY *
EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey)
{
    return (pkey->pkey.ec);
}

RSA *
EVP_PKEY_get0_RSA(EVP_PKEY *pkey)
{
    if (pkey->type != EVP_PKEY_RSA) {
        return NULL;
    }
    return pkey->pkey.rsa;
}

void
RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n != NULL) {
        *n = r->n;
    }
    if (e != NULL) {
        *e = r->e;
    }
    if (d != NULL) {
       *d = r->d;
    }
}

#endif


/*===========================================================================
                          LOCAL FUNCTION PROTOTYPES
=============================================================================*/

/*===========================================================================
                               LOCAL FUNCTIONS
=============================================================================*/

/*===========================================================================
                               GLOBAL FUNCTIONS
=============================================================================*/

/*--------------------------
  openssl_initialize
---------------------------*/
void openssl_initialize(void)
{
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *oqs_provider = NULL;

#if defined _WIN32 || defined __CYGWIN__
    /* Required to avoid OpenSSL runtime errors on Win32 platforms */
    /* See: https://www.openssl.org/docs/faq.html#PROG3 */
    OPENSSL_malloc_init();
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
#endif

    g_libctx = OSSL_LIB_CTX_new();
    if (g_libctx == NULL)
    {
        error("Cannot initialize OpenSSL");
    }

    /* Load default provider */
    default_provider = OSSL_PROVIDER_load(g_libctx, "default");
    if (default_provider == NULL)
    {
        OSSL_LIB_CTX_free(g_libctx);
        error("Error loading default provider");
    }
#if CST_WITH_PQC
    /* Load OQS provider */
    if (OSSL_PROVIDER_add_builtin(g_libctx, "oqsprovider", oqs_provider_init) !=
        1)
    {
        OSSL_PROVIDER_unload(default_provider);
        OSSL_LIB_CTX_free(g_libctx);
        error("Failed to add the builtin provider `oqsprovider`");
    }

    oqs_provider = OSSL_PROVIDER_load(g_libctx, "oqsprovider");
    if (oqs_provider == NULL)
    {
        OSSL_PROVIDER_unload(default_provider);
        OSSL_LIB_CTX_free(g_libctx);
        error("Failed to load `oqsprovider`");
    }
#endif
}

/*--------------------------
  get_libctx
---------------------------*/
OSSL_LIB_CTX *get_libctx(void)
{
    return g_libctx;
}

/*--------------------------
  generate_hash
---------------------------*/

uint8_t *generate_hash(const uint8_t *buf, size_t msg_bytes,
                       const char *hash_alg, size_t *hash_bytes)
{
    char normalized_alg[32] = {0};
    const EVP_MD *type = NULL;
    EVP_MD_CTX *ctx = NULL;
    uint8_t *hash_mem_ptr = NULL;
    unsigned int tmp = 0;
    size_t xoflen = 0;

    if (!buf || !hash_alg || !hash_bytes)
    {
        return NULL;
    }

    /* Normalize algorithm name */
    if (strcmp(hash_alg, "shake128-256") == 0)
    {
        strncpy(normalized_alg, "SHAKE128", sizeof(normalized_alg) - 1);
        xoflen = HASH_BYTES_SHAKE128_256;
    }
    else if (strcmp(hash_alg, "shake256-512") == 0)
    {
        strncpy(normalized_alg, "SHAKE256", sizeof(normalized_alg) - 1);
        xoflen = HASH_BYTES_SHAKE256_512;
    }
    else
    {
        strncpy(normalized_alg, hash_alg, sizeof(normalized_alg) - 1);
    }

    type = EVP_get_digestbyname(normalized_alg);
    if (!type)
    {
        return NULL;
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        return NULL;
    }

    if (EVP_DigestInit_ex(ctx, type, NULL) != 1 ||
        EVP_DigestUpdate(ctx, buf, msg_bytes) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    hash_mem_ptr = (uint8_t *) malloc(EVP_MAX_MD_SIZE);
    if (!hash_mem_ptr)
    {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    if (xoflen > 0)
    {
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_XOFLEN, &xoflen),
            OSSL_PARAM_construct_end()};

        if (EVP_MD_CTX_set_params(ctx, params) != 1)
        {
            ERR_print_errors_fp(stderr);
            EVP_MD_CTX_free(ctx);
            return NULL;
        }
    }

    if (EVP_DigestFinal_ex(ctx, hash_mem_ptr, &tmp) != 1)
    {
        free(hash_mem_ptr);
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    *hash_bytes = (size_t) tmp;
    EVP_MD_CTX_free(ctx);

    return hash_mem_ptr;
}

/*--------------------------
  get_bn
---------------------------*/

uint8_t*
get_bn(const BIGNUM *a, size_t *bytes)
{
    uint8_t *byte_array = NULL; /**< Resulting big number byte array */
    uint32_t a_num_bytes = BN_num_bytes(a);

    byte_array = malloc(a_num_bytes);
    if (byte_array == NULL)
    {
        return NULL;
    }

    BN_bn2bin(a, byte_array);

    *bytes = a_num_bytes;
    return byte_array;
}

/*--------------------------
  sign_data
---------------------------*/

uint8_t*
sign_data(const EVP_PKEY *skey, const BUF_MEM *bptr, hash_alg_t hash_alg,
          size_t *sig_bytes)
{
    EVP_MD_CTX   *ctx = EVP_MD_CTX_create(); /**< Signature context */
    uint8_t      *sig_buf = NULL;            /**< Location of sig. array */
    const EVP_MD *hash_type = NULL;          /**< Hash digest algorithm type */
    unsigned int tmp_sig_bytes = 0;
#ifdef DEBUG
    uint32_t i = 0; /**< Loop index */
#endif

    if (ctx)
    {
        tmp_sig_bytes = EVP_PKEY_size((EVP_PKEY *)skey);
        sig_buf = malloc(tmp_sig_bytes);

        /* Determine OpenSSL hash digest type */
        if (hash_alg == SHA_1)
        {
            hash_type = EVP_sha1();
        }
        else if (hash_alg == SHA_256)
        {
            hash_type = EVP_sha256();
        }
        else
        {
            EVP_MD_CTX_destroy(ctx);
            free(sig_buf);
            return NULL;
        }

        if ((sig_buf != NULL) &&
            ( (EVP_SignInit_ex(ctx, hash_type, NULL) != CST_SUCCESS) ||
              (EVP_SignUpdate(ctx, bptr->data, bptr->length) != CST_SUCCESS) ||
              (EVP_SignFinal(ctx, sig_buf, &tmp_sig_bytes, (EVP_PKEY *)skey)
               != CST_SUCCESS) ))
        {
            *sig_bytes = tmp_sig_bytes;
            EVP_MD_CTX_destroy(ctx);
            free(sig_buf);
            return NULL;
        }

        *sig_bytes = tmp_sig_bytes;

#ifdef DEBUG
        printf("Signature bytes = %d\n", tmp_sig_bytes);
        if (sig_buf)
        {
            for (i = 0; i < tmp_sig_bytes; i++)
            {
                printf("%d) 0x%02x\n", i, sig_buf[i]);
            }
        }
#endif

        EVP_MD_CTX_destroy(ctx);
    }
    return sig_buf;
}

/*--------------------------------
  get_der_encoded_certificate_data
----------------------------------*/
int32_t get_der_encoded_certificate_data(const char* reference,
                                         uint8_t ** der)
{
    /** Used for returning either size of der data or 0 to indicate an error */
    int32_t ret_val = 0;

    /* Read X509 certificate data from cert file */
    X509 *cert = read_certificate(reference);

    if (cert != NULL)
    {
        /* i2d_X509() allocates memory for der data, converts the X509
         * cert structure to binary der formatted data.  It then
         * returns the address of the memory allocated for the der data
         */
        ret_val = i2d_X509(cert, der);

        /* On error return 0 */
        if (ret_val < 0)
        {
            ret_val = 0;
        }
        X509_free(cert);
    }
    return ret_val;
}

/*--------------------------
  read_private_key
---------------------------*/
EVP_PKEY *read_private_key(const char *filename, pem_password_cb *password_cb,
                           const char *password)
{
    BIO *private_key = NULL; /**< OpenSSL BIO ptr */
    EVP_PKEY *pkey = NULL;   /**< Private Key data structure */
    const char *temp = filename + strlen(filename) - PEM_FILE_EXTENSION_BYTES;
    OSSL_DECODER_CTX *dctx = NULL;

    /* Read Private key */
    private_key = BIO_new(BIO_s_file());
    if (!private_key)
    {
        return NULL;
    }

    /* Set BIO to read from the given filename */
    if (BIO_read_filename(private_key, filename) <= 0)
    {
        BIO_free(private_key);
        return NULL;
    }

    if (!strncasecmp(temp, PEM_FILE_EXTENSION, PEM_FILE_EXTENSION_BYTES))
    {
        /* Read Private key - from PEM encoded file */
        pkey =
            PEM_read_bio_PrivateKey_ex(private_key, NULL, password_cb,
                                       (char *) password, get_libctx(), NULL);
        if (!pkey)
        {
            BIO_free(private_key);
            return NULL;
        }
    }
    else
    {
        /* Read Private key - from DER encoded file using OSSL_DECODER_CTX */
        dctx = OSSL_DECODER_CTX_new_for_pkey(
            &pkey, "DER", NULL, NULL, EVP_PKEY_KEYPAIR, get_libctx(), NULL);
        if (dctx == NULL)
        {
            BIO_free(private_key);
            return NULL;
        }

        if (password && *password)
        {
            if (!OSSL_DECODER_CTX_set_pem_password_cb(dctx, password_cb,
                                                      (char *) password))
            {
                OSSL_DECODER_CTX_free(dctx);
                BIO_free(private_key);
                return NULL;
            }
        }

        if (!OSSL_DECODER_from_bio(dctx, private_key))
        {
            OSSL_DECODER_CTX_free(dctx);
            BIO_free(private_key);
            return NULL;
        }

        OSSL_DECODER_CTX_free(dctx);
    }

    BIO_free(private_key);
    return pkey;
}

/*--------------------------
  print_version
---------------------------*/

void print_version(void)
{
    printf("\nCode Signing Tool Version: %s\n",CST_VERSION);
    printf("\nCompiled with:\n\t%s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("\t%s\n\t%s\n\n", OpenSSL_version(OPENSSL_DIR), OpenSSL_version(OPENSSL_ENGINES_DIR));
}

/*--------------------------
  seed_prng
---------------------------*/
uint32_t seed_prng(uint32_t bytes)
{
    return RAND_load_file("/dev/random", bytes);
}


/*--------------------------
  gen_random_bytes
---------------------------*/
int32_t gen_random_bytes(uint8_t *buf, size_t bytes)
{
    if (!RAND_bytes(buf, bytes))
    {
        return CAL_RAND_API_ERROR;
    }

    return CAL_SUCCESS;
}

/*--------------------------
  get_digest_name
---------------------------*/
char*
get_digest_name(hash_alg_t hash_alg)
{
    char *hash_name = NULL;    /**< Ptr to return address of string macro */
    switch(hash_alg) {
        case SHA_1:
            hash_name = HASH_ALG_SHA1;
            break;
        case SHA_256:
            hash_name = HASH_ALG_SHA256;
            break;
        case SHA_384:
            hash_name = HASH_ALG_SHA384;
            break;
        case SHA_512:
            hash_name = HASH_ALG_SHA512;
            break;
        case SHA3_256:
            hash_name = HASH_ALG_SHA3_256;
            break;
        case SHA3_384:
            hash_name = HASH_ALG_SHA3_384;
            break;
        case SHA3_512:
            hash_name = HASH_ALG_SHA3_512;
            break;
        case SHAKE128_256:
            hash_name = HASH_ALG_SHAKE128;
            break;
        case SHAKE256_512:
            hash_name = HASH_ALG_SHAKE256;
            break;
        default:
            hash_name = HASH_ALG_INVALID;
            break;
    }
    return hash_name;
}

/*--------------------------
  calculate_hash
---------------------------*/
int32_t
calculate_hash(const char *in_file,
               hash_alg_t hash_alg,
               uint8_t *buf,
               int32_t *pbuf_bytes)
{
    const EVP_MD *sign_md; /**< Ptr to digest name */
    int32_t bio_bytes; /**< Length of bio data */
    BIO *in = NULL; /**< Ptr to BIO for reading data from in_file */
    BIO *bmd = NULL; /**< Ptr to BIO with hash bytes */
    BIO *inp; /**< Ptr to BIO for appending in with bmd */
    /** Status initialized to API error */
    int32_t err_value =  CAL_CRYPTO_API_ERROR;

    sign_md = EVP_get_digestbyname(get_digest_name(hash_alg));
    if (sign_md == NULL) {
        return CAL_INVALID_ARGUMENT;
    }

    /* Read data to generate hash */
    do {

        /* Create necessary bios */
        in = BIO_new(BIO_s_file());
        bmd = BIO_new(BIO_f_md());
        if (in == NULL || bmd == NULL) {
            break;
        }

        /* Set BIO to read filename in_file */
        if (BIO_read_filename(in, in_file) <= 0) {
            break;
        }

        /* Set BIO md to given hash */
        if (!BIO_set_md(bmd, sign_md)) {
            break;
        }

        /* Appends BIO in to bmd */
        inp = BIO_push(bmd, in);

        /* Read data from file BIO */
        do
        {
            bio_bytes = BIO_read(inp, (uint8_t *)buf, *pbuf_bytes);
        } while (bio_bytes > 0);

        /* Check for read error */
        if (bio_bytes < 0) {
            break;
        }

        /* Get the hash */
        bio_bytes = BIO_gets(inp, (char *)buf, *pbuf_bytes);
        if (bio_bytes <= 0) {
            break;
        }

        /* Send the output bytes in pbuf_bytes */
        *pbuf_bytes = bio_bytes;
        err_value =  CAL_SUCCESS;
    } while(0);

    if (in != NULL) BIO_free(in);
    if (bmd != NULL) BIO_free(bmd);

    return err_value;
}

/*--------------------------
  ver_sig_data
---------------------------*/
int32_t ver_sig_data(const char *in_file,
                     const char *cert_file,
                     hash_alg_t hash_alg,
                     sig_fmt_t  sig_fmt,
                     uint8_t    *sig_buf,
                     size_t     sig_buf_bytes)
{
    EVP_PKEY *pkey = X509_get_pubkey(read_certificate(cert_file));
    const EVP_MD   *hash_type     = EVP_get_digestbyname(get_digest_name(hash_alg));
    int32_t        hash_bytes     = HASH_BYTES_MAX;
    uint8_t *hash = NULL;
    ECDSA_SIG      *ecdsa_sig     = NULL;
    uint8_t        *ecdsa_der     = NULL;
    uint32_t       ecdsa_der_size = 0;
    EVP_PKEY_CTX *verify_ctx = NULL;

    if (NULL == in_file)       return CAL_INVALID_ARGUMENT;
    if (NULL == pkey)          return CAL_INVALID_ARGUMENT;
    if (NULL == hash_type)     return CAL_INVALID_ARGUMENT;
    if (NULL == sig_buf)       return CAL_INVALID_ARGUMENT;
    if (0    == sig_buf_bytes) return CAL_INVALID_ARGUMENT;

    hash = OPENSSL_malloc(HASH_BYTES_MAX);

    if (NULL == hash)
    {
        return CAL_INVALID_ARGUMENT;
    }

    if (CAL_SUCCESS != calculate_hash(in_file, hash_alg, hash, &hash_bytes))
    {
        OPENSSL_free(hash);
        return CAL_CRYPTO_API_ERROR;
    }
    verify_ctx = EVP_PKEY_CTX_new(pkey, NULL);

    if (verify_ctx == NULL || EVP_PKEY_verify_init(verify_ctx) <= 0)
    {
        OPENSSL_free(hash);
        return CAL_CRYPTO_API_ERROR;
    }

    switch (sig_fmt)
    {
        case SIG_FMT_PKCS1:
        case SIG_FMT_RSA_PSS:

            if (EVP_PKEY_CTX_set_rsa_padding(verify_ctx,
                                             (sig_fmt == SIG_FMT_RSA_PSS)
                                                 ? RSA_PKCS1_PSS_PADDING
                                                 : RSA_PKCS1_PADDING) != 1)
            {
                EVP_PKEY_CTX_free(verify_ctx);
                OPENSSL_free(hash);
                return CAL_CRYPTO_API_ERROR;
            }

            if (EVP_PKEY_CTX_set_signature_md(verify_ctx, hash_type) != 1)
            {
                EVP_PKEY_CTX_free(verify_ctx);
                OPENSSL_free(hash);
                return CAL_CRYPTO_API_ERROR;
            }

            if (EVP_PKEY_verify(verify_ctx, sig_buf, sig_buf_bytes,
                                    hash, hash_bytes) != 1)
            {
                EVP_PKEY_CTX_free(verify_ctx);
                OPENSSL_free(hash);
                return CAL_INVALID_SIGNATURE;
            }

            break;

        case SIG_FMT_ECDSA:
            ecdsa_sig = ECDSA_SIG_new();
            if (NULL == ecdsa_sig)
            {
                EVP_PKEY_CTX_free(verify_ctx);
                OPENSSL_free(hash);
                return CAL_CRYPTO_API_ERROR;
            }

            if (ECDSA_SIG_set0(ecdsa_sig,
                               BN_bin2bn(sig_buf, sig_buf_bytes / 2, NULL),
                               BN_bin2bn(sig_buf + sig_buf_bytes / 2,
                                         sig_buf_bytes / 2, NULL)) != 1)
            {
                ECDSA_SIG_free(ecdsa_sig);
                EVP_PKEY_CTX_free(verify_ctx);
                OPENSSL_free(hash);
                return CAL_CRYPTO_API_ERROR;
            }
            ecdsa_der_size = i2d_ECDSA_SIG(ecdsa_sig, &ecdsa_der);
            if (0 == ecdsa_der_size)
            {
                ECDSA_SIG_free(ecdsa_sig);
                EVP_PKEY_CTX_free(verify_ctx);
                OPENSSL_free(hash);
                return CAL_CRYPTO_API_ERROR;
            }

            if (EVP_PKEY_verify(verify_ctx, ecdsa_der, ecdsa_der_size,
                                    hash, hash_bytes) != 1)
            {
                ECDSA_SIG_free(ecdsa_sig);
                EVP_PKEY_CTX_free(verify_ctx);
                OPENSSL_free(hash);
                return CAL_INVALID_SIGNATURE;
            }
            break;

        default:
            EVP_PKEY_CTX_free(verify_ctx);
            OPENSSL_free(hash);
            return CAL_INVALID_ARGUMENT;
    }

    EVP_PKEY_CTX_free(verify_ctx);
    OPENSSL_free(hash);

    return CAL_SUCCESS;
}

/*--------------------------
  get_param_octet_string
---------------------------*/
int get_param_octet_string(const EVP_PKEY *key, const char *param_name,
                           uint8_t **buf, size_t *buf_len)
{
    if (key == NULL || param_name == NULL || buf == NULL || buf_len == NULL)
    {
        return -1;
    }

    *buf = NULL;
    *buf_len = 0;

    if (EVP_PKEY_get_octet_string_param(key, param_name, NULL, 0, buf_len) != 1)
    {
        return -1;
    }

    *buf = malloc(*buf_len);
    if (*buf == NULL)
    {
        return -1;
    }

    if (EVP_PKEY_get_octet_string_param(key, param_name, *buf, *buf_len,
                                        buf_len) != 1)
    {
        free(*buf);
        *buf = NULL;
        return -1;
    }

    return 0;
}

/*--------------------------
  is_ca_certificate
---------------------------*/
int is_ca_certificate(const char *cert_path)
{
    X509 *cert = NULL;
    int is_ca = -1;

    cert = read_certificate(cert_path);
    if (cert)
    {
        is_ca = (X509_check_ca(cert) == X509_CA_CERT);
        X509_free(cert);
    }

    return is_ca;
}

/*--------------------------
  is_pqc_certificate
---------------------------*/
int is_pqc_certificate(const char *cert_path)
{
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    int is_pqc = -1;

    cert = read_certificate(cert_path);
    if (cert)
    {
        pkey = X509_get_pubkey(cert);
        if (!pkey)
        {
            X509_free(cert);
            return is_pqc;
        }
        if (IS_PQC(EVP_PKEY_get0_type_name(pkey)))
        {
            is_pqc = 1;
        }
        else
        {
            is_pqc = 0;
        }
        EVP_PKEY_free(pkey);
        X509_free(cert);
    }

    return is_pqc;
}

/*--------------------------
  is_hybrid_certificate
---------------------------*/
int is_hybrid_certificate(const char *cert_path)
{
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    int is_hybrid = -1;

    cert = read_certificate(cert_path);
    if (cert)
    {
        pkey = X509_get_pubkey(cert);
        if (!pkey)
        {
            X509_free(cert);
            return is_hybrid;
        }
        if (IS_HYBRID(EVP_PKEY_get0_type_name(pkey)))
        {
            is_hybrid = 1;
        }
        else
        {
            is_hybrid = 0;
        }
        EVP_PKEY_free(pkey);
        X509_free(cert);
    }

    return is_hybrid;
}

/*--------------------------
  create_evp_key_from_bytes
---------------------------*/
EVP_PKEY *create_evp_key_from_bytes(OSSL_LIB_CTX *libctx,
                                    const unsigned char *pubkey_bytes,
                                    size_t pubkey_len,
                                    const unsigned char *privkey_bytes,
                                    size_t privkey_len, const char *alg_name)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    const char *openssl_alg_name = NULL;
    OSSL_PARAM params[5] = {0};
    int param_idx = 0;
    const unsigned char *p = privkey_bytes;
    size_t modulus_len = 0;
    size_t exponent_len = 0;

    if (privkey_bytes != NULL && privkey_len > 0)
    {
        if (!IS_PQC(alg_name))
        {
            pkey = d2i_AutoPrivateKey_ex(NULL, &p, privkey_len, libctx, NULL);
            if (!pkey)
            {
                fprintf(stderr,
                        "Error creating private key from provided data");
                ERR_print_errors_fp(stderr);
            }

            return pkey;
        }
    }

    if (strncmp(alg_name, "rsa", 3) == 0)
    {
        openssl_alg_name = "RSA";
        exponent_len = 3; /* Common public exponent length */
        modulus_len = pubkey_len - exponent_len;

        if (pubkey_bytes && pubkey_len > 0)
        {
            params[param_idx++] = OSSL_PARAM_construct_BN(
                OSSL_PKEY_PARAM_RSA_N, (void *) pubkey_bytes, modulus_len);
            params[param_idx++] = OSSL_PARAM_construct_BN(
                OSSL_PKEY_PARAM_RSA_E, (void *) pubkey_bytes + modulus_len,
                exponent_len);
        }
    }
    else if (strcmp(alg_name, "p256") == 0)
    {
        openssl_alg_name = "EC";
        params[param_idx++] = OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
        if (pubkey_bytes && pubkey_len > 0)
        {
            params[param_idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_PKEY_PARAM_PUB_KEY, (void *) pubkey_bytes, pubkey_len);
        }
    }
    else if (strcmp(alg_name, "p384") == 0)
    {
        openssl_alg_name = "EC";
        params[param_idx++] = OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_GROUP_NAME, "secp384r1", 0);
        if (pubkey_bytes && pubkey_len > 0)
        {
            params[param_idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_PKEY_PARAM_PUB_KEY, (void *) pubkey_bytes, pubkey_len);
        }
    }
    else if (strcmp(alg_name, "p521") == 0)
    {
        openssl_alg_name = "EC";
        params[param_idx++] = OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_GROUP_NAME, "secp521r1", 0);
        if (pubkey_bytes && pubkey_len > 0)
        {
            params[param_idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_PKEY_PARAM_PUB_KEY, (void *) pubkey_bytes, pubkey_len);
        }
    }
    else if (IS_PQC(alg_name))
    {
        openssl_alg_name = alg_name;
        if (pubkey_bytes && pubkey_len > 0)
        {
            params[param_idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_PKEY_PARAM_PUB_KEY, (void *) pubkey_bytes, pubkey_len);
        }

        if (privkey_bytes && privkey_len > 0)
        {
            params[param_idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_PKEY_PARAM_PRIV_KEY, (void *) privkey_bytes, privkey_len);
        }
    }
    else
    {
        fprintf(stderr, "Unsupported algorithm name: %s\n", alg_name);
        return NULL;
    }

    params[param_idx] = OSSL_PARAM_construct_end();

    /* Create a new EVP_PKEY_CTX for the specified algorithm */
    ctx = EVP_PKEY_CTX_new_from_name(libctx, openssl_alg_name, NULL);
    if (!ctx)
    {
        fprintf(stderr, "Error creating EVP_PKEY_CTX for %s\n",
                openssl_alg_name);
        return NULL;
    }

    /* Initialize the key generation context */
    if (EVP_PKEY_fromdata_init(ctx) <= 0)
    {
        fprintf(stderr, "Error initializing fromdata context\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /* Generate the key from raw bytes */
    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
    {
        fprintf(stderr, "Error generating key from raw bytes\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);

    return pkey;
}

/*--------------------------
  partition_hybrid_key
---------------------------*/
int partition_hybrid_key(OSSL_LIB_CTX *libctx, const EVP_PKEY *hybrid_key,
                         EVP_PKEY **classical_key, EVP_PKEY **pqc_key)
{
    uint8_t *classical_pubkey =
        NULL; /**< Public key of the classical part of an hybrid key */
    size_t classical_pubkey_size =
        0; /**< Size of the classical part of an hybrid key */
    uint8_t *pqc_pubkey =
        NULL; /**< Public key of the quantum-resistant part of an hybrid key */
    size_t pqc_pubkey_size =
        0; /**< Size of the quantum-resistant part of an hybrid key */
    uint8_t *classical_privkey = NULL; /**< Private key of the classical part of
                                          an hybrid key (if available) */
    size_t classical_privkey_size =
        0; /**< Size of the classical part of an hybrid key */
    uint8_t *pqc_privkey = NULL; /**< Private key of the quantum-resistant part
                                    of an hybrid key (if available) */
    size_t pqc_privkey_size =
        0; /**< Size of the quantum-resistant part of an hybrid key */
    EVP_PKEY *classical_evp_pkey =
        NULL; /**< EVP key of the classical part of an hybrid key */
    EVP_PKEY *pqc_evp_pkey =
        NULL; /**< EVP key of the quantum-resistant part of an hybrid key */
    char classical_alg_name[64] = {0}; /**< Name of the classical algorithm */
    char pqc_alg_name[64] = {0}; /**< Name of the quantum-resistant algorithm */
    int ret = 0;

    /* Get the public key of the classical part of the hybrid key */
    if (get_param_octet_string(hybrid_key, "hybrid_classical_pub",
                               &classical_pubkey, &classical_pubkey_size))
    {
        error("Cannot get the public key of the classical part of the hybrid "
              "key");
        return 0;
    }

    /* Get the public key of the quantum-resistant part of the hybrid key */
    if (get_param_octet_string(hybrid_key, "hybrid_pq_pub", &pqc_pubkey,
                               &pqc_pubkey_size))
    {
        free(classical_pubkey);
        error("Cannot get the public key of the quantum-resistant part of the "
              "hybrid key");
        return 0;
    }

    /* Get the private key of the classical part of the hybrid key (if
     * available) */
    if (get_param_octet_string(hybrid_key, "hybrid_classical_priv",
                               &classical_privkey, &classical_privkey_size))
    {
        /* No private key available, continue with only public key */
        classical_privkey = NULL;
        classical_privkey_size = 0;
    }

    /* Get the private key of the quantum-resistant part of the hybrid key (if
     * available) */
    if (get_param_octet_string(hybrid_key, "hybrid_pq_priv", &pqc_privkey,
                               &pqc_privkey_size))
    {
        /* No private key available, continue with only public key */
        pqc_privkey = NULL;
        pqc_privkey_size = 0;
    }

    /* Extract the classical algorithm name prefix */
    EXTRACT_CLASSICAL_ALGO(EVP_PKEY_get0_type_name(hybrid_key),
                           classical_alg_name);

    /* Create EVP_PKEY from the classical key raw bytes */
    classical_evp_pkey = create_evp_key_from_bytes(
        libctx, classical_pubkey, classical_pubkey_size, classical_privkey,
        classical_privkey_size, classical_alg_name);
    if (!classical_evp_pkey)
    {
        free(classical_pubkey);
        free(pqc_pubkey);
        free(classical_privkey);
        free(pqc_privkey);
        error("Failed to create EVP_PKEY for classical algorithm");
        return 0;
    }

    /* Extract the quantum-resistant algorithm name prefix */
    EXTRACT_PQC_ALGO(EVP_PKEY_get0_type_name(hybrid_key), pqc_alg_name);

    /* Create EVP_PKEY from the quantum-resistant key raw bytes */
    pqc_evp_pkey =
        create_evp_key_from_bytes(libctx, pqc_pubkey, pqc_pubkey_size,
                                  pqc_privkey, pqc_privkey_size, pqc_alg_name);
    if (!pqc_evp_pkey)
    {
        free(classical_pubkey);
        free(pqc_pubkey);
        free(classical_privkey);
        free(pqc_privkey);
        EVP_PKEY_free(classical_evp_pkey);
        error("Failed to create EVP_PKEY for quantum-resistant algorithm");
        return 0;
    }

    free(classical_pubkey);
    free(pqc_pubkey);
    free(classical_privkey);
    free(pqc_privkey);

    *classical_key = classical_evp_pkey;
    *pqc_key = pqc_evp_pkey;

    ret = 1;

    return ret;
}

/*--------------------------
  get_signature_size
---------------------------*/
int get_signature_size(const EVP_PKEY *pkey, size_t *sig0_size,
                       size_t *sig1_size)
{
    int ret = 0;
    int key_id = -1;

    if (!pkey || !sig0_size)
    {
        error("Invalid arguments");
        return ret;
    }

    key_id = EVP_PKEY_id(pkey);

    if (key_id == EVP_PKEY_RSA || key_id == EVP_PKEY_RSA_PSS)
    {
        *sig0_size = EVP_PKEY_size(pkey);
    }
    else if (key_id == EVP_PKEY_EC)
    {
        /* The EVP_PKEY_size() output includes the DER encoding */
        *sig0_size = (EVP_PKEY_bits(pkey) >> 3) * 2;
        if (EVP_PKEY_bits(pkey) & 0x7)
        {
            *sig0_size += 2; /* Valid for P-521 */
        }
    }
#if CST_WITH_PQC
    else if (IS_PQC(EVP_PKEY_get0_type_name(pkey)))
    {
        *sig0_size = EVP_PKEY_size(pkey);
    }
    else if (IS_HYBRID(EVP_PKEY_get0_type_name(pkey)))
    {
        EVP_PKEY *classical_key = NULL;
        EVP_PKEY *pqc_key = NULL;

        if (!sig1_size)
        {
            error("Invalid arguments");
            return ret;
        }

        if (partition_hybrid_key(get_libctx(), pkey, &classical_key,
                                 &pqc_key) != 1)
        {
            error("Can't extract classical and quantum-resistant keys from the "
                  "given hybrid key");
        }
        /* Classical algorithm signature size */
        switch (EVP_PKEY_id(classical_key))
        {
            case EVP_PKEY_RSA:
            case EVP_PKEY_RSA_PSS:
                *sig0_size = EVP_PKEY_size(classical_key);
                break;
            case EVP_PKEY_EC:
                *sig0_size = (EVP_PKEY_bits(classical_key) >> 3) * 2;
                *sig0_size += (EVP_PKEY_bits(classical_key) & 0x7)
                                  ? 2
                                  : 0; /* Valid for P-521 */
                break;
        }

        /* Quantum-resistant algorithm signature size */
        *sig1_size = EVP_PKEY_size(pqc_key);

        EVP_PKEY_free(classical_key);
        EVP_PKEY_free(pqc_key);
    }
#endif

    ret = 1;

    return ret;
}

/*--------------------------------------
  get_certificate_serial_number_length
---------------------------------------*/

int get_certificate_serial_number_length(X509 *cert)
{
    ASN1_INTEGER *serial_number = NULL;
    uint8_t *serial_bytes = NULL;
    int serial_length = 0;

    if (!cert)
    {
        return -1;
    }

    /* Get the serial number as ASN1_INTEGER */
    serial_number = X509_get_serialNumber(cert);

    if (!serial_number)
    {
        return -1;
    }

    /* Get the raw data of the serial number */
    serial_bytes = serial_number->data;
    serial_length = serial_number->length;

    /* Check if the serial number is negative (MSB of first byte is set) */
    if (serial_bytes[0] & 0x80)
    {
        /* Add 1 to the length if the serial number is negative */
        serial_length += 1;
    }

    return serial_length;
}

/*--------------------------
  print_license
---------------------------*/

void print_license(void)
{
    printf("\n\nNXP License Information:\n");
    printf("----------------------------------\n");
    printf("Copyright (c) Freescale Semiconductor, Inc. 2011, 2012. All rights reserved.\n");
    printf("Copyright 2018-2023 NXP\n\n");
    printf("This software is under license from NXP\n");
    printf("By using this software you agree to the license terms provided\n");
    printf("at the time this release was downloaded from www.nxp.com\n");
    printf("\nOpenssl, SSLeay and Apache License 2.0 Information:\n");
    printf("---------------------------------------\n");
    printf("This product includes software developed by the OpenSSL Project\n");
    printf("for use in the OpenSSL Toolkit (http://www.openssl.org/)\n\n");
    printf("This product includes cryptographic software written by\n");
    printf("Eric Young (eay@cryptsoft.com)\n");
    printf("This product includes cryptographic software written by\n");
    printf("Brian Gladman, Worcester, UK\n");
    printf("\nThe following is the full license text for OpenSSL, SSLeay and and Apache 2.0\n");
    printf("and Brian Gladman:\n\n");
    printf("OpenSSL License\n");
    printf("---------------\n\n");
    printf("/* ====================================================================\n");
    printf(" * Copyright (c) 1998-2018 The OpenSSL Project.  All rights reserved.\n");
    printf(" *\n");
    printf(" * Redistribution and use in source and binary forms, with or without\n");
    printf(" * modification, are permitted provided that the following conditions\n");
    printf(" * are met:\n");
    printf(" *\n");
    printf(" * 1. Redistributions of source code must retain the above copyright\n");
    printf(" *    notice, this list of conditions and the following disclaimer.\n");
    printf(" *\n");
    printf(" * 2. Redistributions in binary form must reproduce the above copyright\n");
    printf(" *    notice, this list of conditions and the following disclaimer in\n");
    printf(" *    the documentation and/or other materials provided with the\n");
    printf(" *    distribution.\n");
    printf(" *\n");
    printf(" * 3. All advertising materials mentioning features or use of this\n");
    printf(" *    software must display the following acknowledgment:\n");
    printf(" *    \"This product includes software developed by the OpenSSL Project\n");
    printf(" *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)\"\n");
    printf(" *\n");
    printf(" * 4. The names \"OpenSSL Toolkit\" and \"OpenSSL Project\" must not be used to\n");
    printf(" *    endorse or promote products derived from this software without\n");
    printf(" *    prior written permission. For written permission, please contact\n");
    printf(" *    openssl-core@openssl.org.\n");
    printf(" *\n");
    printf(" * 5. Products derived from this software may not be called \"OpenSSL\"\n");
    printf(" *    nor may \"OpenSSL\" appear in their names without prior written\n");
    printf(" *    permission of the OpenSSL Project.\n");
    printf(" *\n");
    printf(" * 6. Redistributions of any form whatsoever must retain the following\n");
    printf(" *    acknowledgment:\n");
    printf(" *    \"This product includes software developed by the OpenSSL Project\n");
    printf(" *    for use in the OpenSSL Toolkit (http://www.openssl.org/)\"\n");
    printf(" *\n");
    printf(" * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY\n");
    printf(" * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE\n");
    printf(" * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR\n");
    printf(" * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR\n");
    printf(" * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,\n");
    printf(" * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT\n");
    printf(" * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;\n");
    printf(" * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)\n");
    printf(" * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,\n");
    printf(" * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)\n");
    printf(" * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED\n");
    printf(" * OF THE POSSIBILITY OF SUCH DAMAGE.\n");
    printf(" * ====================================================================\n");
    printf(" *\n");
    printf(" * This product includes cryptographic software written by Eric Young\n");
    printf(" * (eay@cryptsoft.com).  This product includes software written by Tim\n");
    printf(" * Hudson (tjh@cryptsoft.com).\n");
    printf(" *\n");
    printf(" */\n\n");
    printf("Original SSLeay License\n");
    printf("-----------------------\n\n");
    printf("/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)\n");
    printf(" * All rights reserved.\n");
    printf(" *\n");
    printf(" * This package is an SSL implementation written\n");
    printf(" * by Eric Young (eay@cryptsoft.com).\n");
    printf(" * The implementation was written so as to conform with Netscapes SSL.\n");
    printf(" *\n");
    printf(" * This library is free for commercial and non-commercial use as long as\n");
    printf(" * the following conditions are aheared to.  The following conditions\n");
    printf(" * apply to all code found in this distribution, be it the RC4, RSA,\n");
    printf(" * lhash, DES, etc., code; not just the SSL code.  The SSL documentation\n");
    printf(" * included with this distribution is covered by the same copyright terms\n");
    printf(" * except that the holder is Tim Hudson (tjh@cryptsoft.com).\n");
    printf(" *\n");
    printf(" * Copyright remains Eric Young's, and as such any Copyright notices in\n");
    printf(" * the code are not to be removed.\n");
    printf(" * If this package is used in a product, Eric Young should be given attribution\n");
    printf(" * as the author of the parts of the library used.\n");
    printf(" * This can be in the form of a textual message at program startup or\n");
    printf(" * in documentation (online or textual) provided with the package.\n");
    printf(" *\n");
    printf(" * Redistribution and use in source and binary forms, with or without\n");
    printf(" * modification, are permitted provided that the following conditions\n");
    printf(" * are met:\n");
    printf(" * 1. Redistributions of source code must retain the copyright\n");
    printf(" *    notice, this list of conditions and the following disclaimer.\n");
    printf(" * 2. Redistributions in binary form must reproduce the above copyright\n");
    printf(" *    notice, this list of conditions and the following disclaimer in the\n");
    printf(" *    documentation and/or other materials provided with the distribution.\n");
    printf(" * 3. All advertising materials mentioning features or use of this software\n");
    printf(" *    must display the following acknowledgement:\n");
    printf(" *    \"This product includes cryptographic software written by\n");
    printf(" *     Eric Young (eay@cryptsoft.com)\"\n");
    printf(" *    The word 'cryptographic' can be left out if the rouines from the library\n");
    printf(" *    being used are not cryptographic related :-).\n");
    printf(" * 4. If you include any Windows specific code (or a derivative thereof) from\n");
    printf(" *    the apps directory (application code) you must include an acknowledgement:\n");
    printf(" *    \"This product includes software written by Tim Hudson (tjh@cryptsoft.com)\"\n");
    printf(" *\n");
    printf(" * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND\n");
    printf(" * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE\n");
    printf(" * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE\n");
    printf(" * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE\n");
    printf(" * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL\n");
    printf(" * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS\n");
    printf(" * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)\n");
    printf(" * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT\n");
    printf(" * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY\n");
    printf(" * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF\n");
    printf(" * SUCH DAMAGE.\n");
    printf(" *\n");
    printf(" * The licence and distribution terms for any publically available version or\n");
    printf(" * derivative of this code cannot be changed.  i.e. this code cannot simply be\n");
    printf(" * copied and put under another distribution licence\n");
    printf(" * [including the GNU Public Licence.]\n");
    printf(" */\n\n");
    printf("Apache License\n");
    printf("Version 2.0\n");
    printf("-----------------------\n\n");
    printf("   1. Definitions.\n");
    printf("\n");
    printf("      \"License\" shall mean the terms and conditions for use, reproduction,\n");
    printf("      and distribution as defined by Sections 1 through 9 of this document.\n");
    printf("\n");
    printf("      \"Licensor\" shall mean the copyright owner or entity authorized by\n");
    printf("      the copyright owner that is granting the License.\n");
    printf("\n");
    printf("      \"Legal Entity\" shall mean the union of the acting entity and all\n");
    printf("      other entities that control, are controlled by, or are under common\n");
    printf("      control with that entity. For the purposes of this definition,\n");
    printf("      \"control\" means (i) the power, direct or indirect, to cause the\n");
    printf("      direction or management of such entity, whether by contract or\n");
    printf("      otherwise, or (ii) ownership of fifty percent (50%%) or more of the\n");
    printf("      outstanding shares, or (iii) beneficial ownership of such entity.\n");
    printf("\n");
    printf("      \"You\" (or \"Your\") shall mean an individual or Legal Entity\n");
    printf("      exercising permissions granted by this License.\n");
    printf("\n");
    printf("      \"Source\" form shall mean the preferred form for making modifications,\n");
    printf("      including but not limited to software source code, documentation\n");
    printf("      source, and configuration files.\n");
    printf("\n");
    printf("      \"Object\" form shall mean any form resulting from mechanical\n");
    printf("      transformation or translation of a Source form, including but\n");
    printf("      not limited to compiled object code, generated documentation,\n");
    printf("      and conversions to other media types.\n");
    printf("\n");
    printf("      \"Work\" shall mean the work of authorship, whether in Source or\n");
    printf("      Object form, made available under the License, as indicated by a\n");
    printf("      copyright notice that is included in or attached to the work\n");
    printf("      (an example is provided in the Appendix below).\n");
    printf("\n");
    printf("      \"Derivative Works\" shall mean any work, whether in Source or Object\n");
    printf("      form, that is based on (or derived from) the Work and for which the\n");
    printf("      editorial revisions, annotations, elaborations, or other modifications\n");
    printf("      represent, as a whole, an original work of authorship. For the purposes\n");
    printf("      of this License, Derivative Works shall not include works that remain\n");
    printf("      separable from, or merely link (or bind by name) to the interfaces of,\n");
    printf("      the Work and Derivative Works thereof.\n");
    printf("\n");
    printf("      \"Contribution\" shall mean any work of authorship, including\n");
    printf("      the original version of the Work and any modifications or additions\n");
    printf("      to that Work or Derivative Works thereof, that is intentionally\n");
    printf("      submitted to Licensor for inclusion in the Work by the copyright owner\n");
    printf("      or by an individual or Legal Entity authorized to submit on behalf of\n");
    printf("      the copyright owner. For the purposes of this definition, \"submitted\"\n");
    printf("      means any form of electronic, verbal, or written communication sent\n");
    printf("      to the Licensor or its representatives, including but not limited to\n");
    printf("      communication on electronic mailing lists, source code control systems,\n");
    printf("      and issue tracking systems that are managed by, or on behalf of, the\n");
    printf("      Licensor for the purpose of discussing and improving the Work, but\n");
    printf("      excluding communication that is conspicuously marked or otherwise\n");
    printf("      designated in writing by the copyright owner as \"Not a Contribution.\"\n");
    printf("\n");
    printf("      \"Contributor\" shall mean Licensor and any individual or Legal Entity\n");
    printf("      on behalf of whom a Contribution has been received by Licensor and\n");
    printf("      subsequently incorporated within the Work.\n");
    printf("\n");
    printf("   2. Grant of Copyright License. Subject to the terms and conditions of\n");
    printf("      this License, each Contributor hereby grants to You a perpetual,\n");
    printf("      worldwide, non-exclusive, no-charge, royalty-free, irrevocable\n");
    printf("      copyright license to reproduce, prepare Derivative Works of,\n");
    printf("      publicly display, publicly perform, sublicense, and distribute the\n");
    printf("      Work and such Derivative Works in Source or Object form.\n");
    printf("\n");
    printf("   3. Grant of Patent License. Subject to the terms and conditions of\n");
    printf("      this License, each Contributor hereby grants to You a perpetual,\n");
    printf("      worldwide, non-exclusive, no-charge, royalty-free, irrevocable\n");
    printf("      (except as stated in this section) patent license to make, have made,\n");
    printf("      use, offer to sell, sell, import, and otherwise transfer the Work,\n");
    printf("      where such license applies only to those patent claims licensable\n");
    printf("      by such Contributor that are necessarily infringed by their\n");
    printf("      Contribution(s) alone or by combination of their Contribution(s)\n");
    printf("      with the Work to which such Contribution(s) was submitted. If You\n");
    printf("      institute patent litigation against any entity (including a\n");
    printf("      cross-claim or counterclaim in a lawsuit) alleging that the Work\n");
    printf("      or a Contribution incorporated within the Work constitutes direct\n");
    printf("      or contributory patent infringement, then any patent licenses\n");
    printf("      granted to You under this License for that Work shall terminate\n");
    printf("      as of the date such litigation is filed.\n");
    printf("\n");
    printf("   4. Redistribution. You may reproduce and distribute copies of the\n");
    printf("      Work or Derivative Works thereof in any medium, with or without\n");
    printf("      modifications, and in Source or Object form, provided that You\n");
    printf("      meet the following conditions:\n");
    printf("\n");
    printf("      (a) You must give any other recipients of the Work or\n");
    printf("          Derivative Works a copy of this License; and\n");
    printf("\n");
    printf("      (b) You must cause any modified files to carry prominent notices\n");
    printf("          stating that You changed the files; and\n");
    printf("\n");
    printf("      (c) You must retain, in the Source form of any Derivative Works\n");
    printf("          that You distribute, all copyright, patent, trademark, and\n");
    printf("          attribution notices from the Source form of the Work,\n");
    printf("          excluding those notices that do not pertain to any part of\n");
    printf("          the Derivative Works; and\n");
    printf("\n");
    printf("      (d) If the Work includes a \"NOTICE\" text file as part of its\n");
    printf("          distribution, then any Derivative Works that You distribute must\n");
    printf("          include a readable copy of the attribution notices contained\n");
    printf("          within such NOTICE file, excluding those notices that do not\n");
    printf("          pertain to any part of the Derivative Works, in at least one\n");
    printf("          of the following places: within a NOTICE text file distributed\n");
    printf("          as part of the Derivative Works; within the Source form or\n");
    printf("          documentation, if provided along with the Derivative Works; or,\n");
    printf("          within a display generated by the Derivative Works, if and\n");
    printf("          wherever such third-party notices normally appear. The contents\n");
    printf("          of the NOTICE file are for informational purposes only and\n");
    printf("          do not modify the License. You may add Your own attribution\n");
    printf("          notices within Derivative Works that You distribute, alongside\n");
    printf("          or as an addendum to the NOTICE text from the Work, provided\n");
    printf("          that such additional attribution notices cannot be construed\n");
    printf("          as modifying the License.\n");
    printf("\n");
    printf("      You may add Your own copyright statement to Your modifications and\n");
    printf("      may provide additional or different license terms and conditions\n");
    printf("      for use, reproduction, or distribution of Your modifications, or\n");
    printf("      for any such Derivative Works as a whole, provided Your use,\n");
    printf("      reproduction, and distribution of the Work otherwise complies with\n");
    printf("      the conditions stated in this License.\n");
    printf("\n");
    printf("   5. Submission of Contributions. Unless You explicitly state otherwise,\n");
    printf("      any Contribution intentionally submitted for inclusion in the Work\n");
    printf("      by You to the Licensor shall be under the terms and conditions of\n");
    printf("      this License, without any additional terms or conditions.\n");
    printf("      Notwithstanding the above, nothing herein shall supersede or modify\n");
    printf("      the terms of any separate license agreement you may have executed\n");
    printf("      with Licensor regarding such Contributions.\n");
    printf("\n");
    printf("   6. Trademarks. This License does not grant permission to use the trade\n");
    printf("      names, trademarks, service marks, or product names of the Licensor,\n");
    printf("      except as required for reasonable and customary use in describing the\n");
    printf("      origin of the Work and reproducing the content of the NOTICE file.\n");
    printf("\n");
    printf("   7. Disclaimer of Warranty. Unless required by applicable law or\n");
    printf("      agreed to in writing, Licensor provides the Work (and each\n");
    printf("      Contributor provides its Contributions) on an \"AS IS\" BASIS,\n");
    printf("      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or\n");
    printf("      implied, including, without limitation, any warranties or conditions\n");
    printf("      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A\n");
    printf("      PARTICULAR PURPOSE. You are solely responsible for determining the\n");
    printf("      appropriateness of using or redistributing the Work and assume any\n");
    printf("      risks associated with Your exercise of permissions under this License.\n");
    printf("\n");
    printf("   8. Limitation of Liability. In no event and under no legal theory,\n");
    printf("      whether in tort (including negligence), contract, or otherwise,\n");
    printf("      unless required by applicable law (such as deliberate and grossly\n");
    printf("      negligent acts) or agreed to in writing, shall any Contributor be\n");
    printf("      liable to You for damages, including any direct, indirect, special,\n");
    printf("      incidental, or consequential damages of any character arising as a\n");
    printf("      result of this License or out of the use or inability to use the\n");
    printf("      Work (including but not limited to damages for loss of goodwill,\n");
    printf("      work stoppage, computer failure or malfunction, or any and all\n");
    printf("      other commercial damages or losses), even if such Contributor\n");
    printf("      has been advised of the possibility of such damages.\n");
    printf("\n");
    printf("   9. Accepting Warranty or Additional Liability. While redistributing\n");
    printf("      the Work or Derivative Works thereof, You may choose to offer,\n");
    printf("      and charge a fee for, acceptance of support, warranty, indemnity,\n");
    printf("      or other liability obligations and/or rights consistent with this\n");
    printf("      License. However, in accepting such obligations, You may act only\n");
    printf("      on Your own behalf and on Your sole responsibility, not on behalf\n");
    printf("      of any other Contributor, and only if You agree to indemnify,\n");
    printf("      defend, and hold each Contributor harmless for any liability\n");
    printf("      incurred by, or claims asserted against, such Contributor by reason\n");
    printf("      of your accepting any such warranty or additional liability.\n");
    printf("\n");
    printf("   END OF TERMS AND CONDITIONS\n");
    printf("\n\n");
    printf("Original Brian Gladman License\n");
    printf("------------------------------\n\n");
    printf("  /*\n");
    printf("  ---------------------------------------------------------------------------\n");
    printf("  Copyright (c) 1998-2008, Brian Gladman, Worcester, UK. All rights reserved.\n");
    printf(" \n");
    printf("  LICENSE TERMS\n");
    printf(" \n");
    printf("  The redistribution and use of this software (with or without changes)\n");
    printf("  is allowed without the payment of fees or royalties provided that:\n");
    printf(" \n");
    printf("   1. source code distributions include the above copyright notice, this\n");
    printf("      list of conditions and the following disclaimer;\n");
    printf(" \n");
    printf("   2. binary distributions include the above copyright notice, this list\n");
    printf("      of conditions and the following disclaimer in their documentation;\n");
    printf(" \n");
    printf("   3. the name of the copyright holder is not used to endorse products\n");
    printf("      built using this software without specific written permission.\n");
    printf(" \n");
    printf("  DISCLAIMER\n");
    printf(" \n");
    printf("  This software is provided 'as is' with no explicit or implied warranties\n");
    printf("  in respect of its properties, including, but not limited to, correctness\n");
    printf("  and/or fitness for purpose.\n");
    printf("  ---------------------------------------------------------------------------\n");
    printf("  Issue Date: 20/12/2007\n");
    printf(" */\n\n");
}
