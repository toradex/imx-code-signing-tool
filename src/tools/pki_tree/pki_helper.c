// SPDX-License-Identifier: BSD-3-Clause
/*
 * (c) Freescale Semiconductor, Inc. 2011, 2012. All rights reserved.
 * Copyright 2018-2020, 2022-2024 NXP
 */

/*===========================================================================*/
/**
    @file    pki_helper.c
@brief   Provide helper functions to ease generating basic PKI tree for
             HAB and AHAB.
 */

/*===========================================================================
                                INCLUDES
=============================================================================*/

#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include "openssl_helper.h"
#include "ssl_backend.h"
#include "pki_helper.h"

/*============================================================================
                           GLOBAL VARIABLE DECLARATIONS
=============================================================================*/

read_certificate_fptr read_certificate = ssl_read_certificate;

/*===========================================================================
                                EXTERNS
=============================================================================*/

extern void handle_errors();

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
  handle_errors
---------------------------*/
void handle_errors()
{
    ERR_print_errors_fp(stderr);
    exit(1);
}

/*--------------------------
  dash_to_underscore
---------------------------*/
static char *dash_to_underscore(const char *input)
{
    char *p = NULL;
    char *fmt = NULL;

    fmt = strdup(input);
    if (fmt == NULL)
    {
        return NULL;
    }
    /* Replace '-' with '_' in the copied string */
    for (p = fmt; *p != '\0'; p++)
    {
        if (*p == '-')
        {
            *p = '_';
        }
    }

    return fmt;
}

/*--------------------------
  format_key_cert_names
---------------------------*/
void format_key_cert_names(const char *kt, const char *kl, const char *da,
                           const char *key_type, int index, int is_ca, char *key_name,
                           char *crt_name, char *subj_name)
{
    const char *prefix = NULL;
    const char *suffix = NULL;
    const char *ca_usr = is_ca ? "ca" : "usr";
    char cn[24] = {0};
    char *fmt_da = NULL;

    if (strcmp(key_type, "ca") == 0)
    {
        prefix = "CA";
    }
    else if (strcmp(key_type, "srk") == 0)
    {
        prefix = "SRK";
    }
    else if (strcmp(key_type, "sgk") == 0)
    {
        prefix = "SGK";
    }
    else if (strcmp(key_type, "csf") == 0)
    {
        prefix = "CSF";
    }
    else if (strcmp(key_type, "img") == 0)
    {
        prefix = "IMG";
    }
    else
    {
        fprintf(stderr, "Invalid key role");
        exit(1);
    }

    if (strcmp(kt, "rsa") == 0 || strcmp(kt, "rsa-pss") == 0)
    {
        suffix = "65537_v3";
        snprintf(cn, sizeof(cn), "%s", kl);
    }
    else if ((strcmp(kt, "ecc") == 0) || (strcmp(kt, "ec") == 0))
    {
        suffix = "v3";
        if (strcmp(kl, "p256") == 0)
        {
            snprintf(cn, sizeof(cn), "prime256v1");
        }
        else if (strcmp(kl, "p384") == 0)
        {
            snprintf(cn, sizeof(cn), "secp384r1");
        }
        else if (strcmp(kl, "p521") == 0)
        {
            snprintf(cn, sizeof(cn), "secp521r1");
        }
        else
        {
            fprintf(stderr, "Invalid ECC key length\n");
            exit(1);
        }
    }
#if CST_WITH_PQC
    else if (strcmp(kt, "dilithium") == 0)
    {
        suffix = "v3";
        snprintf(cn, sizeof(cn), "%s%s", kt, kl);
    }
    else if (strcmp(kt, "ml-dsa") == 0)
    {
        suffix = "v3";
        snprintf(cn, sizeof(cn), "%s%s", "mldsa", kl);
    }
    else if (strcmp(kt, "hybrid") == 0)
    {
        suffix = "v3";
        snprintf(cn, sizeof(cn), "%s", kl);
    }
#endif
    else
    {
        fprintf(stderr, "Invalid key type\n");
        exit(1);
    }

    fmt_da = dash_to_underscore(da);
    if (!fmt_da)
    {
        fprintf(stderr, "Can't format digest algorithm name\n");
        exit(1);
    }

    if ((strcmp(key_type, "sgk") == 0) || (strcmp(key_type, "csf") == 0) ||
        (strcmp(key_type, "img") == 0))
    {
        snprintf(key_name, MAX_KEY_NAME_LENGTH, "%s%d_1_%s_%s_%s_%s_key",
                 prefix, index, fmt_da, cn, suffix, ca_usr);
        snprintf(crt_name, MAX_KEY_NAME_LENGTH, "%s%d_1_%s_%s_%s_%s_crt",
                 prefix, index, fmt_da, cn, suffix, ca_usr);
        snprintf(subj_name, MAX_KEY_NAME_LENGTH, "%s%d_1_%s_%s_%s_%s", prefix,
                 index, fmt_da, cn, suffix, ca_usr);
    }
    else
    {
        snprintf(key_name, MAX_KEY_NAME_LENGTH, "%s%d_%s_%s_%s_%s_key", prefix,
                 index, fmt_da, cn, suffix, ca_usr);
        snprintf(crt_name, MAX_KEY_NAME_LENGTH, "%s%d_%s_%s_%s_%s_crt", prefix,
                 index, fmt_da, cn, suffix, ca_usr);
        snprintf(subj_name, MAX_KEY_NAME_LENGTH, "%s%d_%s_%s_%s_%s", prefix,
                 index, fmt_da, cn, suffix, ca_usr);
    }

    free(fmt_da);
}

/*--------------------------
  generate_serial_file
---------------------------*/
void generate_serial_file(const char *serial_file)
{
    FILE *file = fopen(serial_file, "r");
    if (!file)
    {
        file = fopen(serial_file, "w");
        if (!file)
        {
            fprintf(stderr, "Error opening %s\n", serial_file);
            exit(1);
        }
        fprintf(file, "%s\n", SERIAL);
        fclose(file);
    }
    else
    {
        fclose(file);
    }
}

/*--------------------------
  read_serial
---------------------------*/
unsigned long read_serial(const char *serial_file)
{
    FILE *file = NULL;
    unsigned long serial = 0;

    file = fopen(serial_file, "r");
    if (!file)
    {
        fprintf(stderr, "Error: Unable to open file %s\n", serial_file);
        exit(EXIT_FAILURE);
    }

    if (fscanf(file, "%lu", &serial) != 1)
    {
        fprintf(stderr, "Error: Failed to read serial number from file %s\n",
                serial_file);
        fclose(file);
        exit(EXIT_FAILURE);
    }

    fclose(file);
    return serial;
}

/*--------------------------
  write_serial
---------------------------*/
void write_serial(const char *serial_file, unsigned long serial)
{
    FILE *file = fopen(serial_file, "w");
    if (!file)
    {
        fprintf(stderr, "Error opening %s\n", serial_file);
        exit(1);
    }
    fprintf(file, "%lu\n", serial);
    fclose(file);
}

/*--------------------------
  generate_key
---------------------------*/
EVP_PKEY *generate_key(const char *kt, const char *kl)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int keylen = 0;
    char ktkl[16] = {0};
    OSSL_LIB_CTX *libctx = get_libctx();

    if (strcmp(kt, "rsa") == 0 || strcmp(kt, "rsa-pss") == 0)
    {
        pctx = EVP_PKEY_CTX_new_from_name(libctx, kt, NULL);
        if (!pctx)
            handle_errors();
        keylen = atoi(kl);
        if (EVP_PKEY_keygen_init(pctx) <= 0)
            handle_errors();
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, keylen) <= 0)
            handle_errors();
    }
    else if ((strcmp(kt, "ec") == 0) || (strcmp(kt, "ecc") == 0))
    {
        pctx = EVP_PKEY_CTX_new_from_name(libctx, "ec", NULL);
        if (!pctx)
            handle_errors();
        if (EVP_PKEY_keygen_init(pctx) <= 0)
            handle_errors();
        if (strcmp(kl, "p256") == 0)
        {
            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
                    pctx, NID_X9_62_prime256v1) <= 0)
                handle_errors();
        }
        else if (strcmp(kl, "p384") == 0)
        {
            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp384r1) <=
                0)
                handle_errors();
        }
        else if (strcmp(kl, "p521") == 0)
        {
            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp521r1) <=
                0)
                handle_errors();
        }
        else
        {
            fprintf(stderr, "Unsupported EC key length\n");
            exit(1);
        }
    }
#if CST_WITH_PQC
    else if (strcmp(kt, "dilithium") == 0)
    {
        snprintf(ktkl, sizeof(ktkl), "%s%s", kt, kl);
        pctx = EVP_PKEY_CTX_new_from_name(libctx, ktkl, NULL);
        if (!pctx)
            handle_errors();
        if (EVP_PKEY_keygen_init(pctx) <= 0)
            handle_errors();
    }
    else if (strcmp(kt, "ml-dsa") == 0)
    {
        snprintf(ktkl, sizeof(ktkl), "%s%s", "mldsa", kl);
        pctx = EVP_PKEY_CTX_new_from_name(libctx, ktkl, NULL);
        if (!pctx)
            handle_errors();
        if (EVP_PKEY_keygen_init(pctx) <= 0)
            handle_errors();
    }
    else if (strcmp(kt, "hybrid") == 0)
    {
        pctx = EVP_PKEY_CTX_new_from_name(libctx, kl, NULL);
        if (!pctx)
            handle_errors();
        if (EVP_PKEY_keygen_init(pctx) <= 0)
            handle_errors();
    }
#endif
    else
    {
        fprintf(stderr, "Unsupported key type\n");
        exit(1);
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
        handle_errors();
    EVP_PKEY_CTX_free(pctx);

    return pkey;
}

/*--------------------------
  add_extension
---------------------------*/
static int add_extension(X509 *cert, int nid, char *value)
{
    X509_EXTENSION *ex = NULL;
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex)
    {
        return 0;
    }
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return 1;
}

/*--------------------------
  generate_certificate
---------------------------*/
X509 *generate_certificate(EVP_PKEY *pkey, const char *subj, int days,
                           const char *digest, EVP_PKEY *sign_pkey,
                           X509 *sign_cert, unsigned long serial, int is_ca)
{

    X509 *x509 = NULL;
    X509_NAME *name = NULL;
    OSSL_LIB_CTX *libctx = get_libctx();
    char normalized_digest[32] = {0};
    size_t xoflen = 0;
    OSSL_PARAM params[2] = {};
    int i = 0;

    /* Normalize algorithm name */
    if (strcmp(digest, "shake128-256") == 0)
    {
        strncpy(normalized_digest, "shake128", sizeof(normalized_digest) - 1);
        xoflen = HASH_BYTES_SHAKE128_256;
    }
    else if (strcmp(digest, "shake256-512") == 0)
    {
        strncpy(normalized_digest, "shake256", sizeof(normalized_digest) - 1);
        xoflen = HASH_BYTES_SHAKE256_512;
    }
    else
    {
        strncpy(normalized_digest, digest, sizeof(normalized_digest) - 1);
    }

    if (xoflen > 0)
    {
        params[i++] =
            OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_XOFLEN, &xoflen);
        params[i++] = OSSL_PARAM_construct_end();
    }

    x509 = X509_new();
    if (!x509)
        handle_errors();

    if (X509_set_version(x509, 3) != 1)
        handle_errors();

    ASN1_INTEGER_set(X509_get_serialNumber(x509), serial);

    if (X509_gmtime_adj(X509_get_notBefore(x509), 0) == NULL)
        handle_errors();
    if (X509_gmtime_adj(X509_get_notAfter(x509), (long) 60 * 60 * 24 * days) ==
        NULL)
        handle_errors();
    if (X509_set_pubkey(x509, pkey) != 1)
        handle_errors();

    name = X509_get_subject_name(x509);
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   (const unsigned char *) subj, -1, -1,
                                   0) != 1)
        handle_errors();
    if (sign_cert)
    {
        if (X509_set_issuer_name(x509, X509_get_subject_name(sign_cert)) != 1)
            handle_errors();
    }
    else
    {
        if (X509_set_issuer_name(x509, name) != 1)
            handle_errors();
    }

    if (is_ca)
    {
        if (!add_extension(x509, NID_basic_constraints, "critical,CA:TRUE"))
            handle_errors();
        if (!add_extension(x509, NID_key_usage, "keyCertSign"))
            handle_errors();
        if (!add_extension(x509, NID_subject_key_identifier, "hash"))
            handle_errors();
        if (!add_extension(x509, NID_authority_key_identifier,
                           "keyid:always,issuer:always"))
            handle_errors();
    }
    else
    {
        if (!add_extension(x509, NID_basic_constraints, "CA:FALSE"))
            handle_errors();
        if (!add_extension(x509, NID_key_usage,
                           "nonRepudiation,digitalSignature,keyEncipherment"))
            handle_errors();
        if (!add_extension(x509, NID_netscape_comment,
                           "OpenSSL Generated Certificate"))
            handle_errors();
        if (!add_extension(x509, NID_subject_key_identifier, "hash"))
            handle_errors();
        if (!add_extension(x509, NID_authority_key_identifier, "keyid,issuer"))
            handle_errors();
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        handle_errors();

    if (EVP_DigestSignInit_ex(mdctx, NULL, normalized_digest, libctx, NULL,
                              sign_pkey ? sign_pkey : pkey, params) <= 0)
        handle_errors();

    if (X509_sign_ctx(x509, mdctx) == 0)
        handle_errors();

    EVP_MD_CTX_free(mdctx);

    return x509;
}

/*--------------------------
  write_key_and_cert
---------------------------*/
void write_key_and_cert(EVP_PKEY *pkey, X509 *x509, const char *keyfile,
                        const char *certfile, const char *pass)
{
    FILE *pkey_file = fopen(keyfile, "wb");
    if (!pkey_file)
    {
        fprintf(stderr, "Error opening %s\n", keyfile);
        exit(1);
    }

    if (PEM_write_PrivateKey(pkey_file, pkey, pass ? EVP_des_ede3_cbc() : NULL,
                             (unsigned char *) pass, pass ? strlen(pass) : 0,
                             NULL, NULL) != 1)
    {
        handle_errors();
    }
    fclose(pkey_file);

    FILE *x509_file = fopen(certfile, "wb");
    if (!x509_file)
    {
        fprintf(stderr, "Error opening %s\n", certfile);
        exit(1);
    }

    if (PEM_write_X509(x509_file, x509) != 1)
        handle_errors();
    fclose(x509_file);
}

/*--------------------------
  write_der_key_and_cert
---------------------------*/
void write_der_key_and_cert(EVP_PKEY *pkey, X509 *x509, const char *keyfile,
                            const char *certfile)
{
    FILE *pkey_file = fopen(keyfile, "wb");
    if (!pkey_file)
    {
        fprintf(stderr, "Error opening %s\n", keyfile);
        exit(1);
    }

    if (i2d_PrivateKey_fp(pkey_file, pkey) != 1)
        handle_errors();
    fclose(pkey_file);

    FILE *x509_file = fopen(certfile, "wb");
    if (!x509_file)
    {
        fprintf(stderr, "Error opening %s\n", certfile);
        exit(1);
    }

    if (i2d_X509_fp(x509_file, x509) != 1)
        handle_errors();
    fclose(x509_file);
}

/*--------------------------
  generate_key_pass_file
---------------------------*/
void generate_key_pass_file(const char *key_pass_file)
{
    FILE *file = fopen(key_pass_file, "r");
    if (!file)
    {
        file = fopen(key_pass_file, "w");
        if (!file)
        {
            fprintf(stderr, "Error opening %s\n", key_pass_file);
            exit(1);
        }
        fprintf(file, "%s\n%s\n", KEY_PASS, KEY_PASS);
        fclose(file);
    }
    else
    {
        fclose(file);
    }
}

/*--------------------------
  read_key_pass
---------------------------*/
char *read_key_pass(const char *key_pass_file)
{
    FILE *file = fopen(key_pass_file, "r");
    char line[16];

    if (!file)
    {
        fprintf(stderr, "Error opening %s\n", key_pass_file);
        return NULL;
    }

    if (fgets(line, sizeof(line), file) == NULL)
    {
        fprintf(stderr, "Error reading %s\n", key_pass_file);
        fclose(file);
        return NULL;
    }
    fclose(file);

    size_t len = strcspn(line, "\n");
    line[len] = '\0';

    char *pass = malloc((len + 1) * sizeof(char));
    if (!pass)
    {
        fprintf(stderr, "Error alloacting memory\n");
        return NULL;
    }
    strcpy(pass, line);

    return pass;
}

/*--------------------------
  create_directory
---------------------------*/
int create_directory(const char *dir)
{
    if (mkdir(dir, 0700) != 0)
    {
        if (errno != EEXIST)
        {
            fprintf(stderr,
                    "ERROR: Failed to create directory '%s'. Error code: %d\n",
                    dir, errno);
            return -1;
        }
    }
    return 0;
}

/*--------------------------
  copy_arg
---------------------------*/
int copy_arg(char *dest, const char *src, size_t max_len)
{
    if (strlen(src) >= max_len)
    {
        fprintf(stderr, "ERROR: Argument value too long: %s\n", src);
        return 1;
    }
    strncpy(dest, src, max_len - 1);
    dest[max_len - 1] = '\0';
    return 0;
}

/*--------------------------
  ask_until_valid
---------------------------*/
void ask_until_valid(const char *prompt, char *response, size_t size,
                     const char *valid_values[], size_t valid_values_count)
{
    int valid = 0;
    while (!valid)
    {
        printf("%s ", prompt);
        if (fgets(response, size, stdin) != NULL)
        {
            response[strcspn(response, "\n")] = '\0';
            if (valid_values == NULL)
            {
                valid = 1;
            }
            else
            {
                for (size_t i = 0; i < valid_values_count; ++i)
                {
                    if (strcmp(response, valid_values[i]) == 0)
                    {
                        valid = 1;
                        break;
                    }
                }
            }
        }
        if (!valid)
        {
            printf("Invalid input. Please try again.\n");
        }
    }
}
