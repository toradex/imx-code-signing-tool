// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

/*===========================================================================*/
/**
 *  @file    add_key.c
 *
 *-----------------------------------------------------------------------------
 * Description: This script adds a key to an existing HAB PKI tree to be used
 *              with the HAB code signing feature.  Both the private key and
 *              corresponding certificate are generated.  This script can
 *              generate new SRKs, CSF keys and Images keys for HAB4 or AHAB.
 *              This script is not intended for generating CA root keys.
 *-----------------------------------------------------------------------------
 */

/*===========================================================================
                                INCLUDES
=============================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include "openssl_helper.h"
#include "pki_helper.h"
#include "pkey.h"

/*===========================================================================
                                GLOBALS
=============================================================================*/

#define MAX_PARAM 22
#define MIN_PARAM 16

const char *g_tool_name = "add_key";

const char *valid_yes_no[] = {"y", "n"};
const char *ver_valid_values[] = {"4", "a"};
#if CST_WITH_PQC
const char *kt_valid_values[] = {"ecc",       "rsa",    "rsa-pss",
                                 "dilithium", "ml-dsa", "hybrid"};
const char *valid_dilithium_levels[] = {"3", "5"};
const char *valid_mldsa_parameters_set[] = {"65", "87"};
const char *valid_hybrid_combinations[] = {"p384_dilithium3", "p521_dilithium5",
                                           "p384_mldsa65", "p521_mldsa87"};
const char *md_valid_values[] = {"sha256",   "sha384",   "sha512",
                                 "sha3-256", "sha3-384", "sha3-512",
                                 "shake128-256", "shake256-512"};
const char *md_valid_values_no_shake[] = {"sha256",   "sha384",   "sha512",
                                          "sha3-256", "sha3-384", "sha3-512"};
const char *md_valid_values_no_sha3[] = {"sha256", "sha384", "sha512",
                                         "shake128-256", "shake256-512"};
const char *md_valid_values_only_sha2[] = {"sha256", "sha384", "sha512"};
#else
const char *kt_valid_values[] = {"ecc", "rsa", "rsa-pss"};
const char *md_valid_values[] = {"sha256", "sha384", "sha512"};
#endif
const char *kl_valid_values_rsa[] = {"1024", "2048", "3072", "4096"};
const char *kl_valid_values_ecc[] = {"p256", "p384", "p521"};

/*===========================================================================
                                LOCAL FUNCTIONS
=============================================================================*/

static void usage()
{
    printf("\nUsage:\n");
    printf("Interactive Mode:\n");
    printf("%s\n", g_tool_name);
    printf("\nCommand Line Mode:\n");
    printf("%s -ver <4/a> -key-name <new key name> -kt "
           "<ecc/rsa/rsa-pss/dilithium/ml-dsa/hybrid> -kl <key length> [-md "
           "<message "
           "digest>] -duration <years> -srk <y/n> [-srk-ca <y/n>] -signing-key "
           "<CA/SRK signing key> -signing-crt <CA/SRK signing cert>\n",
           g_tool_name);
    printf("Options:\n");
    printf("    -kl: -kt = ecc then Supported key lengths: p256, p384, p521\n");
    printf("       : -kt = rsa then Supported key lengths: 1024, 2048, 3072, "
           "4096\n");
    printf("       : -kt = rsa-pss then Supported key lengths: 1024, 2048, "
           "3072, 4096\n");
#if CST_WITH_PQC
    printf("       : -kt = dilithium then Supported parameter set: 3, 5\n");
    printf("       : -kt = ml-dsa then Supported parameter set: 65, 87\n");
    printf("       : -kt = hybrid then Supported combinations: "
           "p384_dilithium3, p521_dilithium5, p384_mldsa65, p521_mldsa87\n");
    printf("    -md: -ver = a then Supported message digests: sha256, sha384, "
           "sha512, sha3-256, sha3-384, sha3-512, shake128-256, shake256-512\n");
#else
    printf("    -md: -ver = a then Supported message digests: sha256, sha384, "
           "sha512\n");
#endif
    printf("       : -ver = 4 then md = sha256 is fixed\n");
    printf("\n%s -h | --help : This text\n", g_tool_name);
    printf("\n");
}

/*===========================================================================
                                GLOBAL FUNCTIONS
=============================================================================*/

int main(int argc, char **argv)
{
    int interactive = argc > 1 ? 0 : 1;
    char ver[10] = {0};
    char key_name[64] = {0};
    char kt[64] = {0};
    char kl[64] = {0};
    char md[64] = {0};
    int duration = 0;
    char srk[10] = {0};
    char srk_ca[10] = {0};
    char signing_key[MAX_KEY_NAME_LENGTH] = {0};
    char signing_crt[MAX_KEY_NAME_LENGTH] = {0};
    unsigned long serial = 1;
    char *pass = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *sign_cert = NULL;
    EVP_PKEY *sign_pkey = NULL;
    char duration_str[10] = {0};
    int val_period = 0;
    X509 *cert = NULL;
    char keyfile[MAX_PATH_LENGTH] = {0};
    char certfile[MAX_PATH_LENGTH] = {0};
    char keyfile_der[MAX_PATH_LENGTH] = {0};
    char certfile_der[MAX_PATH_LENGTH] = {0};

    /* Process command line inputs */
    if (!interactive)
    {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)
        {
            usage();
            return 0;
        }
        else if (argc < MIN_PARAM || argc > MAX_PARAM)
        {
            fprintf(
                stderr,
                "ERROR: Correct parameters required in non-interactive mode\n");
            usage();
            return 1;
        }

        for (int i = 1; i < argc; i += 2)
        {
            if (strcmp(argv[i], "-ver") == 0)
            {
                if (copy_arg(ver, argv[i + 1], sizeof(ver)) != 0)
                {
                    usage();
                    return 1;
                }
            }
            else if (strcmp(argv[i], "-key-name") == 0)
            {
                if (copy_arg(key_name, argv[i + 1], sizeof(key_name)) != 0)
                {
                    usage();
                    return 1;
                }
            }
            else if (strcmp(argv[i], "-kt") == 0)
            {
                if (copy_arg(kt, argv[i + 1], sizeof(kt)) != 0)
                {
                    usage();
                    return 1;
                }
            }
            else if (strcmp(argv[i], "-kl") == 0)
            {
                if (copy_arg(kl, argv[i + 1], sizeof(kl)) != 0)
                {
                    usage();
                    return 1;
                }
            }
            else if (strcmp(argv[i], "-md") == 0)
            {
                if (strcmp(ver, "4") == 0)
                {
                    fprintf(stderr,
                            "ERROR: Message digest is fixed for HAB4\n");
                    usage();
                    return 1;
                }
                if (copy_arg(md, argv[i + 1], sizeof(md)) != 0)
                {
                    usage();
                    return 1;
                }
            }
            else if (strcmp(argv[i], "-duration") == 0)
            {
                duration = atoi(argv[i + 1]);
            }
            else if (strcmp(argv[i], "-srk") == 0)
            {
                if (copy_arg(srk, argv[i + 1], sizeof(srk)) != 0)
                {
                    usage();
                    return 1;
                }
                if (strcmp(srk, "y") == 0 &&
                    strcmp(argv[i + 2], "-srk-ca") != 0)
                {
                    fprintf(
                        stderr,
                        "ERROR: SRK CA option required when SRK is selected\n");
                    usage();
                    return 1;
                }
            }
            else if (strcmp(argv[i], "-srk-ca") == 0)
            {
                if (copy_arg(srk_ca, argv[i + 1], sizeof(srk_ca)) != 0)
                {
                    usage();
                    return 1;
                }
            }
            else if (strcmp(argv[i], "-signing-key") == 0)
            {
                if (copy_arg(signing_key, argv[i + 1], sizeof(signing_key)) !=
                    0)
                {
                    usage();
                    return 1;
                }
            }
            else if (strcmp(argv[i], "-signing-crt") == 0)
            {
                if (copy_arg(signing_crt, argv[i + 1], sizeof(signing_crt)) !=
                    0)
                {
                    usage();
                    return 1;
                }
            }
            else
            {
                fprintf(stderr, "ERROR: Invalid parameter: %s\n", argv[i]);
                usage();
                return 1;
            }
        }
    }
    else
    {
        /* Interactive mode */
        ask_until_valid("Which version of HAB/AHAB do you want to generate the "
                        "key for (4 = HAB4 / a = AHAB): ",
                        ver, sizeof(ver), ver_valid_values,
                        ARRAY_SIZE(ver_valid_values));
        ask_until_valid("Enter new key name (e.g. SRK5): ", key_name,
                        sizeof(key_name), NULL, 0);
        ask_until_valid("Enter new key type (ecc / rsa / rsa-pss / dilithium / "
                        "ml-dsa / hybrid): ",
                        kt, sizeof(kt), kt_valid_values,
                        ARRAY_SIZE(kt_valid_values));

        if (strcmp(kt, "rsa") == 0 || strcmp(kt, "rsa-pss") == 0)
        {
            ask_until_valid(
                "Enter new key length in bits (1024 / 2048 / 3072 / 4096): ",
                kl, sizeof(kl), kl_valid_values_rsa,
                ARRAY_SIZE(kl_valid_values_rsa));
        }
        else if ((strcmp(kt, "ecc") == 0) || strcmp(kt, "ec") == 0)
        {
            ask_until_valid("Enter new key length (p256 / p384 / p521): ", kl,
                            sizeof(kl), kl_valid_values_ecc,
                            ARRAY_SIZE(kl_valid_values_ecc));
        }
#if CST_WITH_PQC
        else if (strcmp(kt, "dilithium") == 0)
        {
            ask_until_valid("Enter new key parameter set (3, 5): ", kl,
                            sizeof(kl), valid_dilithium_levels,
                            ARRAY_SIZE(valid_dilithium_levels));
        }
        else if (strcmp(kt, "ml-dsa") == 0)
        {
            ask_until_valid("Enter new key parameter set (65, 87): ", kl,
                            sizeof(kl), valid_mldsa_parameters_set,
                            ARRAY_SIZE(valid_mldsa_parameters_set));
        }
        else if (strcmp(kt, "hybrid") == 0)
        {
            ask_until_valid("Enter classical/pqc algorithm combinations "
                            "(Possible values p384_dilithium3, "
                            "p521_dilithium5, p384_mldsa65, p521_mldsa87): ",
                            kl, sizeof(kl), valid_hybrid_combinations,
                            ARRAY_SIZE(valid_hybrid_combinations));
        }
#endif

        if (strcmp(ver, "a") == 0)
        {
#if CST_WITH_PQC
            if ((strcmp(kt, "rsa") == 0) || (strcmp(kt, "ecc") == 0) ||
                (strcmp(kt, "hybrid") == 0))
            {
                ask_until_valid(
                    "Enter the digest algorithm to use (Possible values: "
                    "sha256, sha384, sha512, sha3-256, sha3-384, sha3-512): ",
                    md, sizeof(md), md_valid_values_no_shake,
                    ARRAY_SIZE(md_valid_values_no_shake));
            }
            else if (strcmp(kt, "rsa-pss") == 0)
            {
                ask_until_valid(
                    "Enter the digest algorithm to use (Possible values: "
                    "sha256, sha384, sha512): ",
                    md, sizeof(md), md_valid_values_only_sha2,
                    ARRAY_SIZE(md_valid_values_only_sha2));
            }
            else
            {
                ask_until_valid("Enter new message digest (sha256, sha384, "
                                "sha512, sha3-256, "
                                "sha3-384, sha3-512, shake128-256, shake256-512): ",
                                md, sizeof(md), md_valid_values,
                                ARRAY_SIZE(md_valid_values));
            }
#else
            ask_until_valid(
                "Enter new message digest (sha256, sha384, sha512): ", md,
                sizeof(md), md_valid_values, ARRAY_SIZE(md_valid_values));
#endif
        }
        else
        {
            strcpy(md, "sha256");
        }

        do
        {
            printf("Enter certificate duration (years): ");
            if (fgets(duration_str, sizeof(duration_str), stdin) == NULL)
            {
                fprintf(stderr, "Error reading input. Please try again.\n");
                continue;
            }

            duration_str[strcspn(duration_str, "\n")] = '\0';

            char *endptr = NULL;
            long input = strtol(duration_str, &endptr, 10);

            if (*endptr != '\0' || input <= 0 || input > INT_MAX)
            {
                printf("Invalid duration. Please enter a positive number.\n");
                duration = 0;
            }
            else
            {
                duration = (int) input;
            }
        } while (duration <= 0);

        ask_until_valid("Is this an SRK key ? (y/n): ", srk, sizeof(srk),
                        valid_yes_no, ARRAY_SIZE(valid_yes_no));

        if (strcmp(srk, "y") == 0)
        {
            ask_until_valid(
                "Do you want the SRK to have the CA flag set ? (y/n): ", srk_ca,
                sizeof(srk_ca), valid_yes_no, ARRAY_SIZE(valid_yes_no));
            ask_until_valid("Enter CA signing key name: ", signing_key,
                            sizeof(signing_key), NULL, 0);
            ask_until_valid("Enter CA signing certificate name: ", signing_crt,
                            sizeof(signing_crt), NULL, 0);
        }
        else
        {
            if (strcmp(ver, "4") == 0 || strcmp(ver, "a") == 0)
            {
                ask_until_valid("Enter SRK signing key name: ", signing_key,
                                sizeof(signing_key), NULL, 0);
                ask_until_valid("Enter SRK signing certificate name: ",
                                signing_crt, sizeof(signing_crt), NULL, 0);
            }
        }
    }

    /* Compute validity period */
    val_period = duration * 365;

    /* Initialize OpenSSL and providers */
    openssl_initialize();

    /* Read serial */
    pass = read_key_pass(KEY_PASS_FILE);

    /* Read password */
    serial = read_serial(SERIAL_FILE);

    /* Read signing private key */
    sign_pkey = read_private_key(signing_key,
                                 (pem_password_cb *) get_passcode_to_key_file,
                                 KEY_PASS_FILE);

    if (!sign_pkey)
    {
        fprintf(stderr, "Failed to load signing key from %s\n", signing_key);
        exit(1);
    }

    /* Read signing certificate */
    sign_cert = read_certificate(signing_crt);
    if (!sign_cert)
    {
        fprintf(stderr, "Failed to load signing certificate from %s\n",
                signing_crt);
        exit(1);
    }

    /* Generate private key */
    pkey = generate_key(kt, kl);

    /* Generate the certificate */
    cert = generate_certificate(pkey, key_name, val_period, md, sign_pkey,
                                sign_cert, serial, strcmp(srk_ca, "y") == 0);

    /* Write the key and certificate to files */
    snprintf(keyfile, sizeof(keyfile), "%s/%s.pem", KEY_DIR, key_name);
    snprintf(certfile, sizeof(certfile), "%s/%s.pem", CRT_DIR, key_name);
    write_key_and_cert(pkey, cert, keyfile, certfile, pass);

    /* Write DER formatted key and certificate */
    snprintf(keyfile_der, sizeof(keyfile_der), "%s/%s.der", KEY_DIR, key_name);
    snprintf(certfile_der, sizeof(certfile_der), "%s/%s.der", CRT_DIR,
             key_name);
    write_der_key_and_cert(pkey, cert, keyfile_der, certfile_der);

    /* Update serial file */
    write_serial(SERIAL_FILE, serial);

    /* Cleanup */
    EVP_PKEY_free(pkey);
    X509_free(cert);
    free(pass);
}
