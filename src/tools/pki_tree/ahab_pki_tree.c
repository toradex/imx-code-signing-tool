// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

/*===========================================================================*/
/**
 *  @file    ahab_pki_tree.c
 *
 *  @brief   Generates a basic PKI tree for AHAB
 *-----------------------------------------------------------------------------
 * Description: This tool generates a basic AHAB PKI tree for the NXP
 *              AHAB code signing feature. What the PKI tree looks like depends
 *              on whether the SRK is chosen to be a CA key or not. If the
 *              SRKs are chosen to be CA keys then this tool will generate the
 *              following PKI tree:
 *
 *                                      CA Key
 *                                      | | |
 *                             -------- + | +---------------
 *                            /           |                 \
 *                         SRK1          SRK2       ...      SRKN
 *                          |             |                   |
 *                          |             |                   |
 *                         SGK1          SGK2                SGKN
 *
 *              where: N can be 1 to 4.
 *
 *              Additional keys can be added to the tree separately. In this
 *              configuration SRKs may only be used to sign/verify other
 *              keys/certificates
 *
 *              If the SRKs are chosen to be non-CA keys then this tool will
 *              generate the following PKI tree:
 *
 *                                      CA Key
 *                                      | | |
 *                             -------- + | +---------------
 *                            /           |                 \
 *                         SRK1          SRK2       ...      SRKN
 *
 *              In this configuration SRKs may only be used to sign code/data
 *              and not other keys. Note that not all NXP processors
 *              including AHAB support this option.
 *-----------------------------------------------------------------------------
 */

/*===========================================================================
                                INCLUDE FILES
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

/*===========================================================================
                                GLOBALS
=============================================================================*/

#define MAX_PARAM 16
#define MIN_PARAM 12
#define MAX_PATH_LENGTH 1024

const char *g_tool_name = "ahab_pki_tree";

const char *valid_yes_no[] = {"y", "n"};
#if CST_WITH_PQC
const char *valid_key_types[] = {"rsa",       "rsa-pss", "ecc",
                                 "dilithium", "ml-dsa",  "hybrid"};
const char *valid_dilithium_levels[] = {"3", "5"};
const char *valid_mldsa_parameters_set[] = {"65", "87"};
const char *valid_hybrid_combinations[] = {"p384_dilithium3", "p521_dilithium5",
                                           "p384_mldsa65", "p521_mldsa87"};
const char *valid_digest_algorithms[] = {
    "sha256",   "sha384",   "sha512",       "sha3-256",
    "sha3-384", "sha3-512", "shake128-256", "shake256-512"};
const char *valid_digest_algorithms_no_shake[] = {
    "sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512"};
const char *valid_digest_algorithms_no_sha3[] = {
    "sha256", "sha384", "sha512", "shake128-256", "shake256-512"};
const char *valid_digest_algorithms_only_sha2[] = {"sha256", "sha384",
                                                   "sha512"};
#else
const char *valid_key_types[] = {"rsa", "rsa-pss", "ecc"};
const char *valid_digest_algorithms[] = {"sha256", "sha384", "sha512"};
#endif
const char *valid_rsa_lengths[] = {"2048", "3072", "4096"};
const char *valid_ecc_lengths[] = {"p256", "p384", "p521"};

/*===========================================================================
                                LOCAL FUNCTIONS
=============================================================================*/
/** Checks the validity of key type, key length, and hash algorithm for
 *  specific ELE-enabled device.
 *
 * @param kt Key type (e.g., "rsa", "rsa-pss", "ecc").
 * @param kl Key length or curve type (e.g., "2048", "3072", "p256").
 * @param da Hash algorithm (e.g., "sha256", "sha384", "sha512").
 */
static void print_ele_allowed_combination(const char *kt, const char *kl,
                                          const char *da)
{

    if (strcmp(kt, "rsa") == 0)
    {
        printf("Warning: If these keys are intended for use with any of "
               "the following devices:\ni.MX RT1180, i.MX91, i.MX93, or i.MX95, "
               "when using an rsa key, only rsa-pss key type is supported\n"
               "with key sizes of 2048, 3072, or 4096 bits, and any SHA hash "
               "algorithm is allowed.\n"
               "For i.MX8ULP devices, RSA is not supported.\n\n");
        return;
    }

    if (strcmp(kt, "rsa-pss") == 0)
    {
        printf("Warning: If these keys are intended for use with i.MX8ULP,\n"
               "note that RSA is not supported, only the following key\n"
               "and hash combinations are permitted:\n"
               "p256 with sha256, p384 with sha384, or p521 with sha512.\n\n");
    }

    if (strcmp(kt, "ecc") == 0)
    {
        if ((strcmp(kl, "p256") == 0 && strcmp(da, "sha256") != 0) ||
            (strcmp(kl, "p384") == 0 && strcmp(da, "sha384") != 0) ||
            (strcmp(kl, "p521") == 0 && strcmp(da, "sha512") != 0))
        {
            printf(
                "Warning: If these keys are intended for use with any of "
                "the following devices:\ni.MX RT1180, i.MX8ULP, i.MX91, or i.MX93, "
                "then only the following key and hash combinations are "
                "permitted:\n"
                "p256 with sha256, p384 with sha384, or p521 with sha512.\n\n");
            return;
        }
    }
}

static void usage()
{
    printf("\nUsage:\n");
    printf("Interactive Mode:\n");
    printf("./pki_tree\n");
    printf("\nCommand Line Mode:\n");
    printf("./pki_tree -existing-ca <y/n> [-ca-key <CA key name> -ca-cert <CA "
           "cert name>] -kt <Key Type> -kl <Key Length> -da <digest "
           "algorithm> -duration <years> -srk-ca <y/n>\n");
    printf("Options:\n");
    printf("-kt ecc       : then Supported key lengths: p256, p384, p521\n");
    printf("-kt rsa       : then Supported key lengths: 2048, 3072, 4096\n");
    printf("-kt rsa-pss   : then Supported key lengths: 2048, 3072, 4096\n");
#if CST_WITH_PQC
    printf("-kt dilithium : then Supported parameter set: 3, 5\n");
    printf("-kt ml-dsa    : then Supported parameter set: 65, 87\n");
    printf("-kt hybrid    : then Supported combinations: p384_dilithium3, "
           "p521_dilithium5, p384_mldsa65, p521_mldsa87\n");
    printf("-da: Supported digest algorithms: sha256, sha384, sha512, "
           "sha3-256, sha3-384, sha3-512, shake128-256, shake256-512\n");
#else
    printf("-da: Supported digest algorithms: sha256, sha384, sha512\n");
#endif
    printf("\n./pki_tree -h | --help : This text\n");
    printf("\n");
}

/*===========================================================================
                                GLOBAL FUNCTIONS
=============================================================================*/

int main(int argc, char *argv[])
{
    char interactive = 'y';
    char existing_ca[4] = {0};
    char ca_key[MAX_KEY_NAME_LENGTH] = {0};
    char ca_cert[MAX_KEY_NAME_LENGTH] = {0};
    char kt[64] = {0};
    char kl[64] = {0};
    char da[16] = {0};
    int duration = 0;
    char srk_ca[10] = {0};
    const EVP_MD *digest = NULL;
    int num_srk = 4;
    int i = 0;
    char *pass = NULL;
    char crt_name[MAX_KEY_NAME_LENGTH] = {0};
    char key_name[MAX_KEY_NAME_LENGTH] = {0};
    char subj_name[MAX_KEY_NAME_LENGTH] = {0};
    unsigned long serial = 0;
    FILE *pass_fp = NULL;
    char key_pass_filepath[MAX_PATH_LENGTH] = {0};
    int val_period = 0;
    char duration_str[10] = {0};
    EVP_PKEY *ca_pkey = NULL;
    X509 *ca_cert_x509 = NULL;
    EVP_PKEY *srk_pkey = NULL;
    X509 *srk_cert_x509 = NULL;
    EVP_PKEY *sgk_pkey = NULL;
    X509 *sgk_cert_x509 = NULL;
    FILE *key_file = NULL;
    FILE *cert_file = NULL;
    char ca_keyfile[MAX_PATH_LENGTH] = {0};
    char ca_certfile[MAX_PATH_LENGTH] = {0};
    char ca_keyfile_der[MAX_PATH_LENGTH] = {0};
    char ca_certfile_der[MAX_PATH_LENGTH] = {0};
    char srk_keyfile_pem[MAX_PATH_LENGTH] = {0};
    char srk_certfile_pem[MAX_PATH_LENGTH] = {0};
    char srk_keyfile_der[MAX_PATH_LENGTH] = {0};
    char srk_certfile_der[MAX_PATH_LENGTH] = {0};
    char sgk_keyfile_pem[MAX_PATH_LENGTH] = {0};
    char sgk_certfile_pem[MAX_PATH_LENGTH] = {0};
    char sgk_keyfile_der[MAX_PATH_LENGTH] = {0};
    char sgk_certfile_der[MAX_PATH_LENGTH] = {0};

    printf("\n");
    printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("This tool is a part of the Code signing tools for NXP's\n");
    printf("Advanced High Assurance Boot. It generates a basic PKI tree.\n");
    printf("The PKI tree consists of one or more Super Root Keys (SRK), with "
           "each\n");
    printf("SRK having one subordinate keys:\n");
    printf("    + a Signing key (SGK)\n");
    printf("Additional keys can be added to the PKI tree but a separate\n");
    printf("tool is available for this. Finally, the private keys generated "
           "are password\n");
    printf("protected with the password provided by the file key_pass.txt.\n");
    printf("The format of the file is the password repeated twice:\n");
    printf("    my_password\n");
    printf("    my_password\n");
    printf(
        "All private keys in the PKI tree are in PKCS #8 format and will be\n");
    printf("protected by the same password.\n\n");
    printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");

    /* Create keys and certificates directories if not exist */
    if (create_directory(KEY_DIR) != 0)
    {
        fprintf(stderr, "ERROR: Could not create key directory.\n");
        return 1;
    }

    if (create_directory(CRT_DIR) != 0)
    {
        fprintf(stderr, "ERROR: Could not create cert directory.\n");
        return 1;
    }

    /* Check that the serial file is present, if not create it */
    generate_serial_file(SERIAL_FILE);
    printf("A default 'serial' file was created!\n");

    /* Check that the file "key_pass.txt" is present, if not create it with
     * default user/pwd */
    generate_key_pass_file(KEY_PASS_FILE);
    printf("A default file 'key_pass.txt' was created with password = test\n");

    /* Read password */
    pass = read_key_pass(KEY_PASS_FILE);

    /* Read serial */
    serial = read_serial(SERIAL_FILE);

    if (argc > 1)
    {
        interactive = 'n';
    }

    /* Process command line inputs */
    if (interactive == 'n')
    {
        if (argc == 2 &&
            (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
        {
            usage();
            return 0;
        }
        else if (argc < MIN_PARAM || argc > MAX_PARAM)
        {
            printf(
                "ERROR: Correct parameters required in non-interactive mode\n");
            usage();
            return 1;
        }

        int i = 1;
        while (i < argc)
        {
            if (strcmp(argv[i], "-existing-ca") == 0)
            {
                i++;
                if (i >= argc ||
                    copy_arg(existing_ca, argv[i], sizeof(existing_ca)))
                {
                    usage();
                    return 1;
                }
                i++;
                if ((strcmp(existing_ca, "y") == 0) &&
                    (i >= argc || strcmp(argv[i], "-ca-key") != 0))
                {
                    printf("ERROR: CA key is required.\n");
                    usage();
                    return 1;
                }
            }
            else if (strcmp(argv[i], "-ca-key") == 0)
            {
                i++;
                if (i >= argc || copy_arg(ca_key, argv[i], sizeof(ca_key)))
                {
                    usage();
                    return 1;
                }
                i++;
                if ((strcmp(existing_ca, "y") == 0) &&
                    (i >= argc || strcmp(argv[i], "-ca-cert") != 0))
                {
                    printf("ERROR: CA cert is required.\n");
                    usage();
                    return 1;
                }
            }
            else if (strcmp(argv[i], "-ca-cert") == 0)
            {
                i++;
                if (i >= argc || copy_arg(ca_cert, argv[i], sizeof(ca_cert)))
                {
                    return 1;
                }
                i++;
            }
            else if (strcmp(argv[i], "-kt") == 0)
            {
                i++;
                if (i >= argc || copy_arg(kt, argv[i], sizeof(kt)))
                {
                    return 1;
                }
                i++;
            }
            else if (strcmp(argv[i], "-kl") == 0)
            {
                i++;
                if (i >= argc || copy_arg(kl, argv[i], sizeof(kl)))
                {
                    return 1;
                }
                i++;
            }
            else if (strcmp(argv[i], "-da") == 0)
            {
                i++;
                if (i >= argc || copy_arg(da, argv[i], sizeof(da)))
                {
                    return 1;
                }
                i++;
            }
            else if (strcmp(argv[i], "-duration") == 0)
            {
                i++;
                if (i >= argc)
                {
                    printf("ERROR: Missing value for -duration\n");
                    usage();
                    return 1;
                }
                duration = atoi(argv[i]);
                if (duration <= 0)
                {
                    printf("ERROR: Invalid value for -duration\n");
                    usage();
                    return 1;
                }
                i++;
            }
            else if (strcmp(argv[i], "-srk-ca") == 0)
            {
                i++;
                if (i >= argc || copy_arg(srk_ca, argv[i], sizeof(srk_ca)))
                {
                    usage();
                    return 1;
                }
                i++;
            }
            else
            {
                fprintf(stderr, "ERROR: Invalid parameter: %s\n", argv[i]);
                usage();
                return 1;
            }
        }
    }

    /* Interactive mode */
    if (interactive == 'y')
    {
        ask_until_valid(
            "Do you want to use an existing CA key (y/n)?: ", existing_ca,
            sizeof(existing_ca), valid_yes_no, ARRAY_SIZE(valid_yes_no));
        if (strcmp(existing_ca, "y") == 0)
        {
            printf("Enter CA key name: ");

            if (scanf("%255s", ca_key) != 1)
            {
                fprintf(stderr, "ERROR: Failed to read input for ca_key.\n");
                usage();
                return 1;
            }

            printf("Enter CA certificate name: ");
            if (scanf("%255s", ca_cert) != 1)
            {
                fprintf(stderr, "ERROR: Failed to read input for ca_cert.\n");
                usage();
                return 1;
            }
        }
#if CST_WITH_PQC
        ask_until_valid("Select the key type (possible values: rsa, rsa-pss, "
                        "ecc, dilithium, ml-dsa, hybrid): ",
                        kt, sizeof(kt), valid_key_types,
                        ARRAY_SIZE(valid_key_types));
#else
        ask_until_valid(
            "Select the key type (possible values: rsa, rsa-pss, ecc): ", kt,
            sizeof(kt), valid_key_types, ARRAY_SIZE(valid_key_types));
#endif
        if (strcmp(kt, "ecc") == 0)
        {
            ask_until_valid("Enter length for elliptic curve to be used for "
                            "PKI tree (Possible values p256, p384, p521): ",
                            kl, sizeof(kl), valid_ecc_lengths,
                            ARRAY_SIZE(valid_ecc_lengths));
        }
        else if (strcmp(kt, "rsa") == 0 || strcmp(kt, "rsa-pss") == 0)
        {
            ask_until_valid("Enter key length in bits for PKI tree (Possible "
                            "values 2048, 3072, 4096): ",
                            kl, sizeof(kl), valid_rsa_lengths,
                            ARRAY_SIZE(valid_rsa_lengths));
        }
#if CST_WITH_PQC
        else if (strcmp(kt, "dilithium") == 0)
        {
            ask_until_valid("Enter level for Dilithium parameter set to be "
                            "used for PKI tree (Possible values 3, 5): ",
                            kl, sizeof(kl), valid_dilithium_levels,
                            ARRAY_SIZE(valid_dilithium_levels));
        }
        else if (strcmp(kt, "ml-dsa") == 0)
        {
            ask_until_valid("Enter parameters set for ML-DSA to be "
                            "used for PKI tree (Possible values 65, 87): ",
                            kl, sizeof(kl), valid_mldsa_parameters_set,
                            ARRAY_SIZE(valid_mldsa_parameters_set));
        }
        else if (strcmp(kt, "hybrid") == 0)
        {
            ask_until_valid("Enter classical/pqc algorithm combinations "
                            "(Possible values p384_dilithium3, p384_mldsa65, "
                            "p521_dilithium5, p521_mldsa87): ",
                            kl, sizeof(kl), valid_hybrid_combinations,
                            ARRAY_SIZE(valid_hybrid_combinations));
        }

        if ((strcmp(kt, "rsa") == 0) || (strcmp(kt, "ecc") == 0) ||
            (strcmp(kt, "hybrid") == 0))
        {
            ask_until_valid(
                "Enter the digest algorithm to use (Possible values: "
                "sha256, sha384, sha512, sha3-256, sha3-384, sha3-512): ",
                da, sizeof(da), valid_digest_algorithms_no_shake,
                ARRAY_SIZE(valid_digest_algorithms_no_shake));
        }
        else if (strcmp(kt, "rsa-pss") == 0)
        {
            ask_until_valid(
                "Enter the digest algorithm to use (Possible values: "
                "sha256, sha384, sha512): ",
                da, sizeof(da), valid_digest_algorithms_only_sha2,
                ARRAY_SIZE(valid_digest_algorithms_only_sha2));
        }
        else
        {
            ask_until_valid(
                "Enter the digest algorithm to use (Possible values: "
                "sha256, sha384, sha512, sha3-256, sha3-384, sha3-512, "
                "shake128-256, shake256-512): ",
                da, sizeof(da), valid_digest_algorithms,
                ARRAY_SIZE(valid_digest_algorithms));
        }

#else
        ask_until_valid("Enter the digest algorithm to use (Possible values "
                        "sha256, sha384, sha512): ",
                        da, sizeof(da), valid_digest_algorithms,
                        ARRAY_SIZE(valid_digest_algorithms));
#endif
        do
        {
            printf("Enter PKI tree duration (years): ");
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

        ask_until_valid(
            "Do you want the SRK certificates to have the CA flag set? (y/n): ",
            srk_ca, sizeof(srk_ca), valid_yes_no, ARRAY_SIZE(valid_yes_no));
    }

    if (strcmp(da, "sha256") == 0)
    {
        digest = EVP_sha256();
    }
    else if (strcmp(da, "sha384") == 0)
    {
        digest = EVP_sha384();
    }
    else if (strcmp(da, "sha512") == 0)
    {
        digest = EVP_sha512();
    }
#if CST_WITH_PQC
    else if (strcmp(da, "sha3-256") == 0)
    {
        digest = EVP_sha3_256();
    }
    else if (strcmp(da, "sha3-384") == 0)
    {
        digest = EVP_sha3_384();
    }
    else if (strcmp(da, "sha3-512") == 0)
    {
        digest = EVP_sha3_512();
    }
    else if (strncmp(da, "shake128-256", 8) == 0)
    {
        digest = EVP_shake128();
    }
    else if (strncmp(da, "shake256-512", 8) == 0)
    {
        digest = EVP_shake256();
    }
#endif
    else
    {
        printf("Invalid digest algorithm\n");
        usage();
        return 1;
    }

    /* Compute validity period */
    val_period = duration * 365;

    /* Initialize OpenSSL and providers */
    openssl_initialize();

    if (strcmp(existing_ca, "n") == 0)
    {
        /* Generate CA key and certificate */
        printf("\n+++++++++++++++++++++++++++++++++++++\n");
        printf("+ Generating CA key and certificate +\n");
        printf("+++++++++++++++++++++++++++++++++++++\n");
        format_key_cert_names(kt, kl, da, "ca", 1, 1, key_name, crt_name,
                              subj_name);
        ca_pkey = generate_key(kt, kl);
        ca_cert_x509 = generate_certificate(ca_pkey, subj_name, val_period, da,
                                            NULL, NULL, serial++, 1);
        snprintf(ca_keyfile, sizeof(ca_keyfile), "%s/%s.pem", KEY_DIR,
                 key_name);
        snprintf(ca_certfile, sizeof(ca_certfile), "%s/%s.pem", CRT_DIR,
                 crt_name);
        write_key_and_cert(ca_pkey, ca_cert_x509, ca_keyfile, ca_certfile,
                           pass);
        snprintf(ca_keyfile_der, sizeof(ca_keyfile_der), "%s/%s.der", KEY_DIR,
                 key_name);
        snprintf(ca_certfile_der, sizeof(ca_certfile_der), "%s/%s.der", CRT_DIR,
                 crt_name);
        write_der_key_and_cert(ca_pkey, ca_cert_x509, ca_keyfile_der,
                               ca_certfile_der);
    }
    else
    {
        /* Use existing CA key and certificate */
        key_file = fopen(ca_key, "rb");
        cert_file = fopen(ca_cert, "rb");

        if (!key_file || !cert_file)
        {
            fprintf(stderr, "Error opening existing CA key/cert files\n");
            exit(1);
        }

        ca_pkey = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
        ca_cert_x509 = PEM_read_X509(cert_file, NULL, NULL, NULL);

        fclose(key_file);
        fclose(cert_file);

        if (!ca_pkey || !ca_cert_x509)
        {
            fprintf(stderr, "Error reading existing CA key/cert files\n");
            exit(1);
        }
    }

    for (i = 1; i <= num_srk; i++)
    {
        /* Generate SRK keys and certificates */
        format_key_cert_names(kt, kl, da, "srk", i, (strcmp(srk_ca, "y") == 0) ? 1 : 0, key_name, crt_name,
                              subj_name);
        snprintf(srk_keyfile_pem, sizeof(srk_keyfile_pem), "%s/%s.pem", KEY_DIR,
                 key_name);
        snprintf(srk_certfile_pem, sizeof(srk_certfile_pem), "%s/%s.pem",
                 CRT_DIR, crt_name);
        snprintf(srk_keyfile_der, sizeof(srk_keyfile_der), "%s/%s.der", KEY_DIR,
                 key_name);
        snprintf(srk_certfile_der, sizeof(srk_certfile_der), "%s/%s.der",
                 CRT_DIR, crt_name);
        printf("\n+++++++++++++++++++++++++++++++++++++++\n");
        printf("+ Generating SRK key and certificate %d +\n", i);
        printf("+++++++++++++++++++++++++++++++++++++++\n");
        srk_pkey = generate_key(kt, kl);
        srk_cert_x509 = generate_certificate(
            srk_pkey, subj_name, val_period, da, ca_pkey, ca_cert_x509,
            serial++, (strcmp(srk_ca, "y") == 0) ? 1 : 0);
        write_key_and_cert(srk_pkey, srk_cert_x509, srk_keyfile_pem,
                           srk_certfile_pem, pass);
        write_der_key_and_cert(srk_pkey, srk_cert_x509, srk_keyfile_der,
                               srk_certfile_der);

        if (strcmp(srk_ca, "y") == 0)
        {
            /* Generate SGK keys and certificates */
            format_key_cert_names(kt, kl, da, "sgk", i, 0, key_name, crt_name,
                                  subj_name);
            snprintf(sgk_keyfile_pem, sizeof(sgk_keyfile_pem), "%s/%s.pem",
                     KEY_DIR, key_name);
            snprintf(sgk_certfile_pem, sizeof(sgk_certfile_pem), "%s/%s.pem",
                     CRT_DIR, crt_name);
            snprintf(sgk_keyfile_der, sizeof(sgk_keyfile_der), "%s/%s.der",
                     KEY_DIR, key_name);
            snprintf(sgk_certfile_der, sizeof(sgk_certfile_der), "%s/%s.der",
                     CRT_DIR, crt_name);
            printf("\n+++++++++++++++++++++++++++++++++++++++\n");
            printf("+ Generating SGK key and certificate %d +\n", i);
            printf("+++++++++++++++++++++++++++++++++++++++\n");
            sgk_pkey = generate_key(kt, kl);
            sgk_cert_x509 =
                generate_certificate(sgk_pkey, subj_name, val_period, da,
                                     srk_pkey, srk_cert_x509, serial++, 0);
            write_key_and_cert(sgk_pkey, sgk_cert_x509, sgk_keyfile_pem,
                               sgk_certfile_pem, pass);
            write_der_key_and_cert(sgk_pkey, sgk_cert_x509, sgk_keyfile_der,
                                   sgk_certfile_der);
            EVP_PKEY_free(sgk_pkey);
            X509_free(sgk_cert_x509);
        }

        EVP_PKEY_free(srk_pkey);
        X509_free(srk_cert_x509);
    }

    /* Update serial file */
    write_serial(SERIAL_FILE, serial);

    printf("\nPKI tree keys and certificates have been successfully "
           "generated in %s and %s, respectively.\n\n",
           KEY_DIR, CRT_DIR);

    /*
    * Print the allowed key and hash size combinations for ELE.
    *
    * Output this information immediately after creating the PKI tree
    * to avoid disrupting the existing question-and-answer flow,
    * which may be expeted by certain automation tools.
    */
    print_ele_allowed_combination(kt, kl, da);

    /* Cleanup */
    EVP_PKEY_free(ca_pkey);
    X509_free(ca_cert_x509);
    free(pass);

    return 0;
}
