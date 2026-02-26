// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

/**
 *   @file  hab4_pki_tree.c
 *
 *   @brief  Generates a basic PKI tree for HABv4
 *-----------------------------------------------------------------------------
 *   Description: This tool generates a basic HAB4 PKI tree for the NXP
 *              HAB code signing feature.  What the PKI tree looks like depends
 *              on whether the SRK is chosen to be a CA key or not.  If the
 *              SRKs are chosen to be CA keys then this tool will generate the
 *              following PKI tree:
 *
 *                                      CA Key
 *                                      | | |
 *                             -------- + | +---------------
 *                            /           |                 \
 *                         SRK1          SRK2       ...      SRKN
 *                         / \            / \                / \
 *                        /   \          /   \              /   \
 *                   CSF1_1  IMG1_1  CSF2_1  IMG2_1 ... CSFN_1  IMGN_1
 *
 *              where: N can be 1 to 4.
 *
 *              Additional keys can be added to the tree separately.  In this
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
 *              and not other keys.  Note that not all Freescale processors
 *              including HAB support this option.
 *
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

#define MAX_PARAM 17
#define MIN_PARAM 12

const char *g_tool_name = "hab4_pki_tree";

const char *yes_no_values[] = {"y", "n"};
const char *kt_values[] = {"rsa", "rsa-pss", "ecc"};
const char *ecc_kl_values[] = {"p256", "p384", "p521"};
const char *rsa_kl_values[] = {"2048", "3072", "4096"};

/*===========================================================================
                                LOCAL FUNCTIONS
=============================================================================*/

static void usage()
{
    printf("\nUsage:\n");
    printf("Interactive Mode:\n");
    printf("%s\n", g_tool_name);
    printf("\nCommand Line Mode:\n");
    printf("%s -existing-ca <y/n> [-ca-key <CA key name> -ca-cert <CA cert "
           "name>] -kt <rsa/rsa-pss/ecc> -kl <ECC Curve/RSA Key Length> "
           "-duration <years> -num-srk <1-4> -srk-ca <y/n>\n",
           g_tool_name);
    printf("  Key Type Options:\n");
    printf("-kl ecc     : then Supported key lengths: p256, p384, p521\n");
    printf("-kl rsa     : then Supported key lengths: 2048, 3072, 4096\n");
    printf("-kl rsa-pss : then Supported key lengths: 2048, 3072, 4096\n");
    printf("\n%s -h | --help : This text\n", g_tool_name);
    printf("\n");
}

/*===========================================================================
                                GLOBAL FUNCTIONS
=============================================================================*/

int main(int argc, char **argv)
{
    char interactive = argc > 1 ? 'n' : 'y';
    char existing_ca[4] = {0};
    char ca_key[MAX_KEY_NAME_LENGTH] = {0};
    char ca_cert[MAX_KEY_NAME_LENGTH] = {0};
    char kt[64] = {0};
    char kl[64] = {0};
    char srk_ca[10] = {0};
    int duration = 0;
    int num_srk = 0;
    int val_period = 0;
    char *pass = NULL;
    unsigned long serial = 0;
    char duration_str[10] = {0};
    char num_srk_str[10] = {0};
    EVP_PKEY *ca_pkey = NULL;
    X509 *ca_cert_x509 = NULL;
    EVP_PKEY *srk_pkey = NULL;
    X509 *srk_cert = NULL;
    EVP_PKEY *csf_pkey = NULL;
    X509 *csf_cert = NULL;
    X509 *img_cert = NULL;
    EVP_PKEY *img_pkey = NULL;
    char key_name[MAX_KEY_NAME_LENGTH] = {0};
    char crt_name[MAX_KEY_NAME_LENGTH] = {0};
    char subj_name[MAX_KEY_NAME_LENGTH] = {0};
    char ca_keyfile_pem[MAX_PATH_LENGTH] = {0};
    char ca_certfile_pem[MAX_PATH_LENGTH] = {0};
    char ca_keyfile_der[MAX_PATH_LENGTH] = {0};
    char ca_certfile_der[MAX_PATH_LENGTH] = {0};
    char srk_keyfile_pem[MAX_PATH_LENGTH] = {0};
    char srk_certfile_pem[MAX_PATH_LENGTH] = {0};
    char srk_keyfile_der[MAX_PATH_LENGTH] = {0};
    char srk_certfile_der[MAX_PATH_LENGTH] = {0};
    char img_keyfile_pem[MAX_PATH_LENGTH] = {0};
    char img_certfile_pem[MAX_PATH_LENGTH] = {0};
    char img_keyfile_der[MAX_PATH_LENGTH] = {0};
    char img_certfile_der[MAX_PATH_LENGTH] = {0};
    char csf_keyfile_pem[MAX_PATH_LENGTH] = {0};
    char csf_certfile_pem[MAX_PATH_LENGTH] = {0};
    char csf_keyfile_der[MAX_PATH_LENGTH] = {0};
    char csf_certfile_der[MAX_PATH_LENGTH] = {0};

    printf("\n");
    printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("This tool is a part of the Code signing tools for NXP's\n");
    printf("High Assurance Boot.  It generates a basic PKI tree.  The PKI\n");
    printf("tree consists of one or more Super Root Keys (SRK), with each\n");
    printf("SRK having two subordinate keys: \n");
    printf("    + a Command Sequence File (CSF) key \n");
    printf("    + Image key. \n");
    printf("Additional keys can be added to the PKI tree but a separate \n");
    printf("tool is available for this. Finally, the private keys generated "
           "are password \n");
    printf("protectedwith the password provided by the file key_pass.txt.\n");
    printf("The format of the file is the password repeated twice:\n");
    printf("    my_password\n");
    printf("    my_password\n");
    printf("All private keys in the PKI tree are in PKCS #8 format will be\n");
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
            fprintf(
                stderr,
                "ERROR: Correct parameters required in non-interactive mode\n");
            usage();
            return 1;
        }

        for (int i = 1; i < argc; i += 2)
        {
            if (strcmp(argv[i], "-existing-ca") == 0)
            {
                if (copy_arg(existing_ca, argv[i + 1], sizeof(existing_ca)) !=
                    0)
                {
                    usage();
                    return 1;
                }
                if (strcmp(existing_ca, "y") == 0 &&
                    strcmp(argv[i + 2], "-ca-key") != 0)
                {
                    fprintf(stderr, "ERROR: CA key is required.\n");
                    usage();
                    return 1;
                }
            }
            else if (strcmp(argv[i], "-ca-key") == 0)
            {
                if (copy_arg(ca_key, argv[i + 1], sizeof(ca_key)) != 0)
                {
                    usage();
                    return 1;
                }
                if (strcmp(existing_ca, "y") == 0 &&
                    strcmp(argv[i + 2], "-ca-cert") != 0)
                {
                    fprintf(stderr, "ERROR: CA cert is required.\n");
                    usage();
                    return 1;
                }
            }
            else if (strcmp(argv[i], "-ca-cert") == 0)
            {
                if (copy_arg(ca_cert, argv[i + 1], sizeof(ca_cert)) != 0)
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
            else if (strcmp(argv[i], "-duration") == 0)
            {
                duration = atoi(argv[i + 1]);
            }
            else if (strcmp(argv[i], "-num-srk") == 0)
            {
                num_srk = atoi(argv[i + 1]);
            }
            else if (strcmp(argv[i], "-srk-ca") == 0)
            {
                if (copy_arg(srk_ca, argv[i + 1], sizeof(srk_ca)) != 0)
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
        ask_until_valid(
            "Do you want to use an existing CA key (y/n)? :", existing_ca,
            sizeof(existing_ca), yes_no_values, ARRAY_SIZE(yes_no_values));
        if (strcmp(existing_ca, "y") == 0)
        {
            printf("Enter CA key name: ");
            fgets(ca_key, sizeof(ca_key), stdin);
            ca_key[strcspn(ca_key, "\n")] = '\0';
            printf("Enter CA certificate name: ");
            fgets(ca_cert, sizeof(ca_cert), stdin);
            ca_cert[strcspn(ca_cert, "\n")] = '\0';
        }
        printf("\nKey type options (confirm targeted device supports desired "
               "key type):\n");
        ask_until_valid(
            "Select the key type (possible values: rsa, rsa-pss, ecc) :", kt,
            sizeof(kt), kt_values, ARRAY_SIZE(kt_values));
        if (strcmp(kt, "ecc") == 0)
        {
            ask_until_valid("Enter length for elliptic curve to be used for "
                            "PKI tree (possible values: p256, p384, p521) :",
                            kl, sizeof(kl), ecc_kl_values,
                            ARRAY_SIZE(ecc_kl_values));
        }
        else
        {
            ask_until_valid("Enter key length in bits for PKI tree (possible "
                            "values: 2048, 3072, 4096) :",
                            kl, sizeof(kl), rsa_kl_values,
                            ARRAY_SIZE(rsa_kl_values));
        }
        printf("Enter PKI tree duration (years): ");
        fgets(duration_str, sizeof(duration_str), stdin);
        duration = atoi(duration_str);
        printf("How many Super Root Keys should be generated ? : ");
        fgets(num_srk_str, sizeof(num_srk_str), stdin);
        num_srk = atoi(num_srk_str);
        ask_until_valid(
            "Do you want the SRK certificates to have the CA flag set? (y/n) :",
            srk_ca, sizeof(srk_ca), yes_no_values, ARRAY_SIZE(yes_no_values));
    }

    /* Check that 0 < num_srk <= 4 (Max. number of SRKs) */
    if (num_srk < 1 || num_srk > 4)
    {
        fprintf(stderr,
                "The number of SRKs generated must be between 1 and 4\n");
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
        printf("+++++++++++++++++++++++++++++++++++++\n\n");
        ca_pkey = generate_key(kt, kl);
        format_key_cert_names(kt, kl, "sha256", "ca", 1, 1, key_name, crt_name,
                              subj_name);
        ca_cert_x509 =
            generate_certificate(ca_pkey, subj_name, val_period, "sha256",
                                 ca_pkey, NULL, serial++, 1);
        snprintf(ca_keyfile_pem, sizeof(ca_keyfile_pem), "%s/%s.pem", KEY_DIR,
                 key_name);
        snprintf(ca_certfile_pem, sizeof(ca_certfile_pem), "%s/%s.pem", CRT_DIR,
                 crt_name);
        snprintf(ca_keyfile_der, sizeof(ca_keyfile_der), "%s/%s.der", KEY_DIR,
                 key_name);
        snprintf(ca_certfile_der, sizeof(ca_certfile_der), "%s/%s.der", CRT_DIR,
                 crt_name);
        write_key_and_cert(ca_pkey, ca_cert_x509, ca_keyfile_pem,
                           ca_certfile_pem, pass);
        write_der_key_and_cert(ca_pkey, ca_cert_x509, ca_keyfile_der,
                               ca_certfile_der);
        strcpy(ca_key, ca_keyfile_pem);
        strcpy(ca_cert, ca_certfile_pem);
    }
    else
    {
        /* Use existing CA key and certificate */
        ca_pkey = read_private_key(ca_key,
                                   (pem_password_cb *) get_passcode_to_key_file,
                                   KEY_PASS_FILE);
        if (!ca_pkey)
        {
            fprintf(stderr, "Failed to load CA key from %s\n", ca_key);
            return 1;
        }
        ca_cert_x509 = read_certificate(ca_cert);
        if (!ca_cert_x509)
        {
            fprintf(stderr, "Failed to load CA certificate from %s\n", ca_cert);
            EVP_PKEY_free(ca_pkey);
            return 1;
        }
    }

    for (int i = 1; i <= num_srk; ++i)
    {
        printf("\n+++++++++++++++++++++++++++++++++++++++\n");
        printf("+ Generating SRK key and certificate %d +\n", i);
        printf("+++++++++++++++++++++++++++++++++++++++\n\n");
        /* Generate SRK keys and certificates */
        srk_pkey = generate_key(kt, kl);
        format_key_cert_names(kt, kl, "sha256", "srk", i, strcmp(srk_ca, "y") == 0 ? 1:0, key_name, crt_name,
                              subj_name);
        srk_cert = generate_certificate(srk_pkey, subj_name, val_period,
                                        "sha256", ca_pkey, ca_cert_x509,
                                        serial++, strcmp(srk_ca, "y") == 0);
        snprintf(srk_keyfile_pem, sizeof(srk_keyfile_pem), "%s/%s.pem", KEY_DIR,
                 key_name);
        snprintf(srk_certfile_pem, sizeof(srk_certfile_pem), "%s/%s.pem",
                 CRT_DIR, crt_name);
        snprintf(srk_keyfile_der, sizeof(srk_keyfile_der), "%s/%s.der", KEY_DIR,
                 key_name);
        snprintf(srk_certfile_der, sizeof(srk_certfile_der), "%s/%s.der",
                 CRT_DIR, crt_name);
        write_key_and_cert(srk_pkey, srk_cert, srk_keyfile_pem,
                           srk_certfile_pem, pass);
        write_der_key_and_cert(srk_pkey, srk_cert, srk_keyfile_der,
                               srk_certfile_der);

        if (strcmp(srk_ca, "y") == 0)
        {

            printf("\n+++++++++++++++++++++++++++++++++++++++\n");
            printf("+ Generating CSF key and certificate %d +\n", i);
            printf("+++++++++++++++++++++++++++++++++++++++\n\n");
            /* Generate CSF certificate (this is a user cert) */
            csf_pkey = generate_key(kt, kl);
            format_key_cert_names(kt, kl, "sha256", "csf", i, 0, key_name,
                                  crt_name, subj_name);
            csf_cert =
                generate_certificate(csf_pkey, subj_name, val_period, "sha256",
                                     srk_pkey, srk_cert, serial++, 0);
            snprintf(csf_keyfile_pem, sizeof(csf_keyfile_pem), "%s/%s.pem",
                     KEY_DIR, key_name);
            snprintf(csf_certfile_pem, sizeof(csf_certfile_pem), "%s/%s.pem",
                     CRT_DIR, crt_name);
            snprintf(csf_keyfile_der, sizeof(csf_keyfile_der), "%s/%s.der",
                     KEY_DIR, key_name);
            snprintf(csf_certfile_der, sizeof(csf_certfile_der), "%s/%s.der",
                     CRT_DIR, crt_name);
            write_key_and_cert(csf_pkey, csf_cert, csf_keyfile_pem,
                               csf_certfile_pem, pass);
            write_der_key_and_cert(csf_pkey, csf_cert, csf_keyfile_der,
                                   csf_certfile_der);
            EVP_PKEY_free(csf_pkey);
            X509_free(csf_cert);

            printf("\n+++++++++++++++++++++++++++++++++++++++\n");
            printf("+ Generating IMG key and certificate %d +\n", i);
            printf("+++++++++++++++++++++++++++++++++++++++\n\n");
            /* Generate IMG certificate (this is a user cert) */
            img_pkey = generate_key(kt, kl);
            format_key_cert_names(kt, kl, "sha256", "img", i, 0, key_name,
                                  crt_name, subj_name);
            img_cert =
                generate_certificate(img_pkey, subj_name, val_period, "sha256",
                                     srk_pkey, srk_cert, serial++, 0);
            snprintf(img_keyfile_pem, sizeof(img_keyfile_pem), "%s/%s.pem",
                     KEY_DIR, key_name);
            snprintf(img_certfile_pem, sizeof(img_certfile_pem), "%s/%s.pem",
                     CRT_DIR, crt_name);
            snprintf(img_keyfile_der, sizeof(img_keyfile_der), "%s/%s.der",
                     KEY_DIR, key_name);
            snprintf(img_certfile_der, sizeof(img_certfile_der), "%s/%s.der",
                     CRT_DIR, crt_name);
            write_key_and_cert(img_pkey, img_cert, img_keyfile_pem,
                               img_certfile_pem, pass);
            write_der_key_and_cert(img_pkey, img_cert, img_keyfile_der,
                                   img_certfile_der);
            EVP_PKEY_free(img_pkey);
            X509_free(img_cert);
        }
        EVP_PKEY_free(srk_pkey);
        X509_free(srk_cert);
    }

    /* Update serial file */
    write_serial(SERIAL_FILE, serial);

    /* Cleanup */
    EVP_PKEY_free(ca_pkey);
    X509_free(ca_cert_x509);
    free(pass);

    return 0;
}
