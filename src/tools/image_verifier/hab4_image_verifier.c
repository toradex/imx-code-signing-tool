// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

/*===========================================================================*/
/**
 *   @file    hab4_image_verifier.c
 *
 *   @brief   Parse HABv4 images.
 *
 */

/*===========================================================================
                                INCLUDE FILES
=============================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/cms.h>
#include <openssl/asn1.h>
#include "hab_types.h"
#include "openssl_helper.h"
#include "ssl_backend.h"
#include "verifier_helper.h"
#include "version.h"

/*===========================================================================
                               LOCAL CONSTANTS
=============================================================================*/

read_certificate_fptr read_certificate = ssl_read_certificate;
const char *g_tool_name = "hab4_image_verifier"; /**< Global holds tool name */
const char *g_tool_version = CST_VERSION; /**< Global holds tool version */

#define HAB_IVT_V0_LEN (4 * 8)
#define HAB_IVT_V1_LEN (4 * 2 + 8 * 5)

#define HAB_CMD_INS_KEY_BASE_SIZE 12

#define HAB_IDX_SRK_NXP 0
#define HAB_IDX_SRK_OEM 5
#define HAB_IDX_CSFK_NXP 1
#define HAB_IDX_CSFK_OEM 6

/* Only for safety purpose */
#define MAX_MOD_X_LEN 512
#define MAX_EXP_Y_LEN 66
#define MAX_SIG_LEN 4096
#define MAX_KEY_LEN 1024
#define MAX_CSF_LEN 4096
#define MAX_SRK_TABLE_LEN 4096
#define MAX_SRK_RECORD_LEN 1024

/*===========================================================================
                  LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
=============================================================================*/

/* IVT Field Information */
typedef struct
{
    const char *name;
    long offset;
    size_t size;
} ivt_field_t;

/* Command structure */
typedef struct
{
    uint8_t tag;
    uint8_t len[2]; /* Length is big-endian */
} csf_command_t;

typedef struct
{
    uint32_t offset;
    uint8_t digest_algorithm;
    uint8_t source_index;
} srk_table_info_t;

typedef struct
{
    uint32_t offset;
    uint8_t flags;
    uint8_t source_index;
    uint8_t target_index;
} key_info_t;

typedef struct
{
    uint32_t offset;
} blob_info_t;

typedef struct
{
    uint32_t start;   // Block start offset
    uint32_t length;  // Block length
} auth_block_t;

/*===========================================================================
                          LOCAL FUNCTION PROTOTYPES
=============================================================================*/

/*===========================================================================
                               LOCAL VARIABLES
=============================================================================*/

static srk_table_info_t srk_table_info[2]; /**< NXP and OEM SRK table info */
static key_info_t keys_info[8];            /**< Store key information */
static blob_info_t blobs_info[2];          /**< Store blob information */
static int keys_info_count = 0;
static int blobs_info_count = 0;
static uint32_t signatures[8]; /**< Store signature offsets */
static int signatures_count = 0;
static auth_block_t auth_blocks[8]; /**< Store authentication blocks */
static int auth_blocks_count = 0;
/*===========================================================================
                               GLOBAL VARIABLES
=============================================================================*/

/*===========================================================================
                               LOCAL FUNCTIONS
=============================================================================*/

/** Helper function to compute the cryptographic digest for a given data buffer.
 * 
 * @param md A pointer to the message digest algorithm (EVP_MD) to use for
 *        computation.
 * @param data A pointer to the buffer containing the data to hash.
 * @param data_len The length of the data buffer.
 * @param digest A pointer to the buffer where the computed digest
 *        will be stored.
 * @param digest_len A pointer to an unsigned integer that will hold the length
 *        of the computed digest.
 * 
 * @return 0 if successful, -1 if an error occurs during digest computation.
 */
static int compute_digest(const EVP_MD *md, const uint8_t *data,
                          size_t data_len, uint8_t *digest,
                          unsigned int *digest_len)
{
    EVP_MD_CTX *md_ctx = NULL;

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
    {
        fprintf(stderr, "Failed to create EVP_MD_CTX\n");
        return -1;
    }

    if (EVP_DigestInit_ex(md_ctx, md, NULL) <= 0)
    {
        fprintf(stderr, "EVP_DigestInit_ex failed\n");
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }

    if (EVP_DigestUpdate(md_ctx, data, data_len) <= 0)
    {
        fprintf(stderr, "EVP_DigestUpdate failed\n");
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }

    if (EVP_DigestFinal_ex(md_ctx, digest, digest_len) <= 0)
    {
        fprintf(stderr, "EVP_DigestFinal_ex failed\n");
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }

    EVP_MD_CTX_free(md_ctx);
    return 0;
}

/** Returns a string representation of the protocol tag based on the provided
 *  tag identifier.
 * 
 * @param pcl_tag The identifier of the protocol tag.
 * 
 * @return A constant string describing the protocol tag.
 */
static const char *get_pcl_tag_str(uint8_t pcl_tag)
{
    switch (pcl_tag)
    {
        case HAB_PCL_SRK:
            return "SRK certificate format";
        case HAB_PCL_X509:
            return "X.509v3 certificate format";
        case HAB_PCL_CMS:
            return "CMS/PKCS#7 signature format";
        case HAB_PCL_BLOB:
            return "SHW-specific wrapped key format";
        case HAB_PCL_AEAD:
            return "Proprietary AEAD MAC format";
        default:
            return "Unknown protocol tag";
    }
}

/** Returns a string representation of the algorithm tag based on the provided
 *  tag identifier.
 * 
 * @param alg_tag The identifier of the algorithm tag.
 * 
 * @return A constant string describing the algorithm tag.
 */
static const char *get_alg_tag_str(uint8_t alg_tag)
{
    switch (alg_tag)
    {
        case HAB_ALG_SHA1:
            return "SHA-1 algorithm";
        case HAB_ALG_SHA256:
            return "SHA-256 algorithm";
        case HAB_ALG_SHA384:
            return "SHA-384 algorithm";
        case HAB_ALG_SHA512:
            return "SHA-512 algorithm";
        default:
            return "Unknown algorithm";
    }
}

/** Returns a string representation of the engine tag based on the provided
 * tag identifier.
 * 
 * @param eng_tag The identifier of the engine tag.
 * 
 * @return A constant string describing the engine tag.
 */
static const char *get_eng_tag_str(uint8_t eng_tag)
{
    switch (eng_tag)
    {
        case HAB_ENG_ANY:
            return "Any";
        case HAB_ENG_DCP:
            return "DCP";
        case HAB_ENG_CAAM:
            return "CAAM";
        case HAB_ENG_CSU:
            return "CSU";
        case HAB_ENG_SNVS:
            return "SNVS";
        case HAB_ENG_OCOTP:
            return "OCOTP";
        case HAB_ENG_SW:
            return "SW";
        default:
            return "Unknown engine tag";
    }
}

/** Returns a string representation of the signature algorithm based on
 *  the provided algorithm tag.
 * 
 * @param sig_alg The identifier of the signature algorithm.
 * 
 * @return A constant string describing the signature algorithm.
 */
static const char *get_sig_alg_str(uint8_t sig_alg)
{
    switch (sig_alg)
    {
        case HAB_ALG_PKCS1:
            return "PKCS#1 RSA signature algorithm";
        case HAB_ALG_ECDSA:
            return "NIST ECDSA signature algorithm";
        default:
            return "Unknown algorithm";
    }
}

/** Maps cipher modes to their string representations.
 * 
 * @param mode The identifier of the cipher mode.
 * 
 * @return A constant string describing the cipher mode.
 */
static const char *get_cipher_mode_str(uint8_t mode)
{
    switch (mode)
    {
        case HAB_MODE_CCM:
            return "CCM (Counter with CBC-MAC)";
        default:
            return "Unknown Mode";
    }
}

/** Returns a string representation of the cipher algorithm based on
 * the provided algorithm identifier.
 * 
 * @param algo The identifier of the cipher algorithm.
 * 
 * @return A constant string describing the cipher algorithm. If the algorithm
 *         is unknown, a default string is returned.
 */
static const char *get_cipher_algo_str(uint8_t algo)
{
    switch (algo)
    {
        case HAB_ALG_AES:
            return "AES Algorithm ID";
        default:
            return "Unknown Algorithm";
    }
}

/** Processes the HAB_CMD_INS_KEY command from the CSF.
 * 
 * @param file A pointer to the image file.
 * @param cmd_offset The offset in the file where the command starts.
 * @param cmd_len The length of the command.
 * @param self_address The address of the CSF itself in memory.
 * @param ivt_offset The offset of the Image Vector Table (IVT) associated with this command.
 */
static void process_ins_key_command(FILE *file, long cmd_offset,
                                    uint16_t cmd_len, long self_address,
                                    long ivt_offset)
{

    uint8_t flags = 0;
    uint8_t pcl_tag = 0;
    uint8_t alg_tag = 0;
    uint8_t src_idx = 0;
    uint8_t tgt_idx = 0;
    long crt_off = 0;
    long blob_off = 0;

    /* Check for invalid arguments */
    if (file == NULL)
    {
        fprintf(stderr, "Invalid input argument: file is NULL\n");
        return;
    }

    if (cmd_len == HAB_CMD_INS_KEY_BASE_SIZE)
    {
        /* Read the values from the command structure */
        read_data(file, &flags, sizeof(uint8_t), cmd_offset + 3);
        read_data(file, &pcl_tag, sizeof(uint8_t), cmd_offset + 4);
        read_data(file, &alg_tag, sizeof(uint8_t), cmd_offset + 5);
        read_data(file, &src_idx, sizeof(uint8_t), cmd_offset + 6);
        read_data(file, &tgt_idx, sizeof(uint8_t), cmd_offset + 7);
        crt_off = read_word_be(
            file, cmd_offset + 8); /* Certificate offset in big-endian */

        print_with_indent("Flags: 0x%X\n", flags);
        print_with_indent("Protocol Tag: 0x%X (%s)\n", pcl_tag,
                          get_pcl_tag_str(pcl_tag));

        /* Process based on the protocol tag (pcl_tag) */
        if (pcl_tag == HAB_PCL_SRK)
        {
            /* Validate algorithm */
            if (alg_tag != HAB_ALG_SHA1 && alg_tag != HAB_ALG_SHA256)
            {
                fprintf(stderr, "Invalid digest algorithm\n");
                return;
            }
            /* Process SRK table based on the target index */
            if (tgt_idx == HAB_IDX_SRK_NXP)
            {
                srk_table_info[0].offset = crt_off;
                srk_table_info[0].digest_algorithm = alg_tag;
                srk_table_info[0].source_index = src_idx;
            }
            else if (tgt_idx == HAB_IDX_SRK_OEM)
            {
                srk_table_info[1].offset = crt_off;
                srk_table_info[1].digest_algorithm = alg_tag;
                srk_table_info[1].source_index = src_idx;
            }
            else
            {
                fprintf(stderr, "Invalid target index for SRK\n");
                return;
            }
            print_with_indent("Algorithm Tag: 0x%X (%s)\n", alg_tag,
                              get_alg_tag_str(alg_tag));
            print_with_indent("SRK Table processed\n");
        }
        else if (pcl_tag == HAB_PCL_X509)
        {
            /* Store key info for X.509 certificates */
            keys_info[keys_info_count].offset = crt_off;
            keys_info[keys_info_count].flags = flags;
            keys_info[keys_info_count].source_index = src_idx;
            keys_info[keys_info_count].target_index = tgt_idx;
            keys_info_count++;
            print_with_indent("X.509 Key processed\n");
        }
        else if (pcl_tag == HAB_PCL_BLOB)
        {
            /* Adjust the offset for the blob */
            blob_off = crt_off - self_address + ivt_offset;
            blobs_info[blobs_info_count].offset = blob_off;
            blobs_info_count++;
            print_with_indent("Blob processed at adjusted offset 0x%lX\n",
                              blob_off);
        }
        else
        {
            print_with_indent("Unknown protocol tag: 0x%X\n", pcl_tag);
        }

        print_with_indent("Source Index: %d\n", src_idx);
        print_with_indent("Target Index: %d\n", tgt_idx);
        print_with_indent("Certificate Offset: 0x%lX\n", crt_off);
    }
    else
    {
        print_with_indent("Invalid command length for HAB_CMD_INS_KEY\n");
    }
}

/** Processes the HAB_CMD_AUT_DAT command from the CSF.
 * 
 * @param file A pointer to the image file.
 * @param cmd_offset The offset in the file where the command starts.
 * @param cmd_len The length of the command.
 * @param csf_offset The offset in the file where the CSF starts.
 */
static void process_aut_dat_command(FILE *file, long cmd_offset,
                                    uint16_t cmd_len, long csf_offset)
{
    uint8_t flags = 0;
    uint8_t key_idx = 0;
    uint8_t pcl_tag = 0;
    uint8_t eng_tag = 0;
    uint8_t eng_cfg = 0;
    uint32_t aut_start = 0;
    int index = 0;
    uint32_t blk_start = 0;
    uint32_t blk_len = 0;

    /* Check for invalid arguments */
    if (file == NULL)
    {
        fprintf(stderr, "Invalid input argument: file is NULL\n");
        return;
    }

    /* Read the values from the command structure */
    read_data(file, &flags, sizeof(uint8_t), cmd_offset + 3);
    read_data(file, &key_idx, sizeof(uint8_t), cmd_offset + 4);
    read_data(file, &pcl_tag, sizeof(uint8_t), cmd_offset + 5);
    read_data(file, &eng_tag, sizeof(uint8_t), cmd_offset + 6);
    read_data(file, &eng_cfg, sizeof(uint8_t), cmd_offset + 7);
    aut_start = read_word_be(
        file, cmd_offset + 8); /* Authentication start in big-endian */

    /* Print the parsed values */
    print_with_indent("Flags: 0x%X\n", flags);
    print_with_indent("Key Index: %d\n", key_idx);
    print_with_indent("Protocol Tag: 0x%X (%s)\n", pcl_tag,
                      get_pcl_tag_str(pcl_tag));
    print_with_indent("Engine Tag: 0x%X (%s)\n", eng_tag,
                      get_eng_tag_str(eng_tag));
    print_with_indent("Engine Configuration: 0x%X\n", eng_cfg);
    print_with_indent("Authentication Data Start: 0x%X\n", aut_start);

    /* Store the signature offset */
    signatures[signatures_count++] = csf_offset + aut_start;

    /* Process each block of data */
    print_with_indent("Processing Authentication Data Blocks:\n");
    increase_indent();

    while (index != ((cmd_len - 12) / 8))
    {
        blk_start = read_word_be(file, cmd_offset + 12 + index * 8);
        blk_len = read_word_be(file, cmd_offset + 16 + index * 8);

        /* Store the block information */
        auth_blocks[auth_blocks_count].start = blk_start;
        auth_blocks[auth_blocks_count].length = blk_len;
        auth_blocks_count++;

        /* Print block details */
        print_with_indent("Block Start: 0x%X\n", blk_start);
        print_with_indent("Block Length: %d bytes\n", blk_len);

        index++;
    }

    decrease_indent();
}

/** Helper function to print the key data (modulus and exponent for RSA, or X
 *  and Y coordinates for ECDSA).
 * 
 * @param file A pointer to the file containing the key data.
 * @param offset The offset in the file where the key data starts.
 * @param mod_x_len The length of the modulus (for RSA) or X coordinate (for ECDSA).
 * @param exp_y_len The length of the exponent (for RSA) or Y coordinate (for ECDSA).
 * @param alg_type The algorithm type (e.g., RSA or ECDSA).
 * 
 * @return 0 if successful, -1 if an error occurs.
 */
static int print_srk_key(FILE *file, long offset, uint16_t mod_x_len,
                         uint16_t exp_y_len, uint8_t alg_type)
{

    uint8_t *modulus_or_x = NULL;
    uint8_t *exponent_or_y = NULL;

    /* Check for invalid arguments */
    if (file == NULL)
    {
        fprintf(stderr, "Invalid input argument: file is NULL\n");
        return -1;
    }

    /* Allocate memory for modulus_or_x and exponent_or_y based on lengths */
    modulus_or_x = malloc(mod_x_len);
    exponent_or_y = malloc(exp_y_len);

    if (!modulus_or_x || !exponent_or_y)
    {
        fprintf(stderr, "Failed to allocate memory for key components\n");
        free(modulus_or_x);
        free(exponent_or_y);
        return -1;
    }

    /* Read modulus_or_x and exponent_or_y from the file */
    read_data(file, modulus_or_x, mod_x_len, offset);
    read_data(file, exponent_or_y, exp_y_len, offset + mod_x_len);

    /* Print modulus or X coordinate as a byte array */

    dump_buffer_with_label((alg_type == HAB_ALG_PKCS1) ? "Modulus: "
                                                       : "X Coordinate: ",
                           modulus_or_x, mod_x_len);
    /* Print exponent or Y coordinate as a byte array */
    dump_buffer_with_label((alg_type == HAB_ALG_PKCS1) ? "Exponent: "
                                                       : "Y Coordinate: ",
                           exponent_or_y, exp_y_len);

    /* Free allocated memory */
    free(modulus_or_x);
    free(exponent_or_y);

    return 0;
}

/** Prints the Super Root Key (SRK) table information from the file.
 * 
 * @param file A pointer to the image file.
 * @param csf_offset The offset in the file where the Command Sequence File (CSF) starts.
 * @param srk_table_info An array of srk_table_info_t structures representing the SRK table information.
 */
static void print_srk_table(FILE *file, long csf_offset,
                            srk_table_info_t srk_table_info[])
{
    long srk_table_offset = 0;
    long srk_table_len = 0;
    uint8_t srk_table_tag = 0;
    uint8_t srk_table_hab_vers = 0;
    uint8_t src_idx = 0;
    uint8_t dgst_alg = 0;
    int index = 0;
    uint8_t srk_hashes[SHA256_DIGEST_LENGTH] = {0};
    uint8_t srk_table_hash[SHA256_DIGEST_LENGTH] = {0};
    uint8_t accumulated_hashes[EVP_MAX_MD_SIZE * 10] = {0};
    uint8_t srk_record_hash[EVP_MAX_MD_SIZE] = {0};
    const EVP_MD *md = NULL;
    unsigned int md_len = 0;
    uint8_t *srk = NULL;
    uint16_t srk_len = 0;
    uint16_t mod_x_len = 0;
    uint16_t exp_y_len = 0;
    uint8_t sig_alg = 0;
    uint8_t srk_flg = 0;
    uint32_t modulus = 0;
    uint32_t exponent = 0;
    uint8_t curve = 0;

    /* Check for invalid arguments */
    if (file == NULL)
    {
        fprintf(stderr, "Invalid input argument: file NULL\n");
        return;
    }

    src_idx = srk_table_info[0].source_index;
    dgst_alg = srk_table_info[0].digest_algorithm;

    /* Initialize hash context */
    if (dgst_alg == HAB_ALG_SHA1)
    {
        md = EVP_sha1();
    }
    else if (dgst_alg == HAB_ALG_SHA256)
    {
        md = EVP_sha256();
    }
    else
    {
        fprintf(stderr, "Unsupported digest algorithm\n");
        return;
    }

    print_with_indent("Dumping SRK table\n");
    srk_table_offset = srk_table_info[0].offset + csf_offset;
    print_with_indent("Offset: 0x%lX\n", srk_table_offset);
    /* Read and validate SRK table tag */
    srk_table_tag = read_byte(file, srk_table_offset);
    if (srk_table_tag != HAB_TAG_CRT)
    {
        fprintf(stderr, "Invalid SRK table tag\n");
        return;
    }
    print_with_indent("SRK Table Tag: 0x%X\n", srk_table_tag);

    /* Read SRK table length */
    srk_table_len = read_short_be(file, srk_table_offset + 1);
    print_with_indent("SRK Table Length: %ld bytes\n", srk_table_len);

    if ((srk_table_len < 4) || (srk_table_len > MAX_SRK_TABLE_LEN))
    {
        fprintf(stderr, "ERROR: Invalid SRK table length: %ld bytes\n",
                srk_table_len);
        return;
    }

    /* Read HAB version and validate */
    srk_table_hab_vers = read_byte(file, srk_table_offset + 3);
    if ((srk_table_hab_vers & 0xF0) != 0x40)
    {
        fprintf(stderr, "Invalid HAB version (not v4)\n");
        return;
    }
    print_with_indent("HAB Version: 0x%X\n", srk_table_hab_vers);

    /* Move past the header */
    srk_table_offset += 4;
    srk_table_len -= 4;

    /* Buffer to accumulate individual SRK record hashes */

    /* Iterate over SRK records in the table */
    while (srk_table_len > 0)
    {

        print_with_indent("Processing SRK record %d\n", index + 1);
        increase_indent();

        /* Read SRK record tag */
        uint8_t srk_record_tag = read_byte(file, srk_table_offset);
        if (srk_record_tag != HAB_KEY_PUBLIC)
        {
            fprintf(stderr, "Invalid SRK record tag\n");
            return;
        }
        print_with_indent("SRK Record Tag: 0x%X\n", srk_record_tag);

        /* Read SRK length */
        srk_len = read_short_be(file, srk_table_offset + 1);
        print_with_indent("SRK Length: %d bytes\n", srk_len);

        if (srk_len > MAX_SRK_RECORD_LEN)
        {
            fprintf(stderr, "Invalid SRK record length\n");
            return;
        }

        /* Read SRK signature algorithm */
        sig_alg = read_byte(file, srk_table_offset + 3);
        print_with_indent("Signature Algorithm: 0x%X (%s)\n", sig_alg,
                          get_sig_alg_str(sig_alg));

        /* Read SRK flags */
        srk_flg = read_byte(file, srk_table_offset + 7);
        print_with_indent("SRK Flags: 0x%X\n", srk_flg);

        /* Process RSA or ECDSA algorithms */
        if (sig_alg == HAB_ALG_PKCS1)
        {
            mod_x_len = read_short_be(file, srk_table_offset + 8);
            exp_y_len = read_short_be(file, srk_table_offset + 10);
            print_with_indent("Modulus Length: %d bytes\n", mod_x_len);
            print_with_indent("Exponent Length: %d bytes\n", exp_y_len);

            /* Validate the total length */
            if ((mod_x_len + exp_y_len + 12) != srk_len)
            {
                fprintf(stderr, "Invalid SRK length");
                return;
            }

            /* Store modulus and exponent for the current SRK index */
            modulus = read_word_be(file, srk_table_offset + 12);
            exponent = read_word_be(file, srk_table_offset + 12 + mod_x_len);
        }
        else if (sig_alg == HAB_ALG_ECDSA)
        {
            /* ECDSA processing */
            curve = read_byte(file, srk_table_offset + 8);
            mod_x_len = read_short_be(file, srk_table_offset + 10);
            print_with_indent("Curve: 0x%X\n", curve);
            print_with_indent("Key Length: %d bytes\n", mod_x_len);
        }
        else
        {
            fprintf(stderr, "Unknown signature algorithm\n");
            return;
        }

        if ((mod_x_len > MAX_MOD_X_LEN) || (exp_y_len > MAX_EXP_Y_LEN))
        {
            fprintf(stderr, "Invalid mod_x length or exp_y length\n");
            return;
        }

        /* Print modulus/exponent or X/Y for RSA/ECDSA based on the algorithm */
        if (print_srk_key(file, srk_table_offset + 12, mod_x_len, exp_y_len,
                          sig_alg) < 0)
        {
            fprintf(stderr, "Failed to print SRK key\n");
            return;
        }

        srk = malloc(srk_len);
        if (!srk)
        {
            fprintf(stderr, "Failed to allocate memory for SRK table\n");
            return;
        }
        read_data(file, srk, srk_len, srk_table_offset);
        /* Compute the hash of the individual SRK record using the helper function */
        if (compute_digest(md, srk, srk_len, srk_record_hash, &md_len) < 0)
        {
            fprintf(stderr, "Failed to compute digest for SRK record\n");
            free(srk);
            return;
        }
        free(srk);

        memcpy(&accumulated_hashes[md_len * index], srk_record_hash, md_len);

        /* Move to the next SRK record */
        srk_table_offset += srk_len;
        srk_table_len -= srk_len;
        index++;

        decrease_indent();
    }
    /* Compute the SRK hash over the accumulated SRK record hashes */
    if (compute_digest(md, accumulated_hashes, md_len * index, srk_table_hash,
                       &md_len) < 0)
    {
        fprintf(stderr, "Failed to compute final SRK table hash\n");
        return;
    }

    dump_buffer_with_label("SRK Table Hash: ", srk_table_hash, md_len);
}

/** Read and prints the information of keys from the file.
 * 
 * @param file A pointer to the image file.
 * @param csf_offset The offset in the file where the Command Sequence File (CSF) starts.
 * @param keys_info A pointer to an array of key_info_t structures representing the keys.
 * @param num_keys The number of keys to print.
 * 
 * @return 0 if successful, -1 if an error occurs.
 */
static int print_keys(FILE *file, long csf_offset, key_info_t *keys_info,
                      int num_keys)
{
    long key_offset = 0;
    uint8_t key_tag = 0;
    uint16_t key_len = 0;
    uint8_t key_hab_vers = 0;
    unsigned char *key_data = NULL;
    X509 *x509_cert = NULL;
    const unsigned char *p = NULL;
    int i = 0;

    /* Check for invalid arguments */
    if ((file == NULL) || (keys_info == NULL))
    {
        fprintf(stderr, "Invalid input argument: NULL\n");
        return -1;
    }

    for (i = 0; i < num_keys; i++)
    {
        key_offset = csf_offset + keys_info[i].offset;

        print_with_indent("Key %d:\n", keys_info[i].target_index);
        increase_indent();

        /* Read and validate the key tag */
        key_tag = read_byte(file, key_offset);
        if (key_tag != HAB_TAG_CRT)
        {
            fprintf(stderr, "Error: Invalid Key tag at offset 0x%lX\n",
                    key_offset);
            decrease_indent();
            continue;
        }
        print_with_indent("Offset: 0x%lX\n", key_offset);

        /* Read the key length */
        key_len = read_short_be(file, key_offset + 1);
        print_with_indent("Length: %d bytes\n", key_len);

        if (key_len > MAX_KEY_LEN)
        {
            fprintf(stderr, "Invalid key length\n");
            decrease_indent();
            return -1;
        }

        /* Allocate memory for the key data and read it from the file */
        key_data = malloc(key_len);
        if (!key_data)
        {
            fprintf(stderr, "Failed to allocate memory for key data\n");
            decrease_indent();
            return -1;
        }
        read_data(file, key_data, key_len, key_offset);

        /* Validate the HAB version (must be v4.x) */
        key_hab_vers = key_data[3];
        if ((key_hab_vers & 0xF0) != 0x40)
        {
            fprintf(stderr, "Error: Invalid HAB version: 0x%X\n", key_hab_vers);
            free(key_data);
            decrease_indent();
            continue;
        }
        print_with_indent("HAB Version: 0x%X\n", key_hab_vers);

        /* ASN.1 decode the certificate  */
        print_with_indent("ASN.1 decoding the X.509 certificate...\n");
        p = key_data + 4; /* Skip the first 4 bytes (header) */
        x509_cert = d2i_X509(NULL, &p, key_len - 4);
        if (!x509_cert)
        {
            fprintf(stderr, "Failed to decode X.509 certificate\n");
            free(key_data);
            decrease_indent();
            continue;
        }

        X509_print_fp(stdout, x509_cert);

        X509_free(x509_cert);
        free(key_data);
        decrease_indent();
    }
    return 0;
}

/** Process and prints the information of blobs from the image file.
 * 
 * @param file A pointer to the image file.
 * @param blobs_info A pointer to an array of blob_info_t structures representing the blobs.
 * @param num_blobs The number of blobs to print.
 * 
 * @return 0 if successful, -1 if an error occurs.
 */
static int print_blobs(FILE *file, blob_info_t *blobs_info, int num_blobs)
{

    uint8_t cipher_mode = 0;
    uint8_t cipher_algo = 0;
    uint8_t unwrapped_size = 0;
    uint8_t flags = 0;
    long blob_offset = 0;
    uint8_t blob_tag = 0;
    uint16_t blob_len = 0;
    uint8_t blob_hab_vers = 0;
    unsigned char *blob_data = NULL;
    int i = 0;

    /* Check for invalid arguments */
    if ((file == NULL) || (blobs_info == NULL))
    {
        fprintf(stderr, "Invalid input argument: NULL\n");
        return -1;
    }

    for (i = 0; i < num_blobs; i++)
    {
        blob_offset = blobs_info[i].offset;

        print_with_indent("Blob %d:\n", i + 1);
        increase_indent();

        /* Read and validate the blob tag */
        blob_tag = read_byte(file, blob_offset);
        if (blob_tag != HAB_TAG_WRP)
        {
            fprintf(stderr, "Error: Invalid Blob tag at offset 0x%lX\n",
                    blob_offset);
            decrease_indent();
            continue;
        }
        print_with_indent("Offset: 0x%lX\n", blob_offset);

        /* Read the blob length */
        blob_len = read_short_be(file, blob_offset + 1);
        print_with_indent("Length: %d bytes\n", blob_len);

        if (blob_len <= 0 || blob_len > 76)
        {
            fprintf(stderr, "Invalid blob size\n");
            decrease_indent();
            return -1;
        }

        /* Allocate memory for the blob data and read it from the file */
        blob_data = malloc(blob_len);
        if (!blob_data)
        {
            fprintf(stderr, "Failed to allocate memory for blob data\n");
            decrease_indent();
            return -1;
        }
        read_data(file, blob_data, blob_len, blob_offset);

        /* Validate the HAB version (must be v4.x) */
        blob_hab_vers = blob_data[3];
        if ((blob_hab_vers & 0xF0) != 0x40)
        {
            fprintf(stderr, "Error: Invalid HAB version: 0x%X\n",
                    blob_hab_vers);
            free(blob_data);
            decrease_indent();
            continue;
        }
        print_with_indent("HAB Version: 0x%X\n", blob_hab_vers);

        cipher_mode = blob_data[4];
        cipher_algo = blob_data[5];
        unwrapped_size = blob_data[6];
        flags = blob_data[7];

        print_with_indent("Cipher Mode: 0x%X (%s)\n", cipher_mode,
                          get_cipher_mode_str(cipher_mode));
        print_with_indent("Cipher Algorithm: 0x%X (%s)\n", cipher_algo,
                          get_cipher_algo_str(cipher_algo));
        print_with_indent("Unwrapped Size: %d bytes\n", unwrapped_size);
        print_with_indent("Flags: 0x%X\n", flags);

        free(blob_data);
        decrease_indent();
    }
    return 0;
}

/** Dumps the contents of a CMS_ContentInfo structure.
 * 
 * @param cms A pointer to the CMS_ContentInfo structure to be dumped.
 */
static void dump_cms_content_info(CMS_ContentInfo *cms)
{
    BIO *out = NULL;

    /* Check for invalid arguments */
    if (cms == NULL)
    {
        fprintf(stderr, "Invalid input argument: cms is NULL\n");
        return;
    }

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (!out)
    {
        fprintf(stderr, "Error creating BIO\n");
        return;
    }

    if (!CMS_ContentInfo_print_ctx(out, cms, 0, NULL))
    {
        fprintf(stderr, "Error printing CMS_ContentInfo\n");
    }

    BIO_free(out);
}

/**
 * @brief Prints the signatures from the file.
 * 
 * @param file A pointer to the image file.
 * @param signatures A pointer to an array of 32-bit unsigned integers representing the signatures.
 * @param num_signatures The number of signatures to print.
 * 
 * @return 0 if successful, -1 otherwise.
 */
int print_signatures(FILE *file, uint32_t *signatures, int num_signatures)
{

    const unsigned char *p = NULL;
    CMS_ContentInfo *cms = NULL;
    long sig_offset = 0;
    uint8_t tag = 0;
    uint16_t sig_len = 0;
    uint8_t sig_hab_vers = 0;
    unsigned char *sig_data = NULL;
    int i = 0;

    /* Check for invalid arguments */
    if ((file == NULL) || (signatures == NULL))
    {
        fprintf(stderr, "Invalid input argument: NULL\n");
        return -1;
    }

    for (i = 0; i < num_signatures; i++)
    {
        sig_offset = signatures[i];

        print_with_indent("Signature %d:\n", i + 1);
        increase_indent();

        /* Read and validate the signature tag */
        tag = read_byte(file, sig_offset);
        if (tag != HAB_TAG_SIG && tag != HAB_TAG_MAC)
        {
            fprintf(stderr, "Error: Invalid Signature tag at offset 0x%lX\n",
                    sig_offset);
            decrease_indent();
            continue;
        }
        print_with_indent("Offset: 0x%lX\n", sig_offset);

        /* Read the signature length */
        sig_len = read_short_be(file, sig_offset + 1);
        print_with_indent("Length: %d bytes\n", sig_len);

        if (sig_len > MAX_SIG_LEN)
        {
            fprintf(stderr, "Invalid signature length\n");
            decrease_indent();
            return -1;
        }

        /* Allocate memory for the signature data and read it from the file */
        sig_data = malloc(sig_len);
        if (!sig_data)
        {
            fprintf(stderr, "Failed to allocate memory for signature data\n");
            decrease_indent();
            return -1;
        }
        read_data(file, sig_data, sig_len, sig_offset);

        /* Validate the HAB version (must be v4.x) */
        sig_hab_vers = sig_data[3];
        if ((sig_hab_vers & 0xF0) != 0x40)
        {
            fprintf(stderr, "Error: Invalid HAB version: 0x%X\n", sig_hab_vers);
            free(sig_data);
            decrease_indent();
            continue;
        }
        print_with_indent("HAB Version: 0x%X\n", sig_hab_vers);

        /* Handle ASN.1 decoding for CMS signatures */
        if (tag == HAB_TAG_SIG)
        {
            print_with_indent("ASN.1 decoding of CMS signature...\n");
            increase_indent();

            /* Decode the CMS signature */
            p = sig_data + 4; /* Skip the first 4 bytes (header) */
            cms = d2i_CMS_ContentInfo(NULL, &p, sig_len - 4);
            if (!cms)
            {
                fprintf(stderr, "Failed to decode CMS signature\n");
                free(sig_data);
                decrease_indent();
                continue;
            }

            /* Print decoded CMS structure */
            dump_cms_content_info(cms);
            CMS_ContentInfo_free(cms);

            decrease_indent();
        }
        /* Handle MAC signatures (for now, we simply dump it) */
        else if (tag == HAB_TAG_MAC)
        {
            dump_buffer_with_label("MAC data: ", sig_data, sig_len);
        }

        free(sig_data);
        decrease_indent();
    }
    return 0;
}

/**
 * Parses a single command from the Command Sequence File (CSF) at the
 * specified offset in file.
 * 
 * @param file A pointer to the file containing the CSF command.
 * @param offset The offset in the file where the CSF command starts.
 * @param remaining_length The remaining length of the CSF commands to be parsed.
 * @param csf_offset The offset in the file where the CSF starts.
 * @param self_address The address of the CSF itself in memory.
 * @param ivt_offset The offset of the Image Vector Table (IVT) associated with this CSF.
 */
static void parse_csf_command(FILE *file, long offset, int remaining_length,
                              long csf_offset, long self_address,
                              long ivt_offset)
{
    uint16_t cmd_length = 0;
    csf_command_t cmd_header = {0};

    /* Check for invalid arguments */
    if (file == NULL)
    {
        fprintf(stderr, "Invalid input argument: file is NULL\n");
        return;
    }

    while (remaining_length > 0)
    {
        /* Read the command header (tag and length) */
        read_data(file, &cmd_header, sizeof(csf_command_t), offset);

        cmd_length = (cmd_header.len[0] << 8) | cmd_header.len[1];

        if (cmd_length <= 0 || cmd_length > remaining_length)
        {
            fprintf(stderr, "ERROR: Invalid command length: %d\n", cmd_length);
            return;
        }

        print_with_indent("Command:\n");
        increase_indent();
        print_with_indent("Command Tag: 0x%X\n", cmd_header.tag);
        print_with_indent("Command Length: %d bytes\n", cmd_length);

        switch (cmd_header.tag)
        {
            case HAB_CMD_SET:
                print_with_indent("Processing 'Set' command...\n");
                break;
            case HAB_CMD_INS_KEY:
                print_with_indent("Processing 'Install Key' command...\n");
                process_ins_key_command(file, offset, cmd_length, self_address,
                                        ivt_offset);
                break;
            case HAB_CMD_AUT_DAT:
                print_with_indent(
                    "Processing 'Authenticate Data' command...\n");
                process_aut_dat_command(file, offset, cmd_length, csf_offset);
                break;
            case HAB_CMD_WRT_DAT:
                print_with_indent("Processing 'Write Data' command...\n");
                break;
            case HAB_CMD_CHK_DAT:
                print_with_indent("Processing 'Check Data' command...\n");
                break;
            case HAB_CMD_NOP:
                print_with_indent("Processing 'No Operation' command...\n");
                break;
            case HAB_CMD_INIT:
                print_with_indent("Processing 'Initialise' command...\n");
                break;
            case HAB_CMD_UNLK:
                print_with_indent("Processing 'Unlock' command...\n");
                break;
            default:
                print_with_indent("Unknown Command: 0x%X\n", cmd_header.tag);
                break;
        }

        decrease_indent();

        /* Move to the next command in the CSF */
        offset += cmd_length;
        remaining_length -= cmd_length;
    }
}

/** Parses the Command Sequence File (CSF) from the file at the specified offset.
 * 
 * @param file A pointer to the file containing the CSF.
 * @param offset The offset in the file where the CSF starts.
 * @param self_address The address of the CSF itself in memory.
 * @param ivt_offset The offset of the Image Vector Table (IVT) associated with
 *        this CSF.
 */
static void parse_csf(FILE *file, long offset, long self_address,
                      long ivt_offset)
{
    hab_hdr_t csf_header = {0};
    uint32_t csf_length = 0;
    uint8_t csf_hab_version = 0;

    /* Check for invalid arguments */
    if (file == NULL)
    {
        fprintf(stderr, "Invalid input argument: file is NULL\n");
        return;
    }

    /* Read the CSF header (tag, length, and parameters) */
    read_data(file, &csf_header, sizeof(hab_hdr_t), offset);

    /* Convert the length from big-endian to host-endian */
    csf_length = (csf_header.len[0] << 8) | csf_header.len[1];

    if (csf_header.tag != HAB_TAG_CSF)
    {
        fprintf(stderr, "Invalid CSF tag\n");
        exit(EXIT_FAILURE);
    }

    /* Read the HAB version */
    read_data(file, &csf_hab_version, sizeof(uint8_t), offset + 3);

    /* Check if the HAB version is v4 (top 4 bits should be 0x4) */
    if ((csf_hab_version & 0xF0) != 0x40)
    {
        fprintf(stderr, "Invalid HAB version (not v4)\n");
        exit(EXIT_FAILURE);
    }

    print_with_indent("Command Sequence File (CSF):\n");

    print_with_indent("Offset: 0x%lX\n", offset);
    print_with_indent("CSF Tag: 0x%X\n", csf_header.tag);
    print_with_indent("CSF Length: %d bytes\n", csf_length);
    print_with_indent("HAB Version: 0x%X\n", csf_hab_version);

    /* Validate CSF length before parsing */
    if ((csf_length < 4) || (csf_length > MAX_CSF_LEN))
    {
        fprintf(stderr, "ERROR: Invalid CSF length: %u\n", csf_length);
        exit(EXIT_FAILURE);
    }

    /* Start parsing commands after the header (offset + 4 bytes) */
    parse_csf_command(file, offset + 4, csf_length - 4, offset, self_address,
                      ivt_offset);
}

/** Parses the Image Vector Table (IVT) from the file at the specified offset.
 * 
 * @param file A pointer to the file containing the IVT.
 * @param offset The offset in the file where the IVT starts.
 */
static void parse_ivt(FILE *file, long offset)
{

    hab_hdr_t ivt_header = {0};
    uint16_t ivt_len = 0;
    uint32_t entry_addr = 0;
    uint32_t csf_addr = 0;
    uint32_t self_addr = 0;
    uint32_t csf_offset = 0;
    uint32_t ivt_offset = 0;
    uint8_t ivt_version = 0;
    uint16_t expected_len = 0;
    uint8_t ivt_hab_vers = 0;
    uint32_t ivt_field_value = 0;

    /* Check for invalid arguments */
    if (file == NULL)
    {
        fprintf(stderr, "Invalid input argument: file is NULL\n");
        return;
    }

    read_data(file, &ivt_header, sizeof(hab_hdr_t), offset);

    ivt_len = (ivt_header.len[0] << 8) | ivt_header.len[1];

    switch (ivt_header.tag)
    {
        case HAB_TAG_IVT0:
            ivt_version = 0;
            expected_len = HAB_IVT_V0_LEN;
            break;
        case HAB_TAG_IVT1:
            ivt_version = 1;
            expected_len = HAB_IVT_V1_LEN;
            break;
        default:
            fprintf(stderr, "Invalid IVT tag\n");
            exit(EXIT_FAILURE);
            break;
    }

    if (ivt_len != expected_len)
    {
        fprintf(stderr, "Invalid IVT length\n");
        exit(EXIT_FAILURE);
    }

    print_with_indent("Image Vector Table:\n");
    increase_indent();

    print_with_indent("Offset: 0x%lX\n", offset);

    print_with_indent("IVT Tag: 0x%X\n", ivt_header.tag);
    print_with_indent("IVT Version: %d\n", ivt_version);
    print_with_indent("IVT Length: 0x%X\n", ivt_len);

    /* Read the HAB version (1 byte) */
    read_data(file, &ivt_hab_vers, sizeof(uint8_t), offset + 3);
    /* Check if the HAB version is v4 (top 4 bits should be 0x4) */
    if ((ivt_hab_vers & 0xF0) != 0x40)
    {
        fprintf(stderr, "Invalid HAB version (not v4)\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        print_with_indent("HAB Version: 0x%X\n", ivt_hab_vers);
    }

    if (ivt_header.tag == HAB_TAG_IVT1)
    {
        fprintf(stderr, "IVT v1 not yet supported\n");
        exit(EXIT_FAILURE);
    }

    /* IVT field information for IVT0 */
    ivt_field_t ivt_info[] = {
        {"Entry", offset + 4, 4},      {"DCD", offset + 12, 4},
        {"Boot Data", offset + 16, 4}, {"Self", offset + 20, 4},
        {"CSF", offset + 24, 4},
    };

    for (int i = 0; i < sizeof(ivt_info) / sizeof(ivt_info[0]); i++)
    {
        /* Read the 4-byte field (all fields are 32-bit) */
        read_word(file, &ivt_field_value, ivt_info[i].offset);
        print_with_indent("%s: 0x%X\n", ivt_info[i].name, ivt_field_value);
    }

    read_word(file, &entry_addr, offset + 4);
    read_word(file, &self_addr, offset + 20);
    read_word(file, &csf_addr, offset + 24);

    csf_offset = csf_addr - self_addr + offset;
    ivt_offset = offset;

    if (csf_addr != 0)
    {
        parse_csf(file, csf_offset, self_addr, ivt_offset);
    }

    print_srk_table(file, csf_offset, srk_table_info);

    print_keys(file, csf_offset, &keys_info[0], keys_info_count);

    print_blobs(file, &blobs_info[0], blobs_info_count);

    print_signatures(file, &signatures[0], signatures_count);
}

/**
 * Displays the usage information for the tool.
 */
static void print_usage()
{
    printf("Usage: %s [options] <image> <offset>\n", g_tool_name);
    printf("Options:\n");
    printf("  -h           Display this help message.\n");
    printf("  -v           Display the version information.\n");
}

/*===========================================================================
                               GLOBAL FUNCTIONS
=============================================================================*/

/** main
 *
 * Entry point main function for the app, processes input arguments and
 * call necessary local function to verify an image.
 *
 * @param[in] argc, number of arguments in argv
 *
 * @param[in] argv, array of arguments.
 *
 * @pre  none
 *
 * @post  if successful, verify the image.
 *
 * @returns #EXIT_SUCCESS on success and #EXIT_FAILURE otherwise.
 */

int main(int argc, char *argv[])
{
    const char *filename = NULL;
    long offset = 0;
    FILE *file = NULL;
    int i = 0;

    /* Parse command-line options */
    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-h") == 0)
        {
            print_usage();
            return EXIT_SUCCESS;
        }
        else if (strcmp(argv[i], "-v") == 0)
        {
            printf("%s version %s\n", g_tool_name, g_tool_version);
            return EXIT_SUCCESS;
        }
    }

    if (argc < 3)
    {
        print_usage();
        return EXIT_FAILURE;
    }

    filename = argv[1];
    offset = strtol(argv[2], NULL, 0);

    if (errno == ERANGE)
    {
        perror("Invalid offset");
        exit(EXIT_FAILURE);
    }

    /* Initialize OpenSSL context */
    openssl_initialize();

    file = fopen(filename, "rb");
    if (!file)
    {
        perror("Failed to open file");
        return 1;
    }

    print_with_indent("Notice: %s is intended solely for experimentation and "
                      "debugging purposes.\n",
                      g_tool_name);
    print_with_indent("It should not be considered as proof or validation of a "
                      "good HABv4 image under any circumstances.\n");
    print_with_indent(
        "For official verification and container integrity checks, users must "
        "proceed with the recommended secure boot procedures,\n");
    print_with_indent("such as using the `hab_status` command as outlined in "
                      "the relevant documentation.\n\n");

    print_with_indent("File: %s\n", filename);
    print_with_indent("Offset: 0x%lX\n", offset);

    /* Parse provided file at given offset */
    parse_ivt(file, offset);

    fclose(file);

    return EXIT_SUCCESS;
}
