// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

/*===========================================================================*/
/**
 *   @file    ahab_image_verifier.c
 *
 *   @brief   Parse AHAB containers.
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
#include "ahab_types.h"
#include "openssl_helper.h"
#include "ssl_backend.h"
#include "verifier_helper.h"
#include "version.h"

/*===========================================================================
                               LOCAL CONSTANTS
=============================================================================*/
enum parse_error_e
{
    PARSE_ERROR_OK = 0,
    PARSE_ERROR_INCORRECT_SIZE,
    PARSE_ERROR_BAD_HEADER_VERSION,
    PARSE_ERROR_INCORRECT_TAG,
    PARSE_ERROR_TOO_MANY_IMAGES,
    PARSE_ERROR_BAD_VALUE,
    PARSE_ERROR_NULL,
    PARSE_ERROR_KO
};

#define CONTAINER_OFFSET_INCREMENT 0x400

#define MAX_SRK_RECORDS 4

/* For safety purpose */
#define MAX_MODULUS_X_PK_LENGTH 2592U /* Dilithium5/ML-DSA87 PK */
#define MAX_EXPONENT_Y_LENGTH 66U     /* ECC P-521 */
#define MAX_SIGNATURE_LENGTH 4627U    /* Dilithium5/ML-DSA87 Sig */
#define MAX_SRK_DATA_LENGTH MAX_MODULUS_X_PK_LENGTH + 8U
#define MAX_KEY_SIZE (MAX_MODULUS_X_PK_LENGTH + MAX_EXPONENT_Y_LENGTH)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

read_certificate_fptr read_certificate = ssl_read_certificate;
const char *g_tool_name = "ahab_image_verifier"; /**< Global holds tool name */
const char *g_tool_version = CST_VERSION; /**< Global holds tool version */

static char *certificate_permissions_str[] = {
    "",
    "Sign container",
    "Debug SCU",
    "Debug CM4",
    "Debug Apps VPU",
    "Fuse SCU ver LC",
    "Fuse monotonic counter",
    "Fuse HDCP",
    "Fuse patch",
};

/*===========================================================================
                  LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
=============================================================================*/

/*===========================================================================
                          LOCAL FUNCTION PROTOTYPES
=============================================================================*/

/*===========================================================================
                               LOCAL VARIABLES
=============================================================================*/

static uint8_t g_srk_selection = 0;

/* Wrapper structure for SRK record */
struct ahab_srk_record
{
    struct ahab_container_srk_s record;
    uint8_t *modulus_or_x;
    uint8_t *exponent_or_y;
    uint8_t *srk_data_hash;
};

/* Wrapper structure for SRK data */
struct ahab_srk_data
{
    struct ahab_container_srk_data_s data;
    uint8_t *key;
};

/* Wrapper structure for SRK table, containing its own records */
struct ahab_srk_table
{
    struct ahab_container_srk_table_s table; /* Each table */
    struct ahab_srk_data data;
    struct ahab_srk_record records[MAX_SRK_RECORDS];
    struct ahab_container_signature_s sig;
};

/* Array of table wrappers for all SRK tables */
static struct ahab_srk_table g_srk_tables[CNTN_MAX_NR_SRK_TABLE];

/* Wrapper structure for certificate, containing its own records and data */
struct ahab_certificate
{
    ahab_container_certificate_v1_t v1;
    ahab_container_certificate_v2_t v2;
    struct ahab_srk_record records[CNTN_MAX_NR_SRK_TABLE];
    struct ahab_srk_data data[CNTN_MAX_NR_SRK_TABLE];
    struct ahab_container_signature_s sig[CNTN_MAX_NR_SRK_TABLE];
};

static struct ahab_certificate g_certificate;
/*===========================================================================
                               GLOBAL VARIABLES
=============================================================================*/

/*===========================================================================
                               LOCAL FUNCTIONS
=============================================================================*/

/** Computes the hash of the given data using the specified hash algorithm.
 *
 * @param[in] data Pointer to the data to be hashed.
 * @param[in] data_len Length of the data to be hashed.
 * @param[in] hash_alg The hash algorithm to be used (SRK_SHA256, SRK_SHA384, SRK_SHA512).
 * @param[out] hash_out Pointer to the buffer where the hash will be stored.
 * @param[out] hash_len Pointer to the length of the computed hash.
 *
 * @return 0 on success, -1 on failure.
 */
static int compute_hash(const uint8_t *data, size_t data_len, uint8_t hash_alg,
                        uint8_t **hash_out, size_t *hash_len)
{
    const EVP_MD *md = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    int result = -1;

    /* Check for invalid arguments */
    if (data == NULL || hash_out == NULL || hash_len == NULL)
    {
        fprintf(stderr, "Invalid input argument(s)\n");
        return -1;
    }

    /* Determine the hash algorithm based on the input */
    switch (hash_alg)
    {
        case SRK_SHA256:
            md = EVP_sha256();
            *hash_len = HASH_BYTES_SHA256;
            break;
        case SRK_SHA384:
            md = EVP_sha384();
            *hash_len = HASH_BYTES_SHA384;
            break;
        case SRK_SHA512:
            md = EVP_sha512();
            *hash_len = HASH_BYTES_SHA512;
            break;
        case SRK_SHA3_256:
            md = EVP_sha3_256();
            *hash_len = HASH_BYTES_SHA3_256;
            break;
        case SRK_SHA3_384:
            md = EVP_sha3_384();
            *hash_len = HASH_BYTES_SHA3_384;
            break;
        case SRK_SHA3_512:
            md = EVP_sha3_512();
            *hash_len = HASH_BYTES_SHA3_512;
            break;
        case SRK_SHAKE128_256:
            md = EVP_shake128();
            *hash_len = HASH_BYTES_SHAKE128_256;
            break;
        case SRK_SHAKE256_512:
            md = EVP_shake256();
            *hash_len = HASH_BYTES_SHAKE256_512;
            break;
        default:
            fprintf(stderr, "Unsupported hash algorithm: 0x%X\n", hash_alg);
            return -1;
    }

    /* Allocate memory for the hash output */
    *hash_out = (uint8_t *) malloc(*hash_len);
    if (*hash_out == NULL)
    {
        perror("Failed to allocate memory for hash");
        return -1;
    }

    memset(*hash_out, 0, *hash_len);

    /* Create a message digest context */
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
    {
        fprintf(stderr, "Failed to create EVP_MD_CTX\n");
        free(*hash_out);
        return -1;
    }

    /* Initialize the hashing operation */
    if (EVP_DigestInit_ex(md_ctx, md, NULL) <= 0)
    {
        fprintf(stderr, "EVP_DigestInit_ex failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Update the hash with the data */
    if (EVP_DigestUpdate(md_ctx, data, data_len) <= 0)
    {
        fprintf(stderr, "EVP_DigestUpdate failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Finalize the hashing operation and get the hash */
    if (EVP_DigestFinal_ex(md_ctx, *hash_out, NULL) <= 0)
    {
        fprintf(stderr, "EVP_DigestFinal_ex failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Successful hashing */
    result = 0;

cleanup:
    EVP_MD_CTX_free(md_ctx);
    if (result != 0)
    {
        free(*hash_out);
        *hash_out = NULL;
    }
    return result;
}

/** Validates a container header.
 *
 * @param[in] header Pointer to the container header structure.
 * @param[in] file_size The total size of the file containing the header.
 * @param[out] PARSE_ERROR_OK or an error code
 */
static enum parse_error_e
validate_header(struct ahab_container_header_s *header, long file_size)
{
    if (header == NULL)
    {
        return PARSE_ERROR_NULL;
    }

    /* Check if version is supported */
    if (header->version != CONTAINER_HEADER_VERSION_1 &&
        header->version != CONTAINER_HEADER_VERSION_2)
    {
        return PARSE_ERROR_BAD_HEADER_VERSION;
    }

    /* Check if the tag is valid */
    if (header->tag != CONTAINER_HEADER_TAG &&
        header->tag != SIGNED_MESSAGE_HEADER_TAG &&
        header->tag != V2X_CONTAINER_HEADER_TAG)
    {
        return PARSE_ERROR_INCORRECT_TAG;
    }

    /* Check if the length specified in the header exceeds the file size */
    if (header->length > file_size)
    {
        return PARSE_ERROR_INCORRECT_SIZE;
    }

    /* Check the number of images in the header */
    if (header->nrImages > AHAB_MAX_NR_IMAGES)
    {
        return PARSE_ERROR_TOO_MANY_IMAGES;
    }

    /* Additional check on reserved field mainly to reduce false positives */
    /* when searching containers in continuous mode. */

    if (header->reserved != 0)
    {
        return PARSE_ERROR_BAD_VALUE;
    }

    return PARSE_ERROR_OK;
}

/** Parses and prints container header flags.
 *
 * @param[in] flags The 32-bit flag value from the container header.
 */
static void parse_container_header_flags(uint32_t flags,
                                         uint8_t container_header_version)
{
    uint8_t srk_set = 0;         /* Bits 0-3: SRK Set */
    uint8_t srk_selection = 0;   /* Bits 4-5: SRK Selection */
    uint8_t srk_revoke_mask = 0; /* Bits 8-11: SRK Revoke Mask */
    uint8_t gdet = 0;            /* Bits 20-21: GDET */

    /* Print the flags in hexadecimal */
    print_with_indent("Flags: 0x%X\n", flags);

    /* Increase indentation for further parsing */
    increase_indent();

    /* Parse SRK Set (Bits 0-3) */
    srk_set = flags & 0xF;
    print_with_indent("SRK Set: ");
    switch (srk_set)
    {
        case HEADER_FLAGS_SRK_SET_NONE:
            printf("Container not authenticated\n");
            break;
        case HEADER_FLAGS_SRK_SET_NXP:
            printf("NXP SRK\n");
            break;
        case HEADER_FLAGS_SRK_SET_OEM:
            printf("OEM SRK\n");
            break;
        default:
            printf("Unknown SRK Set value\n");
            break;
    }

    /* Parse SRK Selection (Bits 4-5) */
    srk_selection = (flags >> HEADER_FLAGS_SRK_SHIFT) & 0x3;
    print_with_indent("SRK Selection: ");
    switch (srk_selection)
    {
        case 0x0:
            printf("SRK 0 is used\n");
            break;
        case 0x1:
            printf("SRK 1 is used\n");
            break;
        case 0x2:
            printf("SRK 2 is used\n");
            break;
        case 0x3:
            printf("SRK 3 is used\n");
            break;
        default:
            printf("Unknown SRK Selection value %d\n", srk_selection);
            break;
    }

    /* Store SRK selection globally */
    g_srk_selection = srk_selection;

    /* Parse SRK Revoke Mask (Bits 8-11) */
    srk_revoke_mask = (flags >> HEADER_FLAGS_REVOKING_MASK_SHIFT) & 0xF;
    print_with_indent("SRK Revoke Mask: ");
    if (srk_revoke_mask == 0)
    {
        printf("None");
    }
    else
    {
        if (srk_revoke_mask & 0x1)
            printf("SRK0 ");
        if (srk_revoke_mask & 0x2)
            printf("SRK1 ");
        if (srk_revoke_mask & 0x4)
            printf("SRK2 ");
        if (srk_revoke_mask & 0x8)
            printf("SRK3 ");
        printf("to be revoked\n");
    }
    print_with_indent("\n");

    /* Parse hybrid container flags */
    if (container_header_version == CONTAINER_HEADER_VERSION_2)
    {
        /* Bit 15: Check all signatures */
        print_with_indent("Signature Check Policy: ");
        if (flags & (1 << 15))
            printf("Force verification of all present signatures\n");
        else
            printf("Apply default fuse policy\n");

        /* Bits 16-18: Fast Boot */
        print_with_indent("Fast Boot Configuration:\n");
        increase_indent();
        if (flags & (1 << 16))
            print_with_indent("Hash and Copy: Enabled\n");
        else
            print_with_indent("Hash and Copy: Disabled\n");

        if (flags & (1 << 17))
            print_with_indent("External Accelerator: Enabled\n");
        else
            print_with_indent("External Accelerator: Disabled\n");

        /* Bit 18 is reserved */
        decrease_indent();

        /* Bits 20-21: GDET */
        gdet = (flags >> 20) & 0x3;
        print_with_indent("GDET: 0x%X\n", gdet);
    }

    /* Decrease indentation after parsing is complete */
    decrease_indent();
}

/** Displays the details of a container header.
 *
 * @param[in] header Pointer to the container header structure.
 * @param[out] PARSE_ERROR_OK or an error code
 */
static enum parse_error_e display_header(struct ahab_container_header_s *header)
{
    uint8_t *tag = NULL;

    /* Check for NULL header */
    if (header == NULL)
    {
        return PARSE_ERROR_NULL;
    }

    print_with_indent("Header:\n");

    increase_indent();

    print_with_indent("Version: %d\n", header->version);
    print_with_indent("Length: %d bytes\n", header->length);
    if (header->tag == CONTAINER_HEADER_TAG)
    {
        tag = "Container";
    }
    else if (header->tag == V2X_CONTAINER_HEADER_TAG)
    {
        tag = "V2X Container";
    }
    else if (header->tag == SIGNED_MESSAGE_HEADER_TAG)
    {
        tag = "Signed Message";
    }
    else
    {
        tag = "Unknown or invalid tag";
    }

    print_with_indent("Tag: %s (0x%X)\n", tag, header->tag);
    parse_container_header_flags(header->flags, header->version);
    print_with_indent("SW Version: %d\n", header->sw_version);
    print_with_indent("Fuse Version: %d\n", header->fuse_version);
    print_with_indent("Number of Images: %d\n", header->nrImages);
    print_with_indent("Signature Block Offset: 0x%X\n",
                      header->signature_block_offset);
    print_with_indent("Reserved: 0x%X\n", header->reserved);

    decrease_indent();
    return PARSE_ERROR_OK;
}

/** Parses and displays the image flags.
 *
 * @param[in] flags The 32-bit flag value representing image flags.
 */
static void parse_image_flags(uint32_t flags, uint8_t container_header_version)
{
    uint8_t image_type = 0; /* Type of image: Bits 0-3 */
    uint8_t core_id = 0;    /* Core ID: Bits 4-7  */
    uint8_t hash_type = 0;  /* Hash Type: Bits 8-10 for V1 / Bits 8-11 for V2 */
    uint8_t encrypted = 0;  /* Encrypted: Bit 11 for V1 / Bit 12 for V2 */

    print_with_indent("Image Flags: 0x%X\n", flags);

    increase_indent();

    image_type =
        bf_get_uint8(flags, IMAGE_FLAGS_TYPE_MASK, IMAGE_FLAGS_TYPE_SHIFT);

    print_with_indent("Type of Image: ");
    switch (image_type)
    {
        case IMAGE_FLAGS_TYPE_EXECUTABLE:
            printf("Executable");
            break;
        case IMAGE_FLAGS_TYPE_DATA:
            printf("Data");
            break;
        case IMAGE_FLAGS_TYPE_DCD:
            /*case IMAGE_FLAGS_TYPE_OEI:*/
            printf("DCD/DDR init (SECO devices) or OEI (ELE devices)");
            break;
        case IMAGE_FLAGS_TYPE_SECO:
            printf("SECO FW (SECO devices) or ELE FW (ELE devices)");
            break;
        case IMAGE_FLAGS_TYPE_PROVISIONING:
            printf("Provisioning");
            break;
        case IMAGE_FLAGS_TYPE_DEK:
            printf("DEK");
            break;
        case IMAGE_FLAGS_TYPE_HDMI:
            printf("HDMI FW");
            break;
        case IMAGE_FLAGS_TYPE_DP:
            printf("DisplayPort FW");
            break;
        case IMAGE_FLAGS_TYPE_V2XP:
            printf("V2X 1 FW");
            break;
        case IMAGE_FLAGS_TYPE_V2XS:
            printf("V2X 2 FW");
            break;
        default:
            printf("Reserved or unknown (0x%X)", image_type);
            break;
    }

    print_with_indent("\n");

    core_id = (flags >> IMAGE_FLAGS_CORE_ID_SHIFT) & 0xF;
    print_with_indent("Core ID: ");
    switch (core_id)
    {
        case IMAGE_CORE_ID_SC:
            /*case IMAGE_CORE_ID_RTC:*/
            printf("SC (SECO devices) or Cortex-M33 (ELE devices)");
            break;
        case IMAGE_CORE_ID_CM4_0:
            /*case IMAGE_CORE_ID_APC:*/
            printf("Cortex-M4 0 (SECO devices) or Cortex-A55 (ELE devices)");
            break;
        case IMAGE_CORE_ID_CM4_1:
            printf("Cortex-M4 1");
            break;
        case IMAGE_CORE_ID_CA53:
            printf("Cortex-A35 or Cortex-A35");
            break;
        case IMAGE_CORE_ID_CA72:
            printf("Cortex-A72");
            break;
        case IMAGE_CORE_ID_SECO:
            /*case IMAGE_CORE_ID_ELE:*/
            printf("SECO (SECO devices) or ELE (ELE devices)");
            break;
        case IMAGE_CORE_ID_V2X_1:
            printf("V2X 1");
            break;
        case IMAGE_CORE_ID_V2X_2:
            printf("V2X 2");
            break;
        case IMAGE_CORE_ID_M7_0:
            printf("Cortex-M7 0");
            break;
        case IMAGE_CORE_ID_M7_1:
            printf("Cortex-M7 1");
            break;
        case IMAGE_CORE_ID_M33_SYNC:
            printf("Cortex-M33 Sync");
            break;
        default:
            printf("Reserved or unknown (0x%X)", core_id);
            break;
    }

    print_with_indent("\n");

    if (container_header_version == CONTAINER_HEADER_VERSION_2)
    {
        hash_type = bf_get_uint8(flags, IMAGE_FLAGS_HASH_MASK_2,
                                 IMAGE_FLAGS_HASH_SHIFT);
    }
    else
    {
        hash_type = bf_get_uint8(flags, IMAGE_FLAGS_HASH_MASK_1,
                                 IMAGE_FLAGS_HASH_SHIFT);
    }

    print_with_indent("Hash Type: ");
    switch (hash_type)
    {
        case HASH_SHA256:
            printf("SHA2_256\n");
            break;
        case HASH_SHA384:
            printf("SHA2_384\n");
            break;
        case HASH_SHA512:
            printf("SHA2_512\n");
            break;
        case HASH_SHA3_256:
            printf("SHA3_256\n");
            break;
        case HASH_SHA3_384:
            printf("SHA3_384\n");
            break;
        case HASH_SHA3_512:
            printf("SHA3_512\n");
            break;
        case HASH_SHAKE128_256:
            printf("SHAKE128_256\n");
            break;
        case HASH_SHAKE256_512:
            printf("SHAKE256_512\n");
            break;
        default:
            printf("Reserved or unknown (0x%X)\n", hash_type);
            break;
    }

    if (container_header_version == CONTAINER_HEADER_VERSION_2)
    {
        encrypted = (flags >> IMAGE_FLAGS_ENCRYPTED_SHIFT_2) & 0x1;
    }
    else
    {
        encrypted = (flags >> IMAGE_FLAGS_ENCRYPTED_SHIFT_1) & 0x1;
    }

    print_with_indent("Encrypted: %s\n", encrypted ? "Yes" : "No");

    decrease_indent();
}

/** Verify the integrity of an image.
 *
 * @param[in] file file handle where the image resides.
 * @param[in] file_size size of the file.
 * @param[in] container_offset current container header offset in the file
 * @param[in] image Pointer to the image structure.
 * @param[in] index The index of the image in the container.
 */
static void verify_image(FILE *file, long file_size, long container_offset,
                         struct ahab_container_image_s *image, int index,
                         struct ahab_container_header_s *container_header)
{
    uint8_t *data = NULL;
    uint8_t *hash = NULL;
    size_t hash_len = 0;
    uint8_t hash_alg = 0;
    int ret = -1;

    /* Check for invalid arguments */
    if (file == NULL || image == NULL)
    {
        fprintf(stderr, "Invalid input argument(s)\n");
        return;
    }

    if (image->image_size > file_size)
    {
        fprintf(stderr,
                "Error: Invalid image size (image_size: %u, file_size: %zu).\n",
                image->image_size, file_size);
        return;
    }

    /* Allocate memory for the data to be verified */
    data = malloc(image->image_size);
    if (!data)
    {
        perror("Failed to allocate memory for image data");
        exit(EXIT_FAILURE);
    }

    memset(data, 0, image->image_size);

    /* Read the data to be verified */
    if (image->image_size)
    {
        /* We may have empty images such as DCD/DDR init images */
        read_data(file, data, image->image_size,
                  container_offset + image->image_offset);
    }

    if (container_header->version == CONTAINER_HEADER_VERSION_2)
    {
        hash_alg = bf_get_uint8(image->flags, IMAGE_FLAGS_HASH_MASK_2,
                                IMAGE_FLAGS_HASH_SHIFT);
    }
    else
    {
        hash_alg = bf_get_uint8(image->flags, IMAGE_FLAGS_HASH_MASK_1,
                                IMAGE_FLAGS_HASH_SHIFT);
    }

    ret = compute_hash(data, image->image_size, hash_alg, &hash, &hash_len);

    if (ret)
    {
        free(data);
        fprintf(stderr, "Error calculating image hash\n");
        return;
    }

    ret = memcmp(hash, image->hash, hash_len);

    increase_indent();
    print_with_indent("Image verification: %s\n",
                      (ret == 0) ? "successful" : "failed");
    decrease_indent();

    free(hash);
    free(data);
}

/** Displays the details of an image.
 *
 * @param[in] image Pointer to the image structure.
 * @param[in] index The index of the image in the container.
 */
static void display_image(struct ahab_container_image_s *image, int index,
                          struct ahab_container_header_s *container_header)
{
    int i = 0;

    /* Check for invalid arguments */
    if (image == NULL)
    {
        fprintf(stderr, "Invalid input argument\n");
        return;
    }

    print_with_indent("Image %d:\n", index);

    increase_indent();

    print_with_indent("Offset: 0x%X\n", image->image_offset);
    print_with_indent("Size: %u bytes\n", image->image_size);
    print_with_indent("Load Address: 0x%lX\n", image->load_address);
    print_with_indent("Entry Point: 0x%lX\n", image->entry_point);
    parse_image_flags(image->flags, container_header->version);
    print_with_indent("Reserved: 0x%X\n", image->reserved);
    dump_buffer_with_label("Hash: ", image->hash, sizeof(image->hash));
    print_with_indent("IV: ");
    for (i = 0; i < sizeof(image->iv); i++)
    {
        printf("%02X", image->iv[i]);
    }
    printf("\n");

    decrease_indent();
}

/** Parses and fills the SRK record data from the given file.
 *
 * @param[in] file Pointer to the file from which the key data will be read.
 * @param[in] key_data_offset Offset in the file where the key data starts.
 * @param[in] srk_table_version Version of the SRK table.
 * @param[out] srk_record Pointer to the SRK record structure to be filled.
 *
 * @return 0 on success, -1 on failure.
 */
static int parse_key_data(FILE *file, long key_data_offset,
                          uint8_t srk_table_version,
                          struct ahab_srk_record *srk_record)
{
    int i = 0;

    /* Check for invalid arguments */
    if ((file == NULL) || (srk_record == NULL))
    {
        fprintf(stderr, "Invalid input argument(s)\n");
        return -1;
    }

    /* Validate length */
    if (srk_record->record.modulus_or_x_or_pk_length > MAX_MODULUS_X_PK_LENGTH)
    {
        fprintf(stderr, "Error: Invalid modulus_or_x_or_pk length: %u\n",
                srk_record->record.modulus_or_x_or_pk_length);
        return -1;
    }

    if (srk_record->record.exponent_or_y_length > MAX_EXPONENT_Y_LENGTH)
    {
        fprintf(stderr, "Error: Invalid exponent_or_y length: %u\n",
                srk_record->record.exponent_or_y_length);
        return -1;
    }

    /* Seek to the specified offset in the file */
    if (fseek(file, key_data_offset, SEEK_SET) != 0)
    {
        perror("Error seeking to the key data");
        return -1;
    }

    if (srk_table_version == SRK_TABLE_VERSION_1)
    {
        /* Allocate memory for the modulus/x and exponent/y */
        srk_record->modulus_or_x =
            malloc(srk_record->record.modulus_or_x_or_pk_length);
        srk_record->exponent_or_y =
            malloc(srk_record->record.exponent_or_y_length);

        if (!srk_record->modulus_or_x || !srk_record->exponent_or_y)
        {
            perror("Failed to allocate memory for SRK key components");
            free(srk_record->modulus_or_x);
            free(srk_record->exponent_or_y);
            return -1;
        }

        memset(srk_record->modulus_or_x, 0,
               srk_record->record.modulus_or_x_or_pk_length);
        memset(srk_record->exponent_or_y, 0,
               srk_record->record.exponent_or_y_length);

        /* Read the modulus/x and exponent/y from the file */
        if (fread(srk_record->modulus_or_x,
                  srk_record->record.modulus_or_x_or_pk_length, 1, file) != 1)
        {
            perror("Failed to read SRK modulus/x");
            free(srk_record->modulus_or_x);
            free(srk_record->exponent_or_y);
            return -1;
        }

        if (srk_record->record.exponent_or_y_length > 0)
        {
            if (fread(srk_record->exponent_or_y,
                      srk_record->record.exponent_or_y_length, 1, file) != 1)
            {
                perror("Failed to read SRK exponent/y");
                free(srk_record->modulus_or_x);
                free(srk_record->exponent_or_y);
                return -1;
            }
        }

        /* Handle RSA or ECDSA specific parsing and printing */
        if (srk_record->record.sign_alg == SRK_RSA ||
            srk_record->record.sign_alg == SRK_RSA_PSS)
        {
            dump_buffer_with_label(
                "Modulus (N):\n", srk_record->modulus_or_x,
                srk_record->record.modulus_or_x_or_pk_length);
            dump_buffer_with_label("Exponent (E):\n", srk_record->exponent_or_y,
                                   srk_record->record.exponent_or_y_length);

            /* Swap bytes for later use */
            swap_bytes(srk_record->modulus_or_x,
                       srk_record->record.modulus_or_x_or_pk_length);
            swap_bytes(srk_record->exponent_or_y,
                       srk_record->record.exponent_or_y_length);
        }
        else if (srk_record->record.sign_alg == SRK_ECDSA)
        {
            print_with_indent("X Coordinate: ");
            for (i = 0; i < srk_record->record.modulus_or_x_or_pk_length; i++)
            {
                printf("%02X", srk_record->modulus_or_x[i]);
            }
            printf("\n");

            print_with_indent("Y Coordinate: ");
            for (i = 0; i < srk_record->record.exponent_or_y_length; i++)
            {
                printf("%02X", srk_record->exponent_or_y[i]);
            }
            printf("\n");
        }
    }
    else if (srk_table_version == SRK_TABLE_VERSION_2)
    {
        srk_record->srk_data_hash = malloc(SRK_DATA_HASH_SIZE);

        if (!srk_record->srk_data_hash)
        {
            perror("Failed to allocate memory for SRK data hash");
            return -1;
        }

        memset(srk_record->srk_data_hash, 0, SRK_DATA_HASH_SIZE);

        /* Read the srk data hash from the file */
        if (fread(srk_record->srk_data_hash, SRK_DATA_HASH_SIZE, 1, file) != 1)
        {
            perror("Failed to read SRK data hash/x");
            free(srk_record->srk_data_hash);
            return -1;
        }

        dump_buffer_with_label("Hash of SRK Data:\n", srk_record->srk_data_hash,
                               SRK_DATA_HASH_SIZE);
    }

    return 0;
}

/** Parses and prints the SRK record from the given container file.
 *
 * @param[in] file Pointer to the file containing the SRK record.
 * @param[in] srk_table_version Version of the SRK table.
 * @param[in] record_offset Offset in the file where the SRK record starts.
 * @param[out] srk_record Pointer to the SRK record structure to be filled.
 *
 * @return 0 on success, -1 on failure.
 */
static int parse_record(FILE *file, uint8_t srk_table_version,
                        long record_offset, struct ahab_srk_record *srk_record)
{
    /* Check for invalid arguments */
    if (file == NULL || srk_record == NULL)
    {
        fprintf(stderr, "Invalid input argument(s)\n");
        return -1;
    }

    /* Seek to the SRK record offset */
    if (fseek(file, record_offset, SEEK_SET) != 0)
    {
        perror("Failed to seek to the SRK record");
        return -1;
    }

    /* Read the fields from the file into srk_record */
    if (fread(&srk_record->record, sizeof(struct ahab_container_srk_s), 1,
              file) != 1)
    {
        perror("Failed to read SRK record fixed fields");
        return -1;
    }

    /* Validate tag and length */
    if (srk_record->record.tag != SRK_TAG)
    {
        fprintf(stderr, "Error: Invalid SRK record tag: 0x%X\n",
                srk_record->record.tag);
        exit(EXIT_FAILURE);
    }

    /* Print the fields */
    print_with_indent("SRK Record:\n");

    increase_indent();

    print_with_indent("Tag: 0x%X\n", srk_record->record.tag);
    print_with_indent("Length: %d bytes\n", srk_record->record.length);

    /* Sign Algorithm */
    print_with_indent("Sign Algorithm: ");
    switch (srk_record->record.sign_alg)
    {
        case SRK_RSA:
            printf("RSA");
            break;
        case SRK_RSA_PSS:
            printf("RSA-PSS");
            break;
        case SRK_ECDSA:
            printf("ECDSA");
            break;
        case SRK_DILITHIUM:
            printf("Dilithium");
            break;
        case SRK_MLDSA:
            printf("ML-DSA");
            break;
        default:
            printf("Unknown");
            break;
    }

    print_with_indent("\n");
    /* Hash Algorithm */
    print_with_indent("Hash Algorithm: ");
    switch (srk_record->record.hash_alg)
    {
        case SRK_SHA256:
            printf("SHA2_256");
            break;
        case SRK_SHA384:
            printf("SHA2_384");
            break;
        case SRK_SHA512:
            printf("SHA2_512");
            break;
        case SRK_SHA3_256:
            printf("SHA3_256");
            break;
        case SRK_SHA3_384:
            printf("SHA3_384");
            break;
        case SRK_SHA3_512:
            printf("SHA3_512");
            break;
        case SRK_SHAKE128_256:
            printf("SHAKE128_256");
            break;
        case SRK_SHAKE256_512:
            printf("SHAKE256_512");
            break;
        default:
            printf("Unknown");
            break;
    }
    print_with_indent("\n");

    /* Key Size or Curve */
    print_with_indent("Key Size/Curve: ");
    switch (srk_record->record.key_size_or_curve)
    {
        case SRK_PRIME256V1:
            printf("PRIME256V1");
            break;
        case SRK_SEC384R1:
            printf("SEC384R1");
            break;
        case SRK_SEC521R1:
            printf("SEC521R1");
            break;
        case SRK_RSA2048:
            printf("RSA2048");
            break;
        case SRK_RSA3072:
            printf("RSA3072");
            break;
        case SRK_RSA4096:
            printf("RSA4096");
            break;
        case SRK_DILITHIUM3:
            printf("%s", srk_record->record.sign_alg == SRK_DILITHIUM
                             ? "Dilithium3"
                             : "ML-DSA65\n");
            break;
        case SRK_DILITHIUM5:
            printf("%s", srk_record->record.sign_alg == SRK_DILITHIUM
                             ? "Dilithium5"
                             : "ML-DSA87\n");
            break;
        default:
            printf("Unknown");
            break;
    }

    print_with_indent("\n");

    /* SRK Flags */
    print_with_indent("SRK Flags: ");
    switch (srk_record->record.flags)
    {
        case 0x0:
            printf("None");
            break;
        case SRK_FLAGS_CA:
            printf("CA Flags");
            break;
        default:
            printf("Unknown");
            break;
    }

    print_with_indent("\n");

    /* Public Key Information */
    if (parse_key_data(file,
                       record_offset + sizeof(struct ahab_container_srk_s),
                       srk_table_version, srk_record) != 0)
    {
        return -1;
    }

    decrease_indent();

    return 0;
}

/** Parses the SRK table from the given container file.
 *
 * @param[in] file Pointer to the file containing the SRK table.
 * @param[in] srk_table_offset Offset in the file where the SRK table starts.
 * @param[out] srk_table Pointer to the SRK table structure to be filled.
 */
static void parse_srk_table(FILE *file, long srk_table_offset,
                            struct ahab_srk_table *srk_table)
{
    int i = 0;
    int j = 0;
    long record_offset = 0; /* Offset for SRK records */

    /* Check for invalid arguments */
    if (file == NULL || srk_table == NULL)
    {
        fprintf(stderr, "Invalid input argument(s)\n");
        return;
    }

    /* Seek to the SRK table offset */
    if (fseek(file, srk_table_offset, SEEK_SET) != 0)
    {
        perror("Failed to seek to the SRK table");
        exit(EXIT_FAILURE);
    }

    /* Read the SRK table header */
    if (fread(&srk_table->table, sizeof(srk_table->table), 1, file) != 1)
    {
        perror("Failed to read the SRK table header");
        exit(EXIT_FAILURE);
    }

    /* Validate version and tag */
    if (srk_table->table.tag != SRK_TABLE_TAG)
    {
        fprintf(stderr, "Error: Invalid SRK table tag: 0x%X\n",
                srk_table->table.tag);
        exit(EXIT_FAILURE);
    }

    if (srk_table->table.version != SRK_TABLE_VERSION_1 &&
        srk_table->table.version != SRK_TABLE_VERSION_2)
    {
        fprintf(stderr, "Error: Unsupported SRK table version: %d\n",
                srk_table->table.version);
        exit(EXIT_FAILURE);
    }

    /* Display SRK table header */
    print_with_indent("SRK Table:\n");
    increase_indent();
    print_with_indent("Tag: 0x%X\n", srk_table->table.tag);
    print_with_indent("Length: %d bytes\n", srk_table->table.length);
    print_with_indent("Version: %d\n", srk_table->table.version);
    decrease_indent();

    /* Parse each SRK record */
    record_offset = srk_table_offset + sizeof(srk_table->table);
    increase_indent();
    for (i = 0; i < MAX_SRK_RECORDS; i++)
    {
        if (parse_record(file, srk_table->table.version, record_offset,
                         &srk_table->records[i]) != 0)
        {
            fprintf(stderr, "Failed to parse SRK record %d\n", i);

            /* Free previously allocated memory for parsed records */
            for (j = 0; j < i; j++)
            {
                free(srk_table->records[j].modulus_or_x);
                free(srk_table->records[j].exponent_or_y);
            }
            return;
        }

        /* Move to the next record based on the length of the current record */
        record_offset += srk_table->records[i].record.length;
    }
    decrease_indent();
}

/** Parses the SRK data from the given container file.
 *
 * @param[in] file Pointer to the file containing the SRK data.
 * @param[in] srk_data_offset Offset in the file where the SRK data starts.
 * @param[out] srk_data Pointer to the SRK data structure to be filled.
 */
static void parse_srk_data(FILE *file, long srk_data_offset,
                           struct ahab_srk_data *srk_data)
{
    size_t key_size = 0;

    /* Check for invalid arguments */
    if (file == NULL || srk_data == NULL)
    {
        fprintf(stderr, "Invalid input argument(s)\n");
        return;
    }

    /* Seek to the SRK data offset */
    if (fseek(file, srk_data_offset, SEEK_SET) != 0)
    {
        perror("Failed to seek to the SRK data");
        exit(EXIT_FAILURE);
    }

    /* Read the SRK data header */
    if (fread(&srk_data->data, sizeof(srk_data->data), 1, file) != 1)
    {
        perror("Failed to read the SRK data header");
        exit(EXIT_FAILURE);
    }

    /* Validate version and tag */
    if (srk_data->data.tag != SRK_DATA_TAG)
    {
        fprintf(stderr, "Error: Invalid SRK data tag: 0x%X\n",
                srk_data->data.tag);
        exit(EXIT_FAILURE);
    }

    if (srk_data->data.version != SRK_DATA_VERSION)
    {
        fprintf(stderr, "Error: Unsupported SRK data version: %d\n",
                srk_data->data.version);
        exit(EXIT_FAILURE);
    }

    /* Display SRK data header */
    print_with_indent("SRK Data:\n");
    increase_indent();
    print_with_indent("Tag: 0x%X\n", srk_data->data.tag);
    print_with_indent("Length: %d bytes\n", srk_data->data.length);
    print_with_indent("Version: %d\n", srk_data->data.version);
    print_with_indent("SRK record number: %d\n",
                      srk_data->data.srk_record_number);

    if (srk_data->data.length < sizeof(srk_data->data))
    {
        fprintf(stderr,
                "Error: Invalid data length in srk_data (length: %lu, expected "
                "at least: %lu).\n",
                (unsigned long) srk_data->data.length,
                (unsigned long) sizeof(srk_data->data));
        return;
    }

    /* Calculate the key size */
    key_size = srk_data->data.length - sizeof(srk_data->data);
    if (key_size == 0 || key_size > MAX_KEY_SIZE)
    {
        fprintf(stderr,
                "Error: Invalid clear size for memset (key_size: %lu).\n",
                (unsigned long) key_size);
        return;
    }

    /* Allocate memory for the SRK data key */
    srk_data->key = malloc(key_size);
    if (!srk_data->key)
    {
        perror("Failed to allocate memory for SRK data key");
        return;
    }

    memset(srk_data->key, 0, key_size);

    /* Validate the length of SRK data */
    if (srk_data->data.length <= sizeof(srk_data->data) ||
        srk_data->data.length > MAX_SRK_DATA_LENGTH)
    {
        fprintf(stderr, "ERROR: Invalid SRK data length: %u\n",
                srk_data->data.length);
        free(srk_data->key);
        return;
    }

    /* Read the key data from the file */
    if (fread(srk_data->key, key_size, 1, file) != 1)
    {
        perror("Failed to read SRK data key");
        free(srk_data->key);
        return;
    }

    /* Display the key data */
    dump_buffer_with_label("Key data:\n", srk_data->key, key_size);

    decrease_indent();
}

/** Parses the SRK table array from the given container file.
 *
 * @param[in] file Pointer to the file containing the SRK table array.
 * @param[in] srk_table_array_offset Offset in the file where the SRK table array starts.
 * @param[out] nb_srk_table Number of SRK tables.
 */
static void parse_srk_table_array(FILE *file, long srk_table_array_offset,
                                  uint32_t *nb_srk_table)
{
    int i = 0;
    long offset = 0;
    struct ahab_container_srk_table_array_s srk_table_array = {0};
    uint8_t srk_record_number = 0;

    /* Check for invalid arguments */
    if (file == NULL)
    {
        fprintf(stderr, "Invalid input argument(s)\n");
        return;
    }

    /* Seek to the SRK table array offset */
    if (fseek(file, srk_table_array_offset, SEEK_SET) != 0)
    {
        perror("Failed to seek to the SRK table");
        exit(EXIT_FAILURE);
    }

    /* Read the SRK table array header */
    if (fread(&srk_table_array, sizeof(srk_table_array), 1, file) != 1)
    {
        perror("Failed to read the SRK table array header");
        exit(EXIT_FAILURE);
    }

    /* Validate version and tag */
    if (srk_table_array.tag != SRK_TABLE_ARRAY_TAG)
    {
        fprintf(stderr, "Error: Invalid SRK table array tag: 0x%X\n",
                srk_table_array.tag);
        exit(EXIT_FAILURE);
    }

    if (srk_table_array.version != SRK_TABLE_ARRAY_VERSION)
    {
        fprintf(stderr, "Error: Unsupported SRK table array version: %d\n",
                srk_table_array.version);
        exit(EXIT_FAILURE);
    }

    /* Display SRK table array header */
    print_with_indent("SRK Table Array:\n");
    increase_indent();
    print_with_indent("Tag: 0x%X\n", srk_table_array.tag);
    print_with_indent("Length: %d bytes\n", srk_table_array.length);
    print_with_indent("Version: %d\n", srk_table_array.version);
    print_with_indent("Number SRK tables: %d\n",
                      srk_table_array.number_srk_table);

    if (srk_table_array.number_srk_table == 0 ||
        srk_table_array.number_srk_table > CNTN_MAX_NR_SRK_TABLE)
    {
        fprintf(stderr, "Error: Invalid number of SRK tables: %d\n",
                srk_table_array.number_srk_table);
        exit(EXIT_FAILURE);
    }

    *nb_srk_table = srk_table_array.number_srk_table;

    increase_indent();

    /* Parse each SRK table */
    offset = srk_table_array_offset + sizeof(srk_table_array);
    for (i = 0; i < srk_table_array.number_srk_table; i++)
    {
        /* Parse SRK table */
        parse_srk_table(file, offset, &g_srk_tables[i]);
        offset += g_srk_tables[i].table.length;

        /* Parse SRK data */
        parse_srk_data(file, offset, &g_srk_tables[i].data);
        increase_indent();
        srk_record_number = g_srk_tables[i].data.data.srk_record_number;

        if (srk_record_number > CNTN_MAX_SRK_TABLE_RECORDS)
        {
            fprintf(stderr, "Error: Invalid number of SRK records: %d\n",
                    srk_record_number);
            exit(EXIT_FAILURE);
        }

        /* Parse SRK key data */
        parse_key_data(file, offset + sizeof(g_srk_tables[i].data.data),
                       SRK_TABLE_VERSION_1,
                       &g_srk_tables[i].records[srk_record_number]);

        decrease_indent();

        /* Move to the next table based on the length of the current table */
        offset += g_srk_tables[i].data.data.length;
    }

    decrease_indent();
    decrease_indent();
}

/** Converts ECDSA r and s values to DER format.
 *
 * @param[in] r Pointer to the r value.
 * @param[in] s Pointer to the s value.
 * @param[in] len Length of the r and s values.
 * @param[out] der Pointer to the DER-encoded signature.
 * @param[out] der_len Pointer to the length of the DER-encoded signature.
 *
 * @return 0 on success, -1 on failure.
 */
static int convert_rs_to_der(const uint8_t *r, const uint8_t *s, size_t len,
                             uint8_t **der, size_t *der_len)
{
    ECDSA_SIG *sig = NULL;
    BIGNUM *bn_r = NULL;
    BIGNUM *bn_s = NULL;
    int ret = -1;

    /* Check for invalid arguments */
    if (r == NULL || s == NULL || der == NULL || der_len == NULL)
    {
        fprintf(stderr, "Invalid input argument(s)\n");
        return -1;
    }

    sig = ECDSA_SIG_new();
    if (!sig)
    {
        fprintf(stderr, "Failed to create ECDSA_SIG object\n");
        return ret;
    }

    /* Set r and s into the ECDSA_SIG structure */
    bn_r = BN_bin2bn(r, len, NULL);
    bn_s = BN_bin2bn(s, len, NULL);
    if (!bn_r || !bn_s || !ECDSA_SIG_set0(sig, bn_r, bn_s))
    {
        fprintf(stderr, "Failed to set r and s in ECDSA_SIG\n");
        ECDSA_SIG_free(sig);
        return ret;
    }

    /* Convert the ECDSA_SIG to DER format */
    *der_len = i2d_ECDSA_SIG(sig, der);
    if (*der_len <= 0)
    {
        fprintf(stderr, "Failed to convert ECDSA_SIG to DER\n");
        ret = -1;
    }
    else
    {
        ret = 0; /* Success */
    }

    ECDSA_SIG_free(sig);
    return ret;
}

/** Verifies the signature using the given hash and signature algorithms.
 *
 * @param[in] hash_alg The hash algorithm used (SRK_SHA256, SRK_SHA384, SRK_SHA512).
 * @param[in] sign_alg The signature algorithm used (SRK_RSA, SRK_ECDSA, SRK_DILITHIUM, etc.).
 * @param[in] key_size_or_curve Key size or curve used for ECDSA or other elliptic curve algorithms.
 * @param[in] data The data to be verified.
 * @param[in] data_length Length of the data to be verified.
 * @param[in] signature_data The signature data.
 * @param[in] signature_length Length of the signature data.
 * @param[in] modulus_or_x Modulus or x-coordinate of the public key.
 * @param[in] modulus_or_x_len Length of the modulus or x-coordinate.
 * @param[in] exponent_or_y Exponent or y-coordinate of the public key.
 * @param[in] exponent_or_y_len Length of the exponent or y-coordinate.
 */
static void verify_signature(uint8_t hash_alg, uint8_t sign_alg,
                             uint8_t key_size_or_curve, uint8_t *data,
                             uint16_t data_length, uint8_t *signature_data,
                             uint16_t signature_length, uint8_t *modulus_or_x,
                             uint16_t modulus_or_x_len, uint8_t *exponent_or_y,
                             uint16_t exponent_or_y_len)
{
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    const EVP_MD *md = NULL;
    int verify_result = -1;
    EVP_PKEY_CTX *verify_pctx = NULL;
    uint8_t *sig = NULL;
    size_t sig_len = 0;
    uint8_t *pubkey = NULL;
    size_t pubkey_len = 0;
    char *alg_name = NULL;

    /* Check for invalid arguments */
    if (data == NULL || signature_data == NULL || modulus_or_x == NULL ||
        exponent_or_y == NULL)
    {
        fprintf(stderr, "Invalid input argument(s)\n");
        return;
    }

    /* Choose the hash algorithm based on SRK */
    switch (hash_alg)
    {
        case SRK_SHA256:
            md = EVP_sha256();
            break;
        case SRK_SHA384:
            md = EVP_sha384();
            break;
        case SRK_SHA512:
            md = EVP_sha512();
            break;
        case SRK_SHA3_256:
            md = EVP_sha3_256();
            break;
        case SRK_SHA3_384:
            md = EVP_sha3_384();
            break;
        case SRK_SHA3_512:
            md = EVP_sha3_512();
            break;
        case SRK_SHAKE128_256:
            md = EVP_shake128();
            break;
        case SRK_SHAKE256_512:
            md = EVP_shake256();
            break;
        default:
            fprintf(stderr, "Unsupported hash algorithm: 0x%X\n", hash_alg);
            return;
    }

    /* Choose the signature algorithm */
    switch (sign_alg)
    {
        case SRK_ECDSA:
            if (key_size_or_curve == SRK_PRIME256V1)
            {
                alg_name = "p256";
            }
            else if (key_size_or_curve == SRK_SEC384R1)
            {
                alg_name = "p384";
            }
            else if (key_size_or_curve == SRK_SEC521R1)
            {
                alg_name = "p521";
            }
            else
            {
                fprintf(stderr, "Unsupported EC curve\n");
                return;
            }

            if (convert_rs_to_der(signature_data,
                                  signature_data + (signature_length / 2),
                                  signature_length / 2, &sig, &sig_len) != 0)
            {
                fprintf(stderr, "Failed to convert r and s to DER format\n");
                return;
            }

            pubkey_len = modulus_or_x_len + exponent_or_y_len + 1;
            pubkey = (uint8_t *) malloc(pubkey_len);
            if (pubkey == NULL)
            {
                fprintf(stderr, "Error allocating memory for public key\n");
                return;
            }

            memset(pubkey, 0, pubkey_len);
            memcpy(pubkey, "\x04", 1);
            memcpy(pubkey + 1, modulus_or_x, modulus_or_x_len);
            memcpy(pubkey + 1 + modulus_or_x_len, exponent_or_y,
                   exponent_or_y_len);

            break;
        case SRK_RSA:
        case SRK_RSA_PSS:
            alg_name = "rsa";
            pubkey_len = modulus_or_x_len + exponent_or_y_len;
            pubkey = (uint8_t *) malloc(pubkey_len);
            if (pubkey == NULL)
            {
                fprintf(stderr, "Error allocating memory for public key\n");
                return;
            }
            memset(pubkey, 0, pubkey_len);
            memcpy(pubkey, modulus_or_x, modulus_or_x_len);
            memcpy(pubkey + modulus_or_x_len, exponent_or_y, exponent_or_y_len);

            sig = signature_data;
            sig_len = signature_length;

            break;
        case SRK_DILITHIUM:
            if (key_size_or_curve == SRK_DILITHIUM3)
            {
                alg_name = "dilithium3";
            }
            else if (key_size_or_curve == SRK_DILITHIUM5)
            {
                alg_name = "dilithium5";
            }
            else
            {
                fprintf(stderr, "Unsupported dilithium parameters set\n");
                return;
            }

            pubkey_len = modulus_or_x_len;
            pubkey = (uint8_t *) malloc(pubkey_len);
            if (pubkey == NULL)
            {
                fprintf(stderr, "Error allocating memory for public key\n");
                return;
            }
            memset(pubkey, 0, pubkey_len);
            memcpy(pubkey, modulus_or_x, modulus_or_x_len);

            sig = signature_data;
            sig_len = signature_length;
            break;
        case SRK_MLDSA:
            if (key_size_or_curve == SRK_MLDSA65)
            {
                alg_name = "mldsa65";
            }
            else if (key_size_or_curve == SRK_MLDSA87)
            {
                alg_name = "mldsa87";
            }
            else
            {
                fprintf(stderr, "Unsupported ML-DSA parameters set\n");
                return;
            }

            pubkey_len = modulus_or_x_len;
            pubkey = (uint8_t *) malloc(pubkey_len);
            if (pubkey == NULL)
            {
                fprintf(stderr, "Error allocating memory for public key\n");
                return;
            }
            memset(pubkey, 0, pubkey_len);
            memcpy(pubkey, modulus_or_x, modulus_or_x_len);

            sig = signature_data;
            sig_len = signature_length;

            break;
        default:
            fprintf(stderr, "Unknown signature algorithm: 0x%X\n", sign_alg);
            return;
    }

    pkey = create_evp_key_from_bytes(get_libctx(), pubkey, pubkey_len, NULL, 0,
                                     alg_name);
    if (!pkey)
    {
        fprintf(stderr, "Failed to create EVP_PKEY\n");
        free(pubkey);
        return;
    }

    /* Create a message digest context */
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
    {
        fprintf(stderr, "Failed to create EVP_MD_CTX\n");
        free(pubkey);
        EVP_PKEY_free(pkey);
        return;
    }

    /* Initialize the verification context */
    if (EVP_DigestVerifyInit(md_ctx, &verify_pctx, md, NULL, pkey) <= 0)
    {
        fprintf(stderr, "EVP_DigestVerifyInit failed\n");
        free(pubkey);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return;
    }

    /* Set the padding mode based on sign_alg */
    if (sign_alg == SRK_RSA || sign_alg == SRK_RSA_PSS)
    {
        if (EVP_PKEY_CTX_set_rsa_padding(verify_pctx,
                                         (sign_alg == SRK_RSA)
                                             ? RSA_PKCS1_PADDING
                                             : RSA_PKCS1_PSS_PADDING) <= 0)
        {
            fprintf(stderr, "Failed to set RSA PKCS1.5 padding\n");
            free(pubkey);
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(pkey);
            return;
        }
    }

    /* Perform the verification */
    verify_result = EVP_DigestVerify(md_ctx, sig, sig_len, data, data_length);

    /* Check the result */
    if (verify_result == 1)
    {
        printf("Signature verification successful\n");
    }
    else if (verify_result == 0)
    {
        printf("Signature verification failed\n");
    }
    else
    {
        fprintf(stderr, "Error during signature verification\n");
        ERR_print_errors_fp(stderr);
    }

    /* Clean up */
    free(pubkey);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
}

/** Parses and verifies the signature from the given container file.
 *
 * @param[in] file Pointer to the file containing the signature.
 * @param[in] file_size Size of the file.
 * @param[in] container_offset Container header offset in the file.
 * @param[in] signature_offset Offset in the file where the signature starts.
 * @param[in] data_offset Offset in the file where the data to be verified starts.
 * @param[in] data_length Length of the data to be verified.
 * @param[in] srk_table SRK table identifier.
 * @param[out] sig Pointer to the signature structure to be filled.
 * @param[in] srk_record Pointer to the SRK record structure used for verification.
 */
static void parse_signature(FILE *file, long file_size, long container_offset,
                            long signature_offset, long data_offset,
                            size_t data_length, uint8_t srk_table,
                            struct ahab_container_signature_s *sig,
                            struct ahab_srk_record *srk_record)
{
    uint8_t *modulus_or_x = NULL;
    uint16_t modulus_or_x_len = 0;
    uint8_t *exponent_or_y = NULL;
    uint16_t exponent_or_y_len = 0;
    uint8_t *signature_data = NULL;
    uint8_t *data = NULL;
    size_t signature_length = 0;
    uint8_t sign_alg = 0;
    uint8_t hash_alg = 0;
    uint8_t key_size_or_curve = 0;

    /* Check for invalid arguments */
    if (file == NULL || sig == NULL || srk_record == NULL)
    {
        fprintf(stderr, "Invalid input argument(s)\n");
        return;
    }

    if (signature_offset < 0 || data_offset < 0)
    {
        fprintf(stderr,
                "Error: Negative offset provided (signature_offset: %ld, "
                "data_offset: %ld).\n",
                signature_offset, data_offset);
        return;
    }

    if ((size_t) signature_offset > file_size ||
        (size_t) data_offset > file_size)
    {
        fprintf(stderr,
                "Error: Offset exceeds file size (file_size: %zu, "
                "signature_offset: %ld, data_offset: %ld).\n",
                file_size, signature_offset, data_offset);
        return;
    }

    if (data_length == 0 || data_length > file_size)
    {
        fprintf(
            stderr,
            "Error: Invalid data length (data_length: %zu, file_size: %zu).\n",
            data_length, file_size);
        return;
    }

    if ((size_t) data_offset + data_length > file_size)
    {
        fprintf(stderr,
                "Error: Data range exceeds file bounds (data_offset: %ld, "
                "data_length: %zu, file_size: %zu).\n",
                data_offset, data_length, file_size);
        return;
    }

    /* Validate signature offset against container_offset */
    if ((size_t) signature_offset < container_offset ||
        (size_t) signature_offset >= file_size)
    {
        fprintf(
            stderr,
            "Error: Signature offset is outside valid range (container_offset: "
            "%zu, file_size: %zu, signature_offset: %ld).\n",
            container_offset, file_size, signature_offset);
        return;
    }

    /* Seek to the signature offset */
    if (fseek(file, signature_offset, SEEK_SET) != 0)
    {
        perror("Failed to seek to the signature");
        exit(EXIT_FAILURE);
    }

    /* Read the signature header */
    if (fread(sig, sizeof(*sig), 1, file) != 1)
    {
        perror("Failed to read the signature header");
        exit(EXIT_FAILURE);
    }

    /* Validate version and tag */
    if (sig->version != 0)
    {
        fprintf(stderr, "Error: Unsupported signature version: %d\n",
                sig->version);
        exit(EXIT_FAILURE);
    }

    if (sig->tag != SIGNATURE_TAG)
    {
        fprintf(stderr, "Error: Invalid signature tag: 0x%X\n", sig->tag);
        exit(EXIT_FAILURE);
    }

    /* Allocate memory for the raw signature data */
    signature_length = sig->length - sizeof(*sig);

    if (signature_length > MAX_SIGNATURE_LENGTH)
    {
        fprintf(stderr, "Error: Invalid signature length: %ld\n",
                signature_length);
        exit(EXIT_FAILURE);
    }

    signature_data = malloc(signature_length);
    if (!signature_data)
    {
        perror("Failed to allocate memory for signature data");
        exit(EXIT_FAILURE);
    }
    memset(signature_data, 0, signature_length);

    /* Read the raw signature data */
    read_data(file, signature_data, signature_length,
              signature_offset + sizeof(*sig));

    dump_buffer_with_label("Signature Data:\n", signature_data,
                           signature_length);

    /* Allocate memory for the data to be verified */
    data = malloc(data_length);
    if (!data)
    {
        free(signature_data);
        perror("Failed to allocate memory for data");
        exit(EXIT_FAILURE);
    }

    memset(data, 0, data_length);

    /* Read the data to be verified */
    read_data(file, data, data_length, data_offset);

    /* Retrieve SRK record information */
    modulus_or_x = srk_record->modulus_or_x;
    modulus_or_x_len = srk_record->record.modulus_or_x_or_pk_length;

    exponent_or_y = srk_record->exponent_or_y;
    exponent_or_y_len = srk_record->record.exponent_or_y_length;

    sign_alg = srk_record->record.sign_alg;
    hash_alg = srk_record->record.hash_alg;
    key_size_or_curve = srk_record->record.key_size_or_curve;

    /* Verify the signature */
    verify_signature(hash_alg, sign_alg, key_size_or_curve, data, data_length,
                     signature_data, signature_length, modulus_or_x,
                     modulus_or_x_len, exponent_or_y, exponent_or_y_len);

    /* Free allocated memory */
    free(data);
    free(signature_data);
}

/** Parses a version 1 certificate from the given file.
 *
 * @param[in] file Pointer to the file containing the certificate.
 * @param[in] file_size Size of the file.
 * @param[in] container_offset Offset in the file where the container header starts.
 * @param[in] certificate_offset Offset in the file where the certificate starts.
 * @param[out] cert Pointer to the certificate structure to be filled.
 */
static void parse_certificate_v1(FILE *file, long file_size,
                                 long container_offset, long certificate_offset,
                                 struct ahab_certificate *cert)
{
    uint8_t cert_perm = 0;
    uint8_t cert_perm_inv = 0;

    /* Check for invalid arguments */
    if (file == NULL || cert == NULL)
    {
        fprintf(stderr, "Invalid input argument(s)\n");
        return;
    }

    /* Seek to the certificate offset */
    if (fseek(file, certificate_offset, SEEK_SET) != 0)
    {
        perror("Failed to seek to the certificate");
        return;
    }

    /* Read the certificate structure */
    if (fread(&cert->v1, sizeof(cert->v1), 1, file) != 1)
    {
        perror("Failed to read the certificate");
        return;
    }

    /* Validate the certificate's version and tag */
    if (cert->v1.version != CERTIFICATE_VERSION_1)
    {
        fprintf(stderr, "Error: Unsupported certificate version: %d\n",
                cert->v1.version);
        return;
    }

    if (cert->v1.tag != CERTIFICATE_TAG)
    {
        fprintf(stderr, "Error: Invalid certificate tag: 0x%X\n", cert->v1.tag);
        return;
    }

    /* Print the certificate information */
    print_with_indent("Certificate Information:\n");
    print_with_indent("Version: %d\n", cert->v1.version);
    print_with_indent("Length: %d bytes\n", cert->v1.length);
    print_with_indent("Tag: 0x%X\n", cert->v1.tag);
    print_with_indent("Signature Offset: 0x%X\n", cert->v1.signature_offset);

    cert_perm = (cert->v1.permissions >> CERTIFICATE_PERMISSIONS_SHFT) &
                CERTIFICATE_PERMISSIONS_MASK;
    cert_perm_inv = cert->v1.permissions & CERTIFICATE_PERMISSIONS_MASK;

    if ((cert_perm ^ cert_perm_inv) != CERTIFICATE_PERMISSIONS_MASK)
    {
        fprintf(stderr, "ERROR: Incorrect certificate permission encoding\n");
    }

    if (__builtin_popcount(cert_perm) != 1)
    {
        fprintf(stderr, "ERROR: Multiple permissions in certificate\n");
    }

    print_with_indent("Permissions: %s (0x%X)\n",
                      certificate_permissions_str[cert_perm], cert_perm);
    print_with_indent("Public Key Information:\n");

    if (parse_record(file, SRK_TABLE_VERSION_1,
                     certificate_offset +
                         offsetof(ahab_container_certificate_v1_t, public_key),
                     &cert->records[0]) != 0)
    {
        fprintf(stderr, "Failed to parse SRK certificate record\n");
        return;
    }

    if (cert->v1.signature_offset != 0)
    {
        parse_signature(file, file_size, container_offset,
                        certificate_offset + cert->v1.signature_offset,
                        certificate_offset, cert->v1.signature_offset, 0,
                        &cert->sig[0],
                        &g_srk_tables[0].records[g_srk_selection]);
    }
}

/** Parses a version 2 certificate from the given file.
 *
 * @param[in] file Pointer to the file containing the certificate.
 * @param[in] file_size Size of the file
 * @param[in] container_offset Offset in the file where the container header starts.
 * @param[in] certificate_offset Offset in the file where the certificate starts.
 * @param[in] nb_srk_table Number of SRK tables.
 * @param[out] cert Pointer to the certificate structure to be filled.
 */
static void parse_certificate_v2(FILE *file, long file_size,
                                 long container_offset, long certificate_offset,
                                 uint32_t nb_srk_table,
                                 struct ahab_certificate *cert)
{
    int i = 0;
    long offset = 0;
    uint8_t cert_perm = 0;
    uint8_t cert_perm_inv = 0;

    /* Check for invalid arguments */
    if (file == NULL || cert == NULL)
    {
        fprintf(stderr, "Invalid input argument(s)\n");
        return;
    }

    /* Seek to the certificate offset */
    if (fseek(file, certificate_offset, SEEK_SET) != 0)
    {
        perror("Failed to seek to the certificate");
        return;
    }

    /* Read the certificate structure */
    if (fread(&cert->v2, sizeof(cert->v2), 1, file) != 1)
    {
        perror("Failed to read the certificate");
        return;
    }

    /* Validate the certificate's version and tag */
    if (cert->v2.version != CERTIFICATE_VERSION_2)
    {
        fprintf(stderr, "Error: Unsupported certificate version: %d\n",
                cert->v2.version);
        return;
    }

    if (cert->v2.tag != CERTIFICATE_TAG)
    {
        fprintf(stderr, "Error: Invalid certificate tag: 0x%X\n", cert->v2.tag);
        return;
    }

    /* Print the certificate information */
    print_with_indent("Certificate Information:\n");
    print_with_indent("Version: %d\n", cert->v2.version);
    print_with_indent("Length: %d bytes\n", cert->v2.length);
    print_with_indent("Tag: 0x%X\n", cert->v2.tag);
    print_with_indent("Signature Offset: 0x%X\n", cert->v2.signature_offset);

    cert_perm = (cert->v2.permissions >> CERTIFICATE_PERMISSIONS_SHFT) &
                CERTIFICATE_PERMISSIONS_MASK;
    cert_perm_inv = cert->v2.permissions & CERTIFICATE_PERMISSIONS_MASK;

    if ((cert_perm ^ cert_perm_inv) != CERTIFICATE_PERMISSIONS_MASK)
    {
        fprintf(stderr, "ERROR: Incorrect certificate permission encoding\n");
    }

    if (__builtin_popcount(cert_perm) != 1)
    {
        fprintf(stderr, "ERROR: Multiple permissions in certificate\n");
    }

    print_with_indent("Permissions: %s (0x%X)\n",
                      certificate_permissions_str[cert_perm], cert_perm);

    print_with_indent("Permissions Data:");
    for (i = 0; i < ARRAY_SIZE(cert->v2.perm_data); i++)
    {
        print_with_indent("0x%X ", cert->v2.perm_data[i]);
    }
    printf("\n");

    print_with_indent("Fuse version: 0x%X\n", cert->v2.fuse_version);

    print_with_indent("UUID: ");
    for (i = 0; i < ARRAY_SIZE(cert->v2.uuid); i++)
    {
        print_with_indent("0x%X ", cert->v2.uuid[i]);
    }
    printf("\n");

    offset = certificate_offset + sizeof(cert->v2);

    for (i = 0; i < nb_srk_table; i++)
    {
        /* SRK record */
        if (parse_record(file, SRK_TABLE_VERSION_2, offset,
                         &cert->records[i]) != 0)
        {
            fprintf(stderr, "Failed to parse SRK record %d\n", i);
            return;
        }

        offset += cert->records[i].record.length;

        /* SRK data */
        parse_srk_data(file, offset, &cert->data[i]);

        /* Key data */
        parse_key_data(file, offset + sizeof(cert->data[i].data),
                       SRK_TABLE_VERSION_1, &cert->records[i]);

        offset += cert->data[i].data.length;
    }

    if (cert->v2.signature_offset != 0)
    {
        offset = 0;

        for (i = 0; i < nb_srk_table; i++)
        {
            parse_signature(
                file, file_size, container_offset,
                certificate_offset + cert->v2.signature_offset + offset,
                certificate_offset, cert->v2.signature_offset, i, &cert->sig[i],
                &g_srk_tables[i].records[g_srk_selection]);

            offset += cert->sig[i].length;
        }
    }
}

/** Parses and validates a certificate from the given container file.
 *
 * @param[in] file Pointer to the file containing the certificate.
 * @param[in] file_size Size of the file.
 * @param[in] container_offset Offset in the file where the container header starts.
 * @param[in] certificate_offset Offset in the file where the certificate starts.
 * @param[in] nb_srk_table Number of SRK tables.
 * @param[out] cert Pointer to the certificate structure to be filled.
 */
static void parse_certificate(FILE *file, long file_size, long container_offset,
                              long certificate_offset, uint32_t nb_srk_table,
                              struct ahab_certificate *cert)
{
    uint8_t certificate_version = 0;

    /* Check for invalid arguments */
    if (file == NULL || cert == NULL)
    {
        fprintf(stderr, "Invalid input argument(s)\n");
        return;
    }

    /* Seek to the certificate offset */
    if (fseek(file, certificate_offset, SEEK_SET) != 0)
    {
        perror("Failed to seek to the certificate");
        return;
    }

    if (fread(&certificate_version, sizeof(certificate_version), 1, file) != 1)
    {
        perror("Failed to read the certificate");
        return;
    }

    /* Validate the certificate's version and parse accordingly */
    if (certificate_version == CERTIFICATE_VERSION_1)
    {
        parse_certificate_v1(file, file_size, container_offset,
                             certificate_offset, cert);
    }
    else if (certificate_version == CERTIFICATE_VERSION_2)
    {
        parse_certificate_v2(file, file_size, container_offset,
                             certificate_offset, nb_srk_table, cert);
    }
    else
    {
        fprintf(stderr, "Error: Unsupported certificate version: %d\n",
                certificate_version);
        return;
    }
}

/** Parses and prints the blob information from the given container file.
 *
 * @param[in] file Pointer to the file containing the blob.
 * @param[in] blob_offset Offset in the file where the blob starts.
 */
static void parse_blob(FILE *file, long blob_offset)
{
    ahab_key_blob_header_t blob = {0};
    uint16_t length = 0;
    uint8_t blob_type = 0;

    /* Check for invalid arguments */
    if (file == NULL)
    {
        fprintf(stderr, "Invalid input argument: file is NULL\n");
        return;
    }

    /* Seek to the blob's offset in the file */
    if (fseek(file, blob_offset, SEEK_SET) != 0)
    {
        perror("Failed to seek to the blob");
        return;
    }

    /* Read the blob header */
    if (fread(&blob, sizeof(blob), 1, file) != 1)
    {
        perror("Failed to read the blob header");
        return;
    }

    /* Validate the blob's version and tag */
    if (blob.version != AHAB_BLOB_HEADER_VERSION)
    {
        fprintf(stderr, "Error: Unsupported blob version: %d\n", blob.version);
        return;
    }

    if (blob.tag != AHAB_BLOB_HEADER_TAG)
    {
        fprintf(stderr, "Error: Invalid blob tag: 0x%X\n", blob.tag);
        return;
    }

    /* Calculate and print the length of the blob */
    length = (blob.length_msb << 8) | blob.length_lsb;
    print_with_indent("Blob Information:\n");
    increase_indent();
    print_with_indent("Version: %d\n", blob.version);
    print_with_indent("Length: %d bytes\n", length);
    print_with_indent("Tag: 0x%X\n", blob.tag);

    /* Interpret the flags */
    print_with_indent("Flags: 0x%X\n", blob.flags);
    if (blob.flags & AHAB_BLOB_KEY_FLAGS_NON_SECURE)
    {
        printf("Non-Secure Key\n");
    }

    blob_type = blob.flags & AHAB_BLOB_KEY_FLAGS_BLOB_TYPE_MASK;
    switch (blob_type)
    {
        case AHAB_BLOB_KEY_FLAGS_BLOB_TYPE_DEK:
            print_with_indent("Blob Type: DEK\n");
            break;
        default:
            print_with_indent("Blob Type: Unknown (0x%X)\n", blob_type);
            break;
    }

    /* Interpret the key size */
    print_with_indent("Key Size: ", blob.size);
    switch (blob.size)
    {
        case AHAB_BLOB_KEY_SIZE_AES128:
            printf("128-bit");
            break;
        case AHAB_BLOB_KEY_SIZE_AES192:
            printf("192-bit");
            break;
        case AHAB_BLOB_KEY_SIZE_AES256:
            printf("256-bit");
            break;
        default:
            printf("Unknown Key Size (0x%X)", blob.size);
            break;
    }
    print_with_indent("\n");

    /* Interpret the algorithm */
    print_with_indent("Algorithm: ");
    switch (blob.algorithm)
    {
        case AHAB_BLOB_HEADER_ALGO_AES:
            printf("AES");
            break;
        case AHAB_BLOB_CS_ALGO_AES_CBC:
            printf("AES-CBC");
            break;
        case AHAB_BLOB_CS_ALGO_AES_CTR:
            printf("AES-CTR");
            break;
        case AHAB_BLOB_CS_ALGO_AES_XTS:
            printf("AES-XTS");
            break;
        default:
            printf("Unknown Algorithm (0x%X)", blob.algorithm);
            break;
    }

    print_with_indent("\n");

    /* Interpret the mode */
    print_with_indent("Mode: ");
    switch (blob.mode)
    {
        case AHAB_BLOB_HEADER_MODE_UNDEFINED:
            printf("Undefined Mode");
            break;
        case AHAB_BLOB_HEADER_MODE_CBC_MAC:
            printf("CBC MAC");
            break;
        case AHAB_BLOB_HEADER_MODE_CBC:
            printf("CBC");
            break;
        case AHAB_BLOB_HEADER_MODE_XTS:
            printf("XTS");
            break;
        case AHAB_BLOB_HEADER_MODE_CTR:
            printf("CTR");
            break;
        default:
            printf("Unknown Mode (0x%X)", blob.mode);
            break;
    }

    decrease_indent();

    print_with_indent("\n");
}

/** Parses and validates the signature block from the given container file.
 *
 * @param[in] file Pointer to the file containing the signature block.
 * @param[in] file_size size of the file.
 * @param[in] container_offset Offset in the file where the container header starts.
 * @param[in] signature_block_offset Offset in the file where the signature block starts.
 */
static void parse_signature_block(FILE *file, long file_size,
                                  long container_offset,
                                  long signature_block_offset)
{
    ahab_container_signature_block_t sig_block = {0};
    struct ahab_srk_record *srk_record = NULL;
    long offset = 0;
    uint32_t nb_srk_table = 1;
    int i = 0;
    int j = 0;

    /* Check for invalid arguments */
    if (file == NULL)
    {
        fprintf(stderr, "Invalid input argument: file is NULL\n");
        return;
    }

    /* Seek to the signature block offset */
    if (fseek(file, signature_block_offset, SEEK_SET) != 0)
    {
        perror("Failed to seek to the signature block");
        return;
    }

    /* Read the signature block */
    if (fread(&sig_block, sizeof(sig_block), 1, file) != 1)
    {
        perror("Failed to read the signature block");
        return;
    }

    /* Validate the signature block version and tag */
    if (sig_block.version != SIGNATURE_BLOCK_VERSION_1 &&
        sig_block.version != SIGNATURE_BLOCK_VERSION_2)
    {
        fprintf(stderr, "Error: Unsupported signature block version: %d\n",
                sig_block.version);
        return;
    }
    if (sig_block.tag != SIGNATURE_BLOCK_TAG)
    {
        fprintf(stderr, "Error: Invalid signature block tag: 0x%X\n",
                sig_block.tag);
        return;
    }

    /* Display the signature block details */
    print_with_indent("Signature Block:\n");
    increase_indent();
    print_with_indent("Version: %d\n", sig_block.version);
    print_with_indent("Length: %d bytes\n", sig_block.length);
    print_with_indent("Tag: 0x%X\n", sig_block.tag);
    print_with_indent("Certificate Offset: 0x%X\n",
                      sig_block.certificate_offset);
    print_with_indent("SRK Table/Array Offset: 0x%X\n",
                      sig_block.srk_table_or_array_offset);

    /* Parse SRK table or array */
    if (sig_block.srk_table_or_array_offset != 0)
    {
        if (sig_block.version == SIGNATURE_BLOCK_VERSION_1)
        {
            parse_srk_table(file,
                            signature_block_offset +
                                sig_block.srk_table_or_array_offset,
                            &g_srk_tables[0]);
        }
        else if (sig_block.version == SIGNATURE_BLOCK_VERSION_2)
        {
            parse_srk_table_array(file,
                                  signature_block_offset +
                                      sig_block.srk_table_or_array_offset,
                                  &nb_srk_table);
        }
        else
        {
            fprintf(stderr, "Error: Unsupported signature block version: %d\n",
                    sig_block.version);
            return;
        }
    }

    /* Parse certificate */
    if (sig_block.certificate_offset != 0)
    {
        parse_certificate(file, file_size, container_offset,
                          signature_block_offset + sig_block.certificate_offset,
                          nb_srk_table, &g_certificate);
    }

    print_with_indent("Blob Offset: 0x%X\n", sig_block.blob_offset);

    /* Parse blob */
    if (sig_block.blob_offset != 0)
    {
        parse_blob(file, signature_block_offset + sig_block.blob_offset);
    }

    print_with_indent("Key Identifier: 0x%X\n", sig_block.key_identifier);

    /* Parse signatures */
    for (i = 0; i < nb_srk_table; i++)
    {
        if (sig_block.certificate_offset != 0)
        {
            srk_record = &g_certificate.records[i];
        }
        else
        {
            srk_record = &g_srk_tables[i].records[g_srk_selection];
        }

        parse_signature(file, file_size, container_offset,
                        signature_block_offset + sig_block.signature_offset +
                            offset,
                        container_offset,
                        signature_block_offset + sig_block.signature_offset -
                            container_offset,
                        i, &g_srk_tables[i].sig, srk_record);

        offset += g_srk_tables[i].sig.length;
    }

    decrease_indent();

    /* Free allocated resources */
    for (j = 0; j < nb_srk_table; j++)
    {
        for (i = 0; i < MAX_SRK_RECORDS; i++)
        {
            if (g_srk_tables[j].records[i].modulus_or_x)
            {
                free(g_srk_tables[j].records[i].modulus_or_x);
                g_srk_tables[j].records[i].modulus_or_x = NULL;
            }

            if (g_srk_tables[j].records[i].exponent_or_y)
            {
                free(g_srk_tables[j].records[i].exponent_or_y);
                g_srk_tables[j].records[i].exponent_or_y = NULL;
            }

            if (g_srk_tables[j].records[i].srk_data_hash)
            {
                free(g_srk_tables[j].records[i].srk_data_hash);
                g_srk_tables[j].records[i].srk_data_hash = NULL;
            }
        }
    }
}

/** Parses and displays the signed message header from the given container file.
 *
 * @param[in] file Pointer to the file containing the signature block.
 * @param[in] message_header_offset Offset in the file where the signed message header starts.
 */
static void parse_signed_message(FILE *file, long message_header_offset)
{

    ahab_signed_message_header_t msg_header = {0};
    uint8_t *iv = NULL;
    uint8_t month = 0;
    uint16_t year = 0;

    /* Check for invalid arguments */
    if (file == NULL)
    {
        fprintf(stderr, "Invalid input argument: file is NULL\n");
        return;
    }

    /* Seek to the signature block offset */
    if (fseek(file, message_header_offset, SEEK_SET) != 0)
    {
        perror("Failed to seek to the signature block");
        return;
    }

    /* Read the signature block */
    if (fread(&msg_header, sizeof(msg_header), 1, file) != 1)
    {
        perror("Failed to read the message header");
        return;
    }

    print_with_indent("Message Header:\n");
    increase_indent();
    print_with_indent("Flags: 0x%X (%s)\n", msg_header.flags,
                      msg_header.flags ? "Encrypted" : "None");

    /* Print IV as byte array */
    print_with_indent("IV: ");
    iv = (uint8_t *) msg_header.iv;
    for (int i = 0; i < 32; i++)
    {
        printf("%02X", iv[i]);
    }
    printf("\n");

    /* Extract the month and year */
    month = (msg_header.issue_date & 0xF000) >> 12;

    /* Validate the month */
    if (month < 1 || month > 12)
    {
        fprintf(stderr, "Invalid issue month\n");
    }

    year = msg_header.issue_date & 0x0FFF;
    print_with_indent("Issue Date: %u/%u\n", month, year);

    print_with_indent("Permission: 0x%X\n", msg_header.permission);
    print_with_indent("Certificate Version: 0x%X\n", msg_header.cert_version);
    print_with_indent("Monotonic Counter: 0x%X\n",
                      msg_header.monotonic_counter);
    print_with_indent("ID: 0x%X ", msg_header.id);
    switch (msg_header.id)
    {
        case 0x01:
            printf("(SAB_KEY_STORE_SEC_PROV)");
            break;
        case 0x02:
            printf("(SAB_ROOT_KEY_ENCRYPTION_KEY_EXPORT_EN)");
            break;
        case 0x03:
            printf("(SAB_KEY_EXCHANGE_KEK_GENERATION_EN)");
            break;
        case 0x91:
            printf("(AHAB_WRITE_SEC_FUSE)");
            break;
        case 0x94:
            printf("(AHAB_ENABLE_DEBUG)");
            break;
        case 0xA0:
            printf("(AHAB_RETURN_LIFECYCLE_UPDATE)");
            break;
        case 0xB5:
            printf("(AHAB_FIPS_CLUSTER_DEGRADE)");
            break;
        case 0xC3:
            printf("(AHAB_FIPS_KEY_ZEROIZATION)");
            break;
        default:
            printf("(Unknown or invalid)");
            break;
    }
    printf("\n");
    print_with_indent("UID: 0x%llX\n", (unsigned long long) msg_header.uid);
    decrease_indent();
}

/** Parses and processes a container
 *
 * @param[in] file Handle on the file containing the container.
 * @param[in] offset Offset in the file where the container starts.
 * @param[in] file_size Size of the file.
 * @param[out] PARSE_ERROR_OK if OK, else error code.
 */
static enum parse_error_e handle_container(FILE *file, long offset,
                                           long file_size, uint8_t index)
{
    struct ahab_container_header_s header = {0};
    long image_offset = 0;
    uint8_t err = PARSE_ERROR_OK;
    int i = 0;

    /* Read the header */
    read_data(file, &header, sizeof(header), offset);

    /* Validate the header */
    err = validate_header(&header, file_size);
    if (err != PARSE_ERROR_OK)
    {
        return err;
    }

    print_with_indent("\nContainer #%d - offset: 0x%lX\n", index, offset);
    /* Display the header */
    display_header(&header);

    /* Process each image */
    if (header.tag == CONTAINER_HEADER_TAG ||
        header.tag == V2X_CONTAINER_HEADER_TAG)
    {
        image_offset = offset + sizeof(header);
        for (i = 0; i < header.nrImages; i++)
        {
            struct ahab_container_image_s image;
            read_data(file, &image, sizeof(image), image_offset);

            /* Perform any necessary validation on the image */
            if (image.image_offset + image.image_size > file_size)
            {
                return PARSE_ERROR_INCORRECT_SIZE;
            }

            /* Display the image data */
            display_image(&image, i, &header);

            /* Verify the image integrity */
            verify_image(file, file_size, offset, &image, i, &header);

            image_offset += sizeof(image);
        }

        /* Parse the signature block if the SRK set is not NONE */
        if ((header.flags & 0xF) != HEADER_FLAGS_SRK_SET_NONE)
        {
            parse_signature_block(file, file_size, offset,
                                  offset + header.signature_block_offset);
        }
    }
    else
    {
        /* Parse signed message */
        parse_signed_message(file, offset + sizeof(header));

        /* Parse the signature block if the SRK set is not NONE */
        if ((header.flags & 0xF) != HEADER_FLAGS_SRK_SET_NONE)
        {
            parse_signature_block(file, file_size, offset,
                                  offset + header.signature_block_offset);
        }
    }
    printf("Warning: Remember to verify the hash value of the SRK table(s) "
           "carefully.\n");
    return PARSE_ERROR_OK;
}

/** Parses and processes the container file.
 *
 * @param[in] filename Name of the file to be parsed.
 * @param[in] offset Offset in the file where the container starts.
 * @param[in] continuous If not 0, parse the whole file and search for containers
 */
static void parse_file(const char *filename, long offset, uint8_t continuous)
{
    FILE *file = NULL;
    long file_size = 0;
    long local_offset = offset;
    uint8_t container_index = 0, err = PARSE_ERROR_OK;

    /* Check for invalid arguments */
    if (filename == NULL)
    {
        fprintf(stderr, "Invalid input argument: filename is NULL\n");
        return;
    }

    /* Open the file */
    file = fopen(filename, "rb");
    if (!file)
    {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }

    /* Get the file size */
    if (fseek(file, 0, SEEK_END) != 0)
    {
        perror("Failed to seek to the end of the file");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    file_size = ftell(file);
    if (file_size == -1L)
    {
        perror("Failed to get the file size");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    rewind(file);

    /* Validate offset */
    if (offset < 0 || (long) offset >= file_size)
    {
        fprintf(
            stderr,
            "ERROR: Offset 0x%lX is out of file bounds (size: %ld bytes).\n",
            offset, file_size);
        fclose(file);
        exit(EXIT_FAILURE);
    }

    print_with_indent("Notice: %s is intended solely for experimentation and "
                      "debugging purposes.\n",
                      g_tool_name);
    print_with_indent("It should not be considered as proof or validation of a "
                      "good ahab container under any circumstances.\n");
    print_with_indent(
        "For official verification and container integrity checks, users must "
        "proceed with the recommended secure boot procedures,\n");
    print_with_indent("such as using the `ahab_status` command as outlined in "
                      "the relevant documentation.\n\n");

    print_with_indent("File: %s\n", filename);
    if (continuous)
    {
        for (local_offset = 0; local_offset < file_size;
             local_offset += CONTAINER_OFFSET_INCREMENT)
        {
            err = handle_container(file, local_offset, file_size,
                                   container_index);
            if (err == PARSE_ERROR_OK)
            {
                container_index++;
            }
        }
    }
    else
    {
        err = handle_container(file, offset, file_size, container_index);
        if (err != PARSE_ERROR_OK)
        {
            printf("Got error %d when parsing the container at offset 0x%lX\n",
                   err, offset);
        }
    }
    fclose(file);
}

/**
 * Displays the usage information for the tool.
 */
static void print_usage()
{
    printf("Usage: %s [options] <container> [offset]\n", g_tool_name);
    printf("  [offset] is optional. If not provided, will use heuristics\n"
           "  to find containers in the file and display everything found.\n"
           "  Could detect false positives.\n");
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
    long container_offset = 0;
    uint8_t continuous = 0;

    /* Parse command-line options */
    for (int i = 1; i < argc; i++)
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

    if (argc < 2)
    {
        print_usage();
        return EXIT_FAILURE;
    }

    filename = argv[1];
    if (argc == 3)
    {
        container_offset = strtol(argv[2], NULL, 0);
        if (errno == ERANGE)
        {
            perror("Invalid offset");
            exit(EXIT_FAILURE);
        }
        continuous = 0;
    }
    else
    {
        container_offset = 0;
        continuous = 1;
    }

    /* Initialize OpenSSL context */
    openssl_initialize();

    /* Parse the image */
    parse_file(filename, container_offset, continuous);

    return EXIT_SUCCESS;
}
