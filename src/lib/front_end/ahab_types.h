/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2017-2020, 2024-2025 NXP
 */

#ifndef AHAB_TYPES_H
#define AHAB_TYPES_H

#include "bitops.h"

/*
 * Definitions applicable for all cryptography related headers:
 *  - certificate
 *  - signature
 *  - Super Root Key
 *  - image (hashing)
 */
#define SRK_RSA         0x21
#define SRK_RSA_PSS     0x22
#define SRK_ECDSA       0x27
#define SRK_DILITHIUM   0xD1
#define SRK_MLDSA 0xD2

#define SRK_PRIME256V1  0x1
#define SRK_SEC384R1    0x2
#define SRK_SEC521R1    0x3
#define SRK_RSA2048     0x5
#define SRK_RSA3072     0x6
#define SRK_RSA4096     0x7
#define SRK_DILITHIUM3  0x9
#define SRK_DILITHIUM5 0xa
#define SRK_MLDSA65 0x9
#define SRK_MLDSA87 0xa

#define SRK_SHA256 0x0
#define SRK_SHA384 0x1
#define SRK_SHA512 0x2
#define SRK_SHA3_256 0x4
#define SRK_SHA3_384 0x5
#define SRK_SHA3_512 0x6
#define SRK_SHAKE128_256 0x8
#define SRK_SHAKE256_512 0x9

#define MAX_SRK_HASH_TYPE SRK_SHAKE256_512

/* Backward compatibility with existing CST code (hab_types.h) */
#define HAB_ALG_SHA3_256 0x4
#define HAB_ALG_SHA3_384 0x5
#define HAB_ALG_SHA3_512 0x6
#define HAB_ALG_SHAKE128_256 0x8
#define HAB_ALG_SHAKE256_512 0x9

struct __attribute__ ((packed)) ahab_container_image_s {
    /* offset 0x0 */
    uint32_t image_offset;
    /* offset 0x4 */
    uint32_t image_size;
    /* offset 0x8 */
    uint64_t load_address;
    /* offset 0x10 */
    uint64_t entry_point;
    /* offset 0x18 */
    uint32_t flags;
    /* offset 0x1c */
    uint32_t reserved;
    /* offset 0x20 */
    uint8_t hash[64];
    /* offset 0x60 */
    uint8_t iv[32];
};

#define IMAGE_FLAGS_TYPE_SHIFT 0
#define IMAGE_FLAGS_TYPE_MASK (BIT_MASK(3, 0))
#define IMAGE_FLAGS_TYPE_EXECUTABLE 0x3
#define IMAGE_FLAGS_TYPE_DATA 0x4
#define IMAGE_FLAGS_TYPE_DCD 0x5
#define IMAGE_FLAGS_TYPE_SECO 0x6
#define IMAGE_FLAGS_TYPE_PROVISIONING 0x7
#define IMAGE_FLAGS_TYPE_DEK 0x8
#define IMAGE_FLAGS_TYPE_HDMI 0x9
#define IMAGE_FLAGS_TYPE_DP 0xA
#define IMAGE_FLAGS_TYPE_V2XP 0xB
#define IMAGE_FLAGS_TYPE_V2XS 0xC
#define IMAGE_FLAGS_TYPE_OEI 0x5
#define IMAGE_FLAGS_TYPE_V2X_DUMMY 0xE

#define IMAGE_FLAGS_TYPE_ELE_CNTN_AS_IMAGE 0x05
#define IMAGE_FLAGS_TYPE_V2X_CNTN_AS_IMAGE 0x0a

static inline uint8_t ahab_container_image_get_type(struct ahab_container_image_s *hdr)
{
    return bf_get_uint8(hdr->flags, IMAGE_FLAGS_TYPE_MASK, IMAGE_FLAGS_TYPE_SHIFT);
}

#define IMAGE_FLAGS_CORE_ID_SHIFT   4
#define IMAGE_FLAGS_CORE_ID_MASK    (BIT_MASK(7, 4))
/* SECO devices */
#define IMAGE_CORE_ID_SC         1
#define IMAGE_CORE_ID_CM4_0      2
#define IMAGE_CORE_ID_CM4_1      3
#define IMAGE_CORE_ID_CA53       4
#define IMAGE_CORE_ID_CA35       4
#define IMAGE_CORE_ID_CA72       5
#define IMAGE_CORE_ID_SECO       6
#define IMAGE_CORE_ID_V2X_1 9
#define IMAGE_CORE_ID_V2X_2 10
/* ELE devices */
#define IMAGE_CORE_ID_RTC 0x01
#define IMAGE_CORE_ID_APC 0x02
#define IMAGE_CORE_ID_ELE 0x06 /* intentially same as SECO */
#define IMAGE_CORE_ID_V2X_PRIMARY 0x09
#define IMAGE_CORE_ID_V2X_SECONDARY 0x0a
#define IMAGE_CORE_ID_M7_0 0x0b
#define IMAGE_CORE_ID_M7_1 0x0c
#define IMAGE_CORE_ID_M33_SYNC 0x0d

#define IMAGE_FLAGS_HASH_SHIFT      8
#define IMAGE_FLAGS_HASH_MASK_1 (BIT_MASK(10, 8))
#define IMAGE_FLAGS_HASH_MASK_2 (BIT_MASK(11, 8))

static inline uint8_t
ahab_container_image_get_hash_1(struct ahab_container_image_s *hdr)
{
    return bf_get_uint8(hdr->flags, IMAGE_FLAGS_HASH_MASK_1,
                        IMAGE_FLAGS_HASH_SHIFT);
}

static inline uint8_t
ahab_container_image_get_hash_2(struct ahab_container_image_s *hdr)
{
    return bf_get_uint8(hdr->flags, IMAGE_FLAGS_HASH_MASK_2,
                        IMAGE_FLAGS_HASH_SHIFT);
}

#define IMAGE_FLAGS_ENCRYPTED_SHIFT_1 11
#define IMAGE_FLAGS_ENCRYPTED_SHIFT_2 12
#define IMAGE_FLAGS_ENCRYPTED_1 (BIT(IMAGE_FLAGS_ENCRYPTED_SHIFT_1))
#define IMAGE_FLAGS_ENCRYPTED_2 (BIT(IMAGE_FLAGS_ENCRYPTED_SHIFT_2))

#define CONTAINER_HEADER_TAG       0x87
#define CONTAINER_HEADER_VERSION_1 0x00
#define CONTAINER_HEADER_VERSION_2 0x02
#define V2X_CONTAINER_HEADER_TAG 0x82

struct __attribute__ ((packed)) ahab_container_header_s {
    /* offset 0x0*/
    uint8_t version;
    uint16_t length;
    uint8_t tag;
    /* offset 0x4*/
    uint32_t flags;
    /* offset 0x8*/
    uint16_t sw_version;
    uint8_t fuse_version;
    uint8_t nrImages;
    /* offset 0xc*/
    uint16_t signature_block_offset;
    uint16_t reserved;
};

static inline struct ahab_container_image_s *
get_ahab_image_array(struct ahab_container_header_s *header)
{
    return (struct ahab_container_image_s *)(uintptr_t)
           ((uintptr_t) header + sizeof(struct ahab_container_header_s));
}

#define HEADER_FLAGS_SRK_SET_SHIFT  0
#define HEADER_FLAGS_SRK_SET_MASK   (BIT_MASK(1, 0))
#define HEADER_FLAGS_SRK_SET_NONE   0x0
#define HEADER_FLAGS_SRK_SET_NXP    0x1
#define HEADER_FLAGS_SRK_SET_OEM    0x2

#define HEADER_FLAGS_SRK_SHIFT  4
#define HEADER_FLAGS_SRK_MASK   (BIT_MASK(5, 4))

#define HEADER_FLAGS_REVOKING_MASK_SHIFT 8
#define HEADER_FLAGS_REVOKING_MASK_MASK (BIT_MASK(11, 8))

#define HEADER_FLAGS_CHECK_ALL_SIGNATURES_MASK_SHIFT 15
#define HEADER_FLAGS_CHECK_ALL_SIGNATURES_FUSE 0x0
#define HEADER_FLAGS_CHECK_ALL_SIGNATURES_ALL 0x1

#define HEADER_FLAGS_FAST_BOOT_MASK_SHIFT 16
#define HEADER_FLAGS_FAST_BOOT_MASK (BIT_MASK(18, 16))

typedef struct __attribute__ ((packed)) ahab_container_signature_block_s {
    /* offset 0x0 */
    uint8_t version;
    uint16_t length;
    uint8_t tag;
    /* offset 0x4 */
    uint16_t certificate_offset;
    uint16_t srk_table_or_array_offset;
    /* offset 0x8 */
    uint16_t signature_offset;
    uint16_t blob_offset;
    /* offset 0xc */
    uint32_t key_identifier;
    /* offset 0x10 */
} ahab_container_signature_block_t;

#define SIGNATURE_BLOCK_TAG        0x90
#define SIGNATURE_BLOCK_VERSION_1  0x00
#define SIGNATURE_BLOCK_VERSION_2  0x01

#define SRK_TAG         0xE1
#define SRK_FLAGS_CA    0x80

#define CNTN_MAX_SRK_TABLE_RECORDS 4

struct __attribute__ ((packed)) ahab_container_srk_s {
    /* offset 0x0 */
    uint8_t tag;
    uint16_t length;
    uint8_t sign_alg;
    /* offset 0x4 */
    uint8_t hash_alg;
    uint8_t key_size_or_curve;
    uint8_t reserved;
    uint8_t flags;
    /* offset 0x8 */
    uint16_t modulus_or_x_or_pk_length;
    uint16_t exponent_or_y_length;
};

#define SRK_DATA_TAG       0x5D
#define SRK_DATA_VERSION   0x00
typedef struct __attribute__ ((packed)) ahab_container_srk_data_s {
    /* offset 0x0 */
    uint8_t version;
    uint16_t length;
    uint8_t tag;
    /* offset 0x4 */
    uint8_t srk_record_number;
    uint8_t reserved[3];
} ahab_container_srk_data_t;

/* Hash of SRK Data entry is fixed size at 512 bits. */
#define SRK_DATA_HASH_SIZE 64
/* Allocate enough memory to hold SRK data structure including key data */
#define MAX_SRK_DATA_SIZE 2048

#define SRK_TABLE_ARRAY_TAG 0x5A
#define SRK_TABLE_ARRAY_VERSION 0x00
#define CNTN_MAX_NR_SRK_TABLE 2

typedef struct __attribute__ ((packed)) ahab_container_srk_table_array_s {
    /* offset 0x0 */
    uint8_t version;
    uint16_t length;
    uint8_t tag;
    uint8_t number_srk_table;
    uint8_t reserved[3];
    /* offset 0x4 */
} ahab_container_srk_table_array_t;

#define SRK_TABLE_TAG       0xD7
#define SRK_TABLE_VERSION_1 0x42
#define SRK_TABLE_VERSION_2 0x43
struct __attribute__ ((packed)) ahab_container_srk_table_s {
    /* offset 0x0 */
    uint8_t tag;
    uint16_t length;
    uint8_t version;
    /* offset 0x4 */
};

#define SIGNATURE_TAG 0xD8
struct __attribute__ ((packed)) ahab_container_signature_s {
    /* offset 0x0 */
    uint8_t version;
    uint16_t length;
    uint8_t tag;
    /* offset 0x4 */
    uint32_t reserved;
    /* offset 0x8 */
    uint8_t data[];
};

#define CERTIFICATE_TAG 0xAF
#define CERTIFICATE_PERMISSIONS_MASK 0xFF
#define CERTIFICATE_PERMISSIONS_SHFT 8
#define CERTIFICATE_INVERTED_PERMISSIONS_SHFT 0

#define CERTIFICATE_PERMISSIONS_OEM_SIG_CONT (1 << 0)
#define CERTIFICATE_PERMISSIONS_OEM_DBG_SCU (1 << 1)
#define CERTIFICATE_PERMISSIONS_OEM_DBG_CM4 (1 << 2)
#define CERTIFICATE_PERMISSIONS_OEM_DBG_APPS_VPU (1 << 3)
#define CERTIFICATE_PERMISSIONS_OEM_FUS_SCU_VER_LC (1 << 4)
#define CERTIFICATE_PERMISSIONS_OEM_FUS_MONO_CNT (1 << 5)
#define CERTIFICATE_PERMISSIONS_OEM_FUS_HDCP (1 << 6)
#define CERTIFICATE_PERMISSIONS_OEM_FUS_PATCH (1 << 7)

#define CERTIFICATE_VERSION_1 0x00
typedef struct __attribute__ ((packed)) ahab_container_certificate_v1_s {
    /* offset 0x0 */
    uint8_t version;
    uint16_t length;
    uint8_t tag;
    /* offset 0x4 */
    uint16_t signature_offset;
    uint16_t permissions;
    /* offset 0x8 */
    struct ahab_container_srk_s public_key;
} ahab_container_certificate_v1_t;

#define CERTIFICATE_VERSION_2 0x02
typedef struct __attribute__ ((packed)) ahab_container_certificate_v2_s {
    /* offset 0x0 */
    uint8_t version;
    uint16_t length;
    uint8_t tag;
    /* offset 0x4 */
    uint16_t signature_offset;
    uint16_t permissions;
    uint32_t perm_data[3];
    uint8_t fuse_version;
    uint8_t res[3];
    uint32_t uuid[4];
} ahab_container_certificate_v2_t;

/* Public declarations and definitions */
#define AHAB_MAX_NR_IMAGES 32

typedef enum ahab_hash
{
    HASH_SHA256 = SRK_SHA256,
    HASH_SHA384 = SRK_SHA384,
    HASH_SHA512 = SRK_SHA512,
    HASH_SHA3_256 = SRK_SHA3_256,
    HASH_SHA3_384 = SRK_SHA3_384,
    HASH_SHA3_512 = SRK_SHA3_512,
    HASH_SHAKE128_256 = SRK_SHAKE128_256,
    HASH_SHAKE256_512 = SRK_SHAKE256_512,
} ahab_hash_t;

#define AHAB_BLOB_HEADER          8
#define CAAM_BLOB_OVERHEAD_NORMAL 48

#define AHAB_BLOB_HEADER_TAG (0x81)
#define AHAB_BLOB_HEADER_VERSION (0x00)

#define AHAB_BLOB_HEADER_MODE_UNDEFINED (0x00)
#define AHAB_BLOB_HEADER_MODE_CBC_MAC (0x66)
#define AHAB_BLOB_HEADER_MODE_CBC (0x67)
#define AHAB_BLOB_HEADER_MODE_XTS (0x68)
#define AHAB_BLOB_HEADER_MODE_CTR (0x69)

#define AHAB_BLOB_HEADER_ALGO_AES (0x55)
#define AHAB_BLOB_HEADER_ALGO_MULTI2 (0x56)

#define AHAB_BLOB_KEY_SIZE_AES128 (0x10)
#define AHAB_BLOB_KEY_SIZE_AES192 (0x18)
#define AHAB_BLOB_KEY_SIZE_AES256 (0x20)

/* CS defines */
#define AHAB_BLOB_CS_ALGO_AES_CBC (0x03)
#define AHAB_BLOB_CS_ALGO_AES_CTR (0x04)
#define AHAB_BLOB_CS_ALGO_AES_XTS (0x37)

#define AHAB_BLOB_KEY_FLAGS_NON_SECURE (0x40)
#define AHAB_BLOB_KEY_FLAGS_BLOB_TYPE_MASK (0x07)
#define AHAB_BLOB_KEY_FLAGS_BLOB_TYPE_DEK (0x01)

typedef struct
{
    uint8_t version;
    uint8_t length_lsb;
    uint8_t length_msb;
    uint8_t tag;
    uint8_t flags;
    uint8_t size;
    uint8_t algorithm;
    uint8_t mode;
} ahab_key_blob_header_t;

#define SIGNED_MESSAGE_HEADER_TAG 0x89

typedef struct __attribute__((packed)) ahab_signed_message_header_s
{
    uint8_t flags;
    uint8_t reserved[3];
    uint32_t iv[8];
    uint16_t issue_date;
    uint8_t permission;
    uint8_t cert_version;
    uint16_t monotonic_counter;
    uint8_t id;
    uint8_t reserved2;
    uint64_t uid;
} ahab_signed_message_header_t;

#endif /* AHAB_TYPES_H */
