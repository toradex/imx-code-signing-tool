/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2018-2019, 2023-2025 NXP
 */

#ifndef ARCH_TYPES_H
#define ARCH_TYPES_H
/*===========================================================================*/
/**
    @file    arch_types.h

    @brief   Boot architectures interface
 */

/*===========================================================================
                            INCLUDE FILES
=============================================================================*/
#include "hab_types.h"
#include "ahab_types.h"

/*===========================================================================
                                MACROS
=============================================================================*/

/* Maximums supported by the different architectures */
#define MAX_CERTIFICATES_ALLOWED  4    /**< Max number of X.509 certs */
#if CST_WITH_PQC
#define MAX_SRK_TABLE_BYTES \
    8192 /**< Maximum bytes for SRK table with PQC support */
#else
#define MAX_SRK_TABLE_BYTES \
    3072 /**< Maximum bytes for SRK table without PQC support */
#endif

/* HAB4/AHAB SRK Table definitions */
#define SRK_TABLE_HEADER_BYTES    4    /**< Number of bytes in table header */
#define SRK_KEY_HEADER_BYTES      12   /**< Number of bytes in key header */

/* Missing define in container.h */
#define SRK_RSA3072               0x6

/* Macro to check if a given tgt_t value is undefined */
#define IS_UNDEF(target)                                 \
    ((target) == TGT_UNDEF ||                            \
     ((target) != TGT_HAB_4 && (target) != TGT_AHAB_1 && \
      (target) != TGT_AHAB_2))

/* Macro to check if a given tgt_t value is an AHAB type */
#define IS_AHAB(target) ((target) == TGT_AHAB_1 || (target) == TGT_AHAB_2)

/* Macro to check if a given tgt_t value is a HAB type */
#define IS_HAB(target) ((target) == TGT_HAB_4)

/* Macro to check if a given tgt_t value is AHAB_1 */
#define IS_AHAB_1(target) ((target) == TGT_AHAB_1)

/* Macro to check if a given tgt_t value is AHAB_2 */
#define IS_AHAB_2(target) ((target) == TGT_AHAB_2)

/*===========================================================================
                                TYPEDEFS
=============================================================================*/
typedef enum tgt_e
{
    TGT_UNDEF = 0, /**< Undefined target */
    TGT_HAB_4,     /**< HAB  version 4 target  */
    TGT_AHAB_1,    /**< AHAB version 1 target  */
    TGT_AHAB_2,    /**< AHAB version 2 target  */
} tgt_t;

typedef enum srk_set_e
{
    SRK_SET_UNDEF = 0, /**< Undefined SRK set */
    SRK_SET_NXP,       /**< NXP SRK set       */
    SRK_SET_OEM,       /**< OEM SRK set       */
} srk_set_t;

typedef enum check_all_signatures_e
{
    CHECK_ALL_SIGNATURES_UNDEF = -1, /**< Undefined check signatures policy */
    CHECK_ALL_SIGNATURES_FUSE,       /**< Apply default fuse policy */
    CHECK_ALL_SIGNATURES_ALL, /**< Force verification of all present signatures */
} check_all_signatures_t;

#endif /* ARCH_TYPES_H */
