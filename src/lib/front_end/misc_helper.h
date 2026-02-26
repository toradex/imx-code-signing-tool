/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020, 2023 NXP
 */

#ifndef MISC_HELPER_H
#define MISC_HELPER_H
/*===========================================================================*/
/**
    @file    misc_helper.h

    @brief   Provide miscellaneous helper functions
 */

/*===========================================================================
                            INCLUDE FILES
=============================================================================*/
#include "csf.h"

/*===========================================================================
                    STRUCTURES AND OTHER TYPEDEFS
=============================================================================*/
/** Byte string
 *
 * Defines the byte string struct
 */
typedef struct byte_str_s
{
    uint8_t *entry;
    size_t  entry_bytes;
} byte_str_t;

/*===========================================================================
                         FUNCTION PROTOTYPES
=============================================================================*/
#ifdef __cplusplus
extern "C" {
#endif

/** Read bytes from a file
 *
 * Reads an amount of bytes from an input file
 *
 * @param[in]  filename Input file name to be read
 *
 * @param[out] byte_str Byte string struct to return the read data
 *
 * @param[in]  offsets  If defined,
 *
 * @pre @a filename and @a offsets must not be NULL
 *
 * @post none
 *
 * @returns the size of memory allocated point to by byte_str
 */
void
read_file(const char *filename, byte_str_t *byte_str, offsets_t *offsets);

#ifdef __cplusplus
}
#endif

#endif /* MISC_HELPER_H */
