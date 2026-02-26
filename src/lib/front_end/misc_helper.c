// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2023-2024 NXP
 */

/*===========================================================================*/
/**
    @file    misc_helper.c

    @brief   Provide miscellaneous helper functions 
 */

/*===========================================================================
                                INCLUDE FILES
=============================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "misc_helper.h"
#include "err.h"

/*===========================================================================
                               LOCAL CONSTANTS
=============================================================================*/
#define MAX_ERR_MSG_BYTES (1024)

/*===========================================================================
                                 LOCAL MACROS
=============================================================================*/

/*===========================================================================
                  LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
=============================================================================*/

/*===========================================================================
                            LOCAL VARIABLES
=============================================================================*/
static char err_msg[MAX_ERR_MSG_BYTES];

/*===========================================================================
                            LOCAL FUNCTION PROTOTYPES
=============================================================================*/
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

/*===========================================================================
                            LOCAL FUNCTIONS
=============================================================================*/

/*--------------------------
  read_file
---------------------------*/
void
read_file(const char *filename, byte_str_t *byte_str, offsets_t *offsets)
{
    FILE     *file = NULL;
    long bytes_to_read = 0;
    size_t read_size = 0;

    /* Open the source file */
    file = fopen(filename, "rb");
    if (NULL == file)
    {
        snprintf(err_msg, MAX_ERR_MSG_BYTES, "Cannot open %s", filename);
        error(err_msg);
    }

    /* Get the file size */
    if (fseek(file, 0, SEEK_END) != 0)
    {
        fclose(file);
        error("Failed to seek in file");
    }
    bytes_to_read = ftell(file);
    if (bytes_to_read < 0)
    {
        fclose(file);
        error("Failed");
    }

    rewind(file);

    /* If some offsets are specified, refine the number of bytes to be read */
    if (NULL != offsets)
    {
        if ((bytes_to_read < offsets->first)
            || (bytes_to_read < offsets->second))
        {
            snprintf(err_msg,
                     MAX_ERR_MSG_BYTES,
                     "Offsets defined outside the file %s",
                     filename);
            error(err_msg);
        }

        if (offsets->first > offsets->second)
        {
            error("Incorrect offsets");
        }

        bytes_to_read = offsets->second - offsets->first;

        if (fseek(file, offsets->first, SEEK_SET) != 0)
        {
            fclose(file);
            error("Failed to seek in file");
        }
    }

    /* Save the file data */
    byte_str->entry_bytes = bytes_to_read;
    byte_str->entry       = malloc(bytes_to_read);
    if (NULL == byte_str->entry)
    {
        snprintf(err_msg, MAX_ERR_MSG_BYTES, "Cannot allocate memory for handling %s", filename);
        error(err_msg);
    }

    memset(byte_str->entry, 0, bytes_to_read);
    read_size = fread(byte_str->entry, 1, bytes_to_read, file);

    if (read_size != bytes_to_read)
    {
        snprintf(err_msg, MAX_ERR_MSG_BYTES, "Unexpected read termination of %s", filename);
        error(err_msg);
    }

    fclose(file);
}
