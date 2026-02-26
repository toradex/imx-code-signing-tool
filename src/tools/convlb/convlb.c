// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2018-2019, 2023-2024 NXP
 */

/*===========================================================================*/
/**
    @file    convlb.c

    @brief   Convert line breaks to Unix format
 */

/*===========================================================================
                                INCLUDE FILES
=============================================================================*/
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

/*===========================================================================
                                GLOBALS
=============================================================================*/

#define NULL ((void *)0)

#define TEMPFILENAME ".convlb.tmp"

char *toolname = NULL;

/*===========================================================================
                                LOCAL FUNCTIONS
=============================================================================*/
static void print_usage(void)
{
    printf("Usage: %s <filepath>\n", toolname);
}

static void err(const char *msg)
{
    printf("[ERROR] %s: %s\n\n", toolname, msg);
    print_usage();
    exit(1);
}

/*===========================================================================
                                GLOBAL FUNCTIONS
=============================================================================*/
int main (int argc, char *argv[])
{
    char *filepath   = NULL;
    FILE *file       = NULL;
    FILE *tempfile   = NULL;

    toolname = argv[0];
    filepath = argv[1];

    if (NULL == filepath) {
        err("invalid input file path");
    }

    file = fopen(filepath, "rb");
    if (NULL == file) {
        err("cannot open input file");
    }

    tempfile = fopen(TEMPFILENAME, "wb+");
    if (NULL == tempfile) {
        err("cannot create a temporary file");
    }

    char byte;
    while (0 != fread(&byte, sizeof(char), 1, file)) {
        if ('\r' != byte) {
            fwrite(&byte, sizeof(char), 1, tempfile);
        }
    }

    /* Re-open the file to destroy the previous content */
    fclose(file);
    file = fopen(filepath, "wb");
    if (NULL == file) {
        err("cannot update input file");
    }
    if (fseek(tempfile, 0, SEEK_SET) != 0)
    {
        fclose(file);
        fclose(tempfile);
        err("cannot seek in tempfile");
    }

    while (0 != fread(&byte, sizeof(char), 1, tempfile)) {
        fwrite(&byte, sizeof(char), 1, file);
    }

    fclose(file);
    fclose(tempfile);
    if (remove(TEMPFILENAME) != 0)
    {
        fprintf(stderr,
                "Warning: Failed to remove temporary file %s. errno: %d\n",
                TEMPFILENAME, errno);
    }

    printf("%s has been executed successfully.\n", toolname);
    return 0;
}
