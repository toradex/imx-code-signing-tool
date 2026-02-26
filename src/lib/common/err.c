// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2018-2019, 2023-2024 NXP
 */

/*===========================================================================*/
/**
    @file   err.c

    @brief  Implements the error logging interface used by different tools
*/

/*===========================================================================
                                INCLUDE FILES
=============================================================================*/
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "err.h"

/*===========================================================================
                               GLOBAL VARIABLES
=============================================================================*/
extern const char *g_tool_name;

/*===========================================================================
                               GLOBAL FUNCTIONS
=============================================================================*/

/*--------------------------
  error
---------------------------*/
void error(const char *str, ...)
{
    va_list args;

    va_start(args, str);

    fprintf(stderr, "\n[ERROR] %s: ", g_tool_name);
    vfprintf(stderr, str, args);
    fprintf(stderr, "\n");

    va_end(args);

    exit(1);
}

/*--------------------------
  warn
---------------------------*/
void warn(const char *str, ...)
{
#ifdef DEBUG
    va_list args;

    va_start(args, str);

    printf("\n[WARNING] %s: ", g_tool_name);
    vprintf(str, args);
    printf("\n");

    va_end(args);
#endif
}
