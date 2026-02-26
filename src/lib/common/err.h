/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2018-2019, 2023-2024 NXP
 */

#ifndef ERR_H
#define ERR_H
/*===========================================================================*/
/**
    @file    err.h

    @brief   Error logging interface
 */

/*===========================================================================
                         FUNCTION PROTOTYPES
=============================================================================*/
#ifdef __cplusplus
extern "C" {
#endif

    /** Display error message
 *
 * Displays error message to STDERR and exits the program
 *
 * @param[in] str Error string to display to the user
 *
 * @pre  @a str is not NULL
 *
 * @post Program exits with exit code 1.
 */
    void error(const char *str, ...);

    /** Display warning message
 *
 * Displays warning message to STDOUT.
 *
 * @param[in] str Warning string to display to the user
 *
 * @pre  @a str is not NULL
 *
 * @post Program exits with exit code 1.
 */
    void warn(const char *str, ...);

#ifdef __cplusplus
}
#endif

#endif /* ERR_H */
