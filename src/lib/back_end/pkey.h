/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Freescale Semiconductor
 * (c) Freescale Semiconductor, Inc. 2011,2012. All rights reserved.
 * Copyright 2019, 2023 NXP
 */

#ifndef PKEY_H
#define PKEY_H
/*===========================================================================*/
/**
    @file    pkey.h

    @brief   CST private key and password provider API
 */

/*===========================================================================
                            INCLUDE FILES
=============================================================================*/

/*===========================================================================
                              CONSTANTS
=============================================================================*/

/*===========================================================================
                                MACROS
=============================================================================*/

/*===========================================================================
                                ENUMS
=============================================================================*/

/*===========================================================================
                    STRUCTURES AND OTHER TYPEDEFS
=============================================================================*/

/*===========================================================================
                     GLOBAL VARIABLE DECLARATIONS
=============================================================================*/

/*===========================================================================
                         FUNCTION PROTOTYPES
=============================================================================*/
#ifdef __cplusplus
extern "C" {
#endif

/** get_passcode_to_key_file
 *
 * @par Purpose
 *
 * Callback to gte password for the encrypted key file. Default behavior
 * can be overridden by customers by linking with their own implementation
 * of libpw.a and this function
 *
 * @par Operation
 *
 * @param[out] buf,  return buffer for the password
 *
 * @param[in] size,  size of the buf in bytes
 *
 * @param[in] rwflag,  not used
 *
 * @param[in] userdata,  filename for a public key used in the CSF
 *
 * @retval returns size of password string
 */
int get_passcode_to_key_file(char *buf, int size, int rwflag, void *userdata);

/** get_key_file
 *
 * @par Purpose
 *
 * This API extracts private key filename using cert filename. This API is
 * moved to libpw to allow customers to change its implementation to better
 * suit their needs.
 *
 * @par Operation
 *
 * @param[in] cert_file,  filename for certificate
 *
 * @param[out] key_file,  filename for private key for the input certificate
 *
 * @retval SUCCESS
 */
int32_t get_key_file(const char* cert_file, char* key_file);

#ifdef __cplusplus
}
#endif

#endif /* PKEY_H */
