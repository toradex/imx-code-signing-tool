/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Freescale Semiconductor
 * (c) Freescale Semiconductor, Inc. 2011-2015. All rights reserved.
 * Copyright 2018-2019, 2023 NXP
 */

#ifndef SSL_WRAPPER_H
#define SSL_WRAPPER_H

/*===========================================================================
                            INCLUDE FILES
=============================================================================*/
#ifndef REMOVE_ENCRYPTION
#include <openssl/evp.h>
#endif
#include <adapt_layer.h>

/*===========================================================================
                                MACROS
=============================================================================*/
#define MAX_ERR_STR_BYTES (120) /**< Max. error string bytes */

/*===========================================================================
                         FUNCTION PROTOTYPES
=============================================================================*/
#ifdef __cplusplus
extern "C" {
#endif

void handle_errors(char * str,  int32_t *err_value, char *err_str);

int32_t encryptccm(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
                   int aad_len, unsigned char *key, int key_len, unsigned char *iv,
                   int iv_len, const char * out_file, unsigned char *tag, int tag_len,
                   int32_t *err_value, char *err_str);

int32_t encryptcbc(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    int key_len, unsigned char *iv, const char *out_file, int32_t *err_value, char *err_str);

#ifdef __cplusplus
}
#endif

#endif /* SSL_WRAPPER_H  */
