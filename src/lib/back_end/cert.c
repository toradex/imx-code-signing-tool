// SPDX-License-Identifier: BSD-3-Clause
/*
 * (c) Freescale Semiconductor, Inc. 2011, 2012. All rights reserved.
 * Copyright 2020, 2022-2024 NXP
 */

/*===========================================================================*/
/**
    @file    cert.c

    @brief   Implements certificate content reading API.
    The implementation of this API can be overloaded to read certificate
    from a Hardware Security Module (HSM).
 */

/*===========================================================================
                                INCLUDE FILES
=============================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "openssl_helper.h"

/*===========================================================================
                               GLOBAL FUNCTIONS
=============================================================================*/

/*--------------------------
  ssl_read_certificate
---------------------------*/
X509 *ssl_read_certificate(const char *filename)
{
    BIO  *bio_cert = NULL; /**< OpenSSL BIO ptr */
    X509 *cert = NULL;     /**< X.509 certificate data structure */
    const char *temp =
        NULL; /**> Points to expected location of ".pem" filename extension */

    if (filename == NULL)
    {
        return NULL;
    }

    temp = filename + strlen(filename) - PEM_FILE_EXTENSION_BYTES;

    bio_cert = BIO_new(BIO_s_file());
    if (bio_cert == NULL)
    {
        return NULL;
    }

    if (BIO_read_filename(bio_cert, filename) <= 0)
    {
        BIO_free(bio_cert);
        return NULL;
    }

    cert = X509_new_ex(get_libctx(), NULL);
    if (cert == NULL)
    {
        BIO_free(bio_cert);
        return NULL;
    }

    /* PEM encoded */
    if (!strncasecmp(temp, PEM_FILE_EXTENSION, PEM_FILE_EXTENSION_BYTES))
    {
        if (PEM_read_bio_X509(bio_cert, &cert, NULL, NULL) == NULL)
        {
            X509_free(cert);
            BIO_free(bio_cert);
            return NULL;
        }
    }
    /* DER encoded */
    else
    {
        cert = d2i_X509_bio(bio_cert, &cert);
        if (cert == NULL)
        {
            BIO_free(bio_cert);
            return NULL;
        }
    }

    BIO_free(bio_cert);
    return cert;
}
