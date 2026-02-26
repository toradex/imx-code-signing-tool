/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2024 NXP
 */

#include <adapt_layer.h>
#include "engine.h"

int32_t ssl_gen_sig_data(const char *in_file, const char *cert_file,
                         hash_alg_t hash_alg, sig_fmt_t sig_fmt,
                         uint8_t *sig0_buf, size_t *sig0_buf_bytes,
                         uint8_t *sig1_buf, size_t *sig1_buf_bytes,
                         func_mode_t mode);

X509 *ssl_read_certificate(const char *filename);

int32_t engine_gen_sig_data(const char *in_file, const char *cert_ref,
                            hash_alg_t hash_alg, sig_fmt_t sig_fmt,
                            uint8_t *sig0_buf, size_t *sig0_buf_bytes,
                            uint8_t *sig1_buf, size_t *sig1_buf_bytes,
                            func_mode_t mode);

X509 *engine_read_certificate(const char *cert_ref);
