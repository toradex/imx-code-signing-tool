/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2023 NXP
 */

#ifndef ENGINE_H
#define ENGINE_H

#include <adapt_layer.h>
#include "openssl_helper.h"
#include <openssl/evp.h>
#include <openssl/x509.h>

struct engine_ctx {
	/* Engine configuration */
	ENGINE *engine;
};

/**  engine_ctx_new
 *
 * Allocates a new functional reference.
 *
 * @returns functional reference if successful NULL otherwise.
 */
struct engine_ctx *engine_ctx_new(void);

/** engine_ctx_destroy
 *
 * Destroys context and release the functional reference from ctx_new
 *
 * @param[ctx] Pointer to engine context structure
 *
 * @post if successful memory space allocated for functional reference is freed.
 *
 * @pre  #ctx_new has been called previously.
 *
 * @returns 1 if successful 0 otherwise.
 */
int32_t engine_ctx_destroy(struct engine_ctx *ctx);

/** engine_ctx_init
 *
 * Initialize context
 *
 * @param[ctx] Pointer to engine context structure
 *
 * @post if successful memory space allocated is freed.
 *
 * @pre  #ctx_new has been called previously.
 *
 * @returns 1 if successful 0 otherwise.
 */
int32_t engine_ctx_init(struct engine_ctx *ctx);

/** engine_ctx_finish
 *
 * Finalize engine operations initialized with ctx_init
 *
 * @param[ctx] Functional reference
 *
 * @pre  #ctx_init has been called previously.
 *
 * @returns 1 if successful 0 otherwise.
 */
int32_t engine_ctx_finish(struct engine_ctx *ctx);

/**  ENGINE_load_certificate
 *
 * Read certificate with a given reference from engine.
 *
 * @param[in] e engine instance
 *
 * @param[in] cert_ref certificate reference
 *
 * @pre @a e, @a cert_ref must not be NULL.
 *
 * @returns pointer to X.509 certificate if successful, NULL otherwise.
 */
X509 *ENGINE_load_certificate(ENGINE *e, const char *cert_ref);

/**  ENGINE_load_key
 *
 * Read key with a given reference from engine.
 *
 * @param[in] e engine instance
 *
 * @param[in] key_ref key reference
 *
 * @pre @a e, @a key_ref must not be NULL.
 *
 * @returns pointer to EVP_PKEY key if successful, NULL otherwise.
 */
EVP_PKEY *ENGINE_load_key(ENGINE *e, const char *key_ref);


#endif /* ENGINE_H */
