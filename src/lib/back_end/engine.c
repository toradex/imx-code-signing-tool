// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2024 NXP
 */

#define OPENSSL_SUPPRESS_DEPRECATED

#include "engine.h"
#include "err.h"
#include "openssl_helper.h"
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <stdint.h>

#if CST_WITH_PKCS11
extern int bind_engine(ENGINE *e, const char *id, const void *fns);
#else
static int bind_engine(ENGINE *e, const char *id, const void *fns)
{
    fprintf(stderr, "ERROR: PKCS#11 support not enabled\n");
    return 0;
}
#endif

struct engine_ctx *engine_ctx_new(void)
{
    struct engine_ctx *ctx = NULL;

	ctx = OPENSSL_malloc(sizeof(struct engine_ctx));
	return ctx;
}

int32_t engine_ctx_destroy(struct engine_ctx *ctx)
{
	if (ctx) {
		ENGINE_free(ctx->engine);
		OPENSSL_free(ctx);
	}
	return 1;
}

int32_t engine_ctx_init(struct engine_ctx *ctx)
{
    dynamic_fns fns;
    /* OpenSSL Initialization */
#if OPENSSL_VERSION_NUMBER >= 0x10100000
	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS |
			    OPENSSL_INIT_ADD_ALL_DIGESTS |
			    OPENSSL_INIT_LOAD_CONFIG,
			    NULL);
#else
	OPENSSL_config(NULL);
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();
#endif

	ERR_clear_error();

	ENGINE_load_builtin_engines();

    ctx->engine = ENGINE_new();
    if (ctx->engine == NULL) {
        error("Error creating new engine instance: %s\n",
              ERR_reason_error_string(ERR_get_error()));
        return 0;
    }

    memset(&fns, 0, sizeof(fns));
    /* Bind the engine using the bind_engine function */
    if (!bind_engine(ctx->engine, "pkcs11", &fns)) {
        error("Error binding pkcs11 engine: %s\n",
              ERR_reason_error_string(ERR_get_error()));
        ENGINE_free(ctx->engine);
        return 0;
    }

#ifdef DEBUG
	ENGINE_ctrl_cmd_string(ctx->engine, "VERBOSE", NULL, 0);
#endif

	if (!ENGINE_init(ctx->engine)) {
		ENGINE_free(ctx->engine);
		return 0;
	}

	return 1;
}

int32_t engine_ctx_finish(struct engine_ctx *ctx)
{
	if (ctx)
		ENGINE_finish(ctx->engine);
	return 1;
}

X509 *ENGINE_load_certificate(ENGINE *e, const char *cert_ref)
{
	struct {
		const char *s_slot_cert_id;
		X509 *cert;
	} params = {0};

	params.s_slot_cert_id = cert_ref;
	params.cert = NULL;

	if (!ENGINE_ctrl_cmd(e, "LOAD_CERT_CTRL", 0, &params, NULL, 1)) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	return params.cert;
}

EVP_PKEY *ENGINE_load_key(ENGINE *e, const char *key_ref)
{
	return ENGINE_load_private_key(e, key_ref, 0, 0);
}

X509 *engine_read_certificate(const char *cert_ref)
{
	/* Engine configuration */
	struct engine_ctx *ctx = NULL;
	/* Certificate */
	X509 *cert = NULL;
	/* Operation completed successfully */
	int32_t error = CAL_SUCCESS;

	/* Check for valid arguments */
	if (!cert_ref)
		return NULL;

	/* Allocate new context */
	ctx = engine_ctx_new();

	if (!ctx) {
		error = CAL_CRYPTO_API_ERROR;
		goto out;
	}

	/* Initialize the context */
	if (!engine_ctx_init(ctx)) {
		error = CAL_CRYPTO_API_ERROR;
		goto out;
	}

	cert = ENGINE_load_certificate(ctx->engine, cert_ref);

	if (!cert) {
		error = CAL_CRYPTO_API_ERROR;
		goto out;
	}

#ifdef DEBUG
	X509_print_fp(stdout, cert);
#endif

out:
	if (ctx) {
	/*
	 * Destroy the context: ctx_finish is not called here since
	 * ENGINE_finish cleanups the engine instance. Calling ctx_destroy
	 * next will lead to null pointer dereference.
	 */
		engine_ctx_destroy(ctx);
	}

	if (error)
		ERR_print_errors_fp(stderr);

	return cert;
}
