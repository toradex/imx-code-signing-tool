/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Freescale Semiconductor
 * (c) Freescale Semiconductor, Inc. 2011, 2012. All rights reserved.
 * Copyright 2018-2020, 2023-2025 NXP
 */

#ifndef __OPENSSL_HELPER_H
#define __OPENSSL_HELPER_H
/*===========================================================================*/
/**
    @file    openssl_helper.h

    @brief   Provide helper functions to ease openssl tasks and also defines
             common macros that can used across different tools
 */

/*===========================================================================
                                INCLUDE FILES
=============================================================================*/
#include "adapt_layer.h"
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

/*===========================================================================
                                 CONSTANTS
=============================================================================*/

#define TRUE                      1 /**< Success val returned by functions */
#define FALSE                     0 /**< Failure val returned by functions */

#define X509_UTCTIME_STRING_BYTES 13 /**< Expected length of validity period
                                       *   strings in X.509 certificates using
                                       *   UTCTime format
                                       */
#define X509_GENTIME_STRING_BYTES 15 /**< Expected length of validity period
                                       *   strings in X.509 certificates using
                                       *   Generalized Time format
                                       */
#define PEM_FILE_EXTENSION        ".pem"   /* PEM file extention */
#define PEM_FILE_EXTENSION_BYTES  4        /* Length of pem extention */

/* Message digest string definitions */
#define HASH_ALG_SHA1             "sha1"   /**< String macro for sha1 */
#define HASH_ALG_SHA256           "sha256" /**< String macro for sha256 */
#define HASH_ALG_SHA384           "sha384" /**< String macro for sha384 */
#define HASH_ALG_SHA512           "sha512" /**< String macro for sha512 */
#define HASH_ALG_SHA3_256 "sha3-256"       /**< String macro for sha3-256 */
#define HASH_ALG_SHA3_384 "sha3-384"       /**< String macro for sha3-384 */
#define HASH_ALG_SHA3_512 "sha3-512"       /**< String macro for sha3-512 */
#define HASH_ALG_SHAKE128_256 \
    "shake128-256" /**< String macro for SHAKE 128 output 256 */
#define HASH_ALG_SHAKE256_512 \
    "shake256-512" /**< String macro for SHAKE 256 output 512 */
#define HASH_ALG_SHAKE128 "shake128"       /**< String macro for SHAKE 128 */
#define HASH_ALG_SHAKE256 "shake256"       /**< String macro for SHAKE 256 */
#define HASH_ALG_INVALID          "null"   /**< String macro for invalid hash */

/* Message digest length definitions */
#define HASH_BYTES_SHA1           20   /**< Size of SHA1 output bytes */
#define HASH_BYTES_SHA256         32   /**< Size of SHA256 output bytes */
#define HASH_BYTES_SHA384         48   /**< Size of SHA384 output bytes */
#define HASH_BYTES_SHA512         64   /**< Size of SHA512 output bytes */
#define HASH_BYTES_SHA3_256 32         /**< Size of SHA3-256 output bytes */
#define HASH_BYTES_SHA3_384 48         /**< Size of SHA3-384 output bytes */
#define HASH_BYTES_SHA3_512 64         /**< Size of SHA3-512 output bytes */
#define HASH_BYTES_SHAKE128_256 \
    32 /**< Size of SHAKE128 output 256 output bytes */
#define HASH_BYTES_SHAKE256_512 \
    64 /**< Size of SHAKE256 output 512 output bytes */
#define HASH_BYTES_MAX            HASH_BYTES_SHA512

/* X509 certificate definitions */
#define X509_USR_CERT             0x0 /**< User certificate */
#define X509_CA_CERT              0x1 /**< CA certificate */

/* Dilithium 3 definitions */
#define DILITHIUM3_PK_SIZE 1952  /**< Dilithium3 public key size (bytes) */
#define DILITHIUM3_SK_SIZE 4000  /**< Dilithium3 secret key size (bytes) */
#define DILITHIUM3_SIG_SIZE 3293 /**< Dilithium3 signature size (bytes) */

/* Dilithium 5 definitions */
#define DILITHIUM5_PK_SIZE 2592  /**< Dilithium5 public key size (bytes) */
#define DILITHIUM5_SK_SIZE 4864  /**< Dilithium5 secret key size (bytes) */
#define DILITHIUM5_SIG_SIZE 4595 /**< Dilithium5 signature size (bytes) */

/* ML-DSA65 definitions */
#define MLDSA65_PK_SIZE 1952  /**< ML-DSA65 public key size (bytes) */
#define MLDSA65_SK_SIZE 4032  /**< ML-DSA65 secret key size (bytes) */
#define MLDSA65_SIG_SIZE 3309 /**< ML-DSA65 signature size (bytes) */

/* ML-DSA87 definitions */
#define MLDSA87_PK_SIZE 2592  /**< ML-DSA87 public key size (bytes) */
#define MLDSA87_SK_SIZE 4896  /**< ML-DSA87 secret key size (bytes) */
#define MLDSA87_SIG_SIZE 4627 /**< ML-DSA87 signature size (bytes) */

/*===========================================================================
                                 MACROS
=============================================================================*/

/** Extracts a byte from a given 32 bit word value
 *
 * @param [in] val value to extract byte from
 *
 * @param [in] bit_shift Number of bits to shift @a val left before
 *                       extracting the least significant byte
 *
 * @returns the least significant byte after shifting @a val to the left
 *          by @a bit_shift bits
 */
#define EXTRACT_BYTE(val, bit_shift) \
    (((val) >> (bit_shift)) & 0xFF)

/** Checks if the algorithm is a post-quantum cryptography (PQC) algorithm.
 *
 * A supported PQC algorithm is either dilithium3, mldsa65,
 * mldsa87, or, dilithium5.
 *
 * @param [in] algo The algorithm string.
 *
 * @returns true if the algorithm is PQC, false otherwise.
 */
#define IS_PQC(algo)                                                       \
    (strcmp(algo, "dilithium3") == 0 || strcmp(algo, "dilithium5") == 0 || \
     strcmp(algo, "mldsa65") == 0 || strcmp(algo, "mldsa87") == 0)

/** Checks if the algorithm is a supported hybrid algorithm.
 *
 * @param [in] algo The algorithm string.
 *
 * @returns true if the algorithm is hybrid, false otherwise.
 */
#define IS_HYBRID(algo) \
    (strstr(algo, "p384_") == algo || strstr(algo, "p521_") == algo)

/** Checks if the algorithm is a supported composite algorithm.
 *
 * @param [in] algo The algorithm string.
 *
 * @returns true if the algorithm is composite, false otherwise.
 */
#define IS_COMPOSITE(algo) \
    (strstr(algo, "_p384") != NULL || strstr(algo, "_p521"))

/** Extracts the classical algorithm name from a given hybrid or composite
 * algorithm name.
 *
 * @param [in] algo The algorithm string.
 * @param [out] buffer A buffer to store the extracted classical algorithm name.
 */
#define EXTRACT_CLASSICAL_ALGO(algo, buffer)   \
    {                                          \
        if (IS_HYBRID(algo))                   \
        {                                      \
            sscanf(algo, "%[^_]_", buffer);    \
        }                                      \
        else if (IS_COMPOSITE(algo))           \
        {                                      \
            sscanf(algo, "%*[^_]_%s", buffer); \
        }                                      \
        else                                   \
        {                                      \
            strcpy(buffer, "");                \
        }                                      \
    }

/** Extracts the PQC algorithm name from a given hybrid or composite algorithm
 * name.
 *
 * @param [in] algo The algorithm string.
 * @param [in] buffer A buffer to store the extracted PQC algorithm name.
 */
#define EXTRACT_PQC_ALGO(algo, buffer)         \
    {                                          \
        if (IS_HYBRID(algo))                   \
        {                                      \
            sscanf(algo, "%*[^_]_%s", buffer); \
        }                                      \
        else if (IS_COMPOSITE(algo))           \
        {                                      \
            sscanf(algo, "%[^_]_", buffer);    \
        }                                      \
        else                                   \
        {                                      \
            strcpy(buffer, "");                \
        }                                      \
    }

/*============================================================================
                                      ENUMS
=============================================================================*/

typedef enum cst_status
{
    CST_FAILURE = FALSE,
    CST_SUCCESS = TRUE
} cst_status_t;

/*============================================================================
                           STRUCTURES AND OTHER TYPEDEFS
=============================================================================*/

/*============================================================================
                           GLOBAL VARIABLE DECLARATIONS
=============================================================================*/

/*===========================================================================
                               OPENSSL COMPAT SUPPORT
=============================================================================*/

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)

#define OPENSSL_malloc_init CRYPTO_malloc_init
#define X509_get0_notBefore X509_get_notBefore
#define X509_get0_notAfter  X509_get_notAfter

void
ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);

int
ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);

void
EVP_MD_CTX_free(EVP_MD_CTX *ctx);

EVP_MD_CTX *
EVP_MD_CTX_new(void);

EC_KEY *
EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey);

RSA *
EVP_PKEY_get0_RSA(EVP_PKEY *pkey);

void
RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);

#endif

#ifdef EVP_PKEY_get_size
    #define PKEY_GET_SIZE(pkey) EVP_PKEY_get_size(pkey)
#else
    #define PKEY_GET_SIZE(pkey) EVP_PKEY_size(pkey)
#endif

/*============================================================================
                                FUNCTION PROTOTYPES
=============================================================================*/

/** openssl_initialize
 *
 * Initializes the openssl library.  This function must be called once
 * by the program using any of the openssl helper functions
 *
 */
extern void openssl_initialize(void);

/** get_libctx
 *
 * This function provides access to the global OpenSSL library context
 * (g_libctx).
 *
 * @return OSSL_LIB_CTX* - A pointer to the global OpenSSL library context.
 *                         If the global context is not initialized, this will
 * return NULL.
 */
extern OSSL_LIB_CTX *get_libctx(void);

/** Computes hash digest
 *
 * Calls openssl API to generate hash for the given data in buf.
 *
 * @param[in] buf, binary data for hashing
 *
 * @param[in] msg_bytes, size in bytes for binary data
 *
 * @param[in] hash_alg, character string containing hash algorithm,
 *                      "sha1" or "sha256"
 *
 * @param[out] hash_bytes, size of digest result in bytes
 *
 * @pre  #openssl_initialize has been called previously
 *
 * @pre  @a buf and @a hash_alg are not NULL.
 *
 * @post It is the responsibilty of the caller to free the memory allocated by
 *       this function holding the computed hash result.
 *
 * @returns The location of the digest result if successful, NULL otherwise
 */
extern uint8_t *
generate_hash(const uint8_t *buf, size_t msg_bytes, const char *hash_alg,
              size_t *hash_bytes);

/** get_bn
 *
 * Extracts data from an openssl BIGNUM type to a byte array.  Used
 * for extracting certificate data such as an RSA public key modulus.
 *
 * @param[in] a      BIG_NUM structure
 *
 * @param[out] bytes size of resulting byte array
 *
 * @pre @a a and @a bytes are not NULL
 *
 * @post It is the responsibilty of the caller to free the memory allocated by
 *       this function holding the big number result.
 *
 * @returns location of resulting byte array or NULL if failed to alloc mem.
 */
extern uint8_t*
get_bn(const BIGNUM *a, size_t *bytes);

/** get_der_encoded_certificate_data
 *
 * Read X.509 certificate data from given certificate reference and encode it
 * to DER format and returns result in @derder.
 *
 * @param[in] filename    filename, function will work with both PEM and DER
 *                        input certificate files.
 *
 * @param[out] der        address to write der data
 *
 * @post if successful the contents of the certificate are written at address
 * @a der.
 *
 * @pre  #openssl_initialize has been called previously
 *
 * @post caller is responsible for releasing memory location returned in @a der
 *
 * @returns if successful function returns number of bytes written at address
 * @a der, 0 otherwise.
 */
extern int32_t get_der_encoded_certificate_data(const char* reference,
                                         uint8_t ** der);
/** sign_data
 *
 * Signs a data buffer with a given private key
 *
 * @param[in] skey       signer private key
 *
 * @param[in] bptr       location of data buffer to digitally sign
 *
 * @param[in] hash_alg   hash digest algorithm
 *
 * @param[out] sig_bytes size of resulting signature buffer
 *
 * @pre  #openssl_initialize has been called previously
 *
 * @post It is the responsibilty of the caller to free the memory allocated by
 *       this function holding the signature  result.
 *
 * @returns if successful returns location of resulting byte array otherwise
 * NULL.
 */
extern uint8_t*
sign_data(const EVP_PKEY *skey, const BUF_MEM *bptr, hash_alg_t hash_alg,
          size_t *sig_bytes);


/** read_private_key
 *
 * Uses openssl API to read private key from given certificate file
 *
 * @param[in] filename    filename of key file
 *
 * @param[in] password_cb callback fn to provide password for keyfile
 *            see openssl's pem.h for callback'e prototype
 *
 * @param[in] password    password for keyfile
 *
 * @post if successful the contents of the private key are extracted to
 * EVP_PKEY object.
 *
 * @pre  #openssl_initialize has been called previously
 *
 * @post caller is responsible for releasing the private key memory.
 *
 * @returns if successful function returns location of EVP_PKEY object
 *   otherwise NULL.
 */
extern EVP_PKEY*
read_private_key(const char *filename, pem_password_cb *password_cb,
                 const char *password);

/** seed_prng
 *
 * Calls openssl API to seed prng to given bytes randomness
 *
 * @param[in] bytes   bytes to randomize the seed
 *
 * @pre  None
 *
 * @post None
 */
uint32_t seed_prng(uint32_t bytes);

/** gen_random_bytes
 *
 * Generates random bytes using openssl RAND_bytes
 *
 * @param[out] buf    buf to return the random bytes
 *
 * @param[in] bytes   size of the buf in bytes and number of random bytes
 *                    to generate
 *
 * @pre  None
 *
 * @post None
 */
int32_t gen_random_bytes(uint8_t *buf, size_t bytes);

/** get_param_octet_string
 *
 * Retrieves the octet string parameter from the given EVP_PKEY object.
 *
 * @param[in]  key         Pointer to the EVP_PKEY object
 * @param[in]  param_name  Name of the parameter to retrieve
 * @param[out] buf         Pointer to the buffer that will hold the octet string
 * @param[out] buf_len     Pointer to the length of the buffer
 *
 * @return int             1 on success, 0 on failure
 *
 * @pre  key, param_name, buf, buf_len should not be NULL
 *
 * @post On success, buf contains the octet string and buf_len contains the
 *       length of the buffer
 */
extern int get_param_octet_string(const EVP_PKEY *key, const char *param_name,
                                  uint8_t **buf, size_t *buf_len);

/** Checks if the given certificate has the CA flag set.
 *
 * @param[in] cert_path The path to the certificate file.
 *
 * @return 1 if the CA flag is set, 0 if not, -1 on error.
 */
extern int is_ca_certificate(const char *cert_path);

/** Checks if the given certificate is pqc.
 *
 * @param[in] cert_path The path to the certificate file.
 *
 * @return 1 if the certificate is pqc, 0 if not, -1 on error.
 */
extern int is_pqc_certificate(const char *cert_path);

/** Checks if the given certificate is hybrid.
 *
 * @param[in] cert_path The path to the certificate file.
 *
 * @return 1 if the certificate is hybrid, 0 if not, -1 on error.
 */
extern int is_hybrid_certificate(const char *cert_path);

/** Create an EVP_PKEY object using raw public and/or private key bytes.
 *
 * @param[in] libctx The OpenSSL library context.
 * @param[in] pubkey_bytes The raw bytes of the public key.
 * @param[in] pubkey_len The length of the public key bytes.
 * @param[in] privkey_bytes The raw bytes of the private key (optional).
 * @param[in] privkey_len The length of the private key bytes.
 * @param[in] alg_name The name of the algorithm (e.g., "rsa", "p256").
 *
 * @return An EVP_PKEY object on success, or NULL on failure.
 */
extern EVP_PKEY *create_evp_key_from_bytes(OSSL_LIB_CTX *libctx,
                                           const unsigned char *pubkey_bytes,
                                           size_t pubkey_len,
                                           const unsigned char *privkey_bytes,
                                           size_t privkey_len,
                                           const char *alg_name);

/** Partitions a hybrid EVP key into classical and post-quantum EVP keys.
 *
 * @param libctx[in] A pointer to the OpenSSL library context.
 * @param hybrid_key[in] A pointer to the hybrid EVP key to be partitioned.
 * @param classical_key[out] A double pointer to the EVP_PKEY structure where
 *        the classical key will be stored.
 * @param pqc_key[out] A double pointer to the EVP_PKEY structure where the
 *        post-quantum key will be stored.
 *
 * @return int 1 on success, 0 on failure.
 */
extern int partition_hybrid_key(OSSL_LIB_CTX *libctx,
                                const EVP_PKEY *hybrid_key,
                                EVP_PKEY **classical_key, EVP_PKEY **pqc_key);

/** Calculate the signature sizes for a given EVP_PKEY. If the key is a
 * hybrid key, it calculates sizes for both classical and quantum-resistant
 * parts.
 *
 * @param[in] pkey The EVP_PKEY structure containing the key.
 * @param[out] sig0_size Pointer to a size_t where the size of the first
 *                       signature part will be stored.
 * @param[out] sig1_size Pointer to a size_t where the size of the second
 *                       signature part will be stored. This is used
 *                       when the pkey is a hybrid key.
 *
 * @return Returns 1 on success, 0 on failure.
 */
extern int get_signature_size(const EVP_PKEY *pkey, size_t *sig0_size,
                              size_t *sig1_size);

/** Get the length of the serial number from an X509 certificate.
 * This helper function is created to handle the case when a leading zero is
 * being added to the serial number when it is negative. This happens because
 * the serial number is treated as a signed integer, and if the MSB is set,
 * the number is interpreted as negative. The function checks if the MSB is set.
 * If it is, we should adjust the serial number length returned by the
 * ASN1_INTEGER representation by simply adding 1 to the length.
 *
 * @param cert Pointer to the X509 certificate. Must not be NULL.
 *
 * @return int The length of the serial number in DER format, or -1 if error.
 */
extern int get_certificate_serial_number_length(X509 *cert);

/** Diplays program license information to stdout
 *
 * @pre  None
 *
 * @post None
 */
extern void
print_license(void);

/** Diplays program version information to stdout
 *
 * @pre  None
 *
 * @post None
 */
extern void
print_version(void);

#endif /* __OPENSSL_HELPER_H */
