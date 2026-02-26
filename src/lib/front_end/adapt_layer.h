/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Freescale Semiconductor
 * (c) Freescale Semiconductor, Inc. 2011-2015 All rights reserved.
 * Copyright 2018-2020, 2022-2024 NXP
 */

#ifndef ADAPT_LAYER_H
#define ADAPT_LAYER_H
/*===========================================================================*/
/**
    @file    adapt_layer.h

    @brief   CST adaptation layer interface
 */

/*===========================================================================
                            INCLUDE FILES
=============================================================================*/
#include <stdint.h>
#include <openssl/x509.h>
/*===========================================================================
                              CONSTANTS
=============================================================================*/

/*===========================================================================
                                MACROS
=============================================================================*/
#define UNUSED(expr)                (void)(expr)

#define CAL_SUCCESS                 ( 0) /* Operation completed successfully */
#define CAL_FILE_NOT_FOUND          (-1) /* Error when file does not exist   */
#define CAL_INVALID_SIG_DATA_SIZE   (-2) /* Error when sig data size invalid */
#define CAL_FAILED_FILE_CREATE      (-3) /* Error unable to create file      */
#define CAL_MAC_LEN_INCORRECT       (-4) /* Error MAC len is incorrect       */
#define CAL_INVALID_ARGUMENT        (-5) /* Error argument passed is invalid */
#define CAL_CRYPTO_API_ERROR        (-6) /* Error with openssl API           */
#define CAL_INSUFFICIENT_BUFFER_LEN (-7) /* Buffer length is not sufficient  */
#define CAL_DATA_COMPARE_FAILED     (-8) /* Data comparison operation failed */
#define CAL_RAND_SEED_ERROR         (-9) /* Failure to run rand_seed         */
#define CAL_RAND_API_ERROR         (-10) /* Failure in RAND_bytes            */
#define CAL_NO_CRYPTO_API_ERROR    (-11) /* Error when Encryption is disabled*/
#define CAL_INVALID_SIGNATURE      (-12) /* Error when verifying isignature  */
#define CAL_INSUFFICIENT_MEMORY    (-13) /* Buffer length is not sufficient  */
#define CAL_LAST_ERROR            (-100) /* Max error codes for adapt layer  */

#define FILE_BUF_SIZE             (1024) /* 1K buf for file read/file write  */

#define MAX_AES_KEY_LENGTH          (32) /* Max bytes in AES key             */
#define AES_BLOCK_BYTES             (16)           /**< Max. AES block bytes */
#define FLAG_BYTES                   (1)                  /**< Bytes in Flag */
#define BYTE_SIZE_BITS               (8)       /**< Number of bits in a byte */

#define SIG_REQ_FILENAME   "sig_req.txt" /**< Signing request filename       */

/*===========================================================================
                                ENUMS
=============================================================================*/
typedef enum func_mode_e
{
    MODE_UNDEF = 0,     /**< Undefined functional mode */
    MODE_NOMINAL,       /**< Execution in normal mode  */
    MODE_HSM,           /**< Execution in HSM mode     */
} func_mode_t;

typedef enum _SIG_FMT
{
    SIG_FMT_UNDEF = 0, /**< Undefined signature format */
    SIG_FMT_PKCS1,     /**< RAW PKCS#1 signature format */
    SIG_FMT_CMS,       /**< CMS (PKCS#7) signature format */
    SIG_FMT_ECDSA,     /**< ECDSA signature format. R|S concatanated */
    SIG_FMT_AEAD,      /**< Proprietary AEAD MAC format */
    SIG_FMT_RSA_PSS,   /**< RSA-PSS signature format */
    SIG_FMT_DILITHIUM, /**< DILITHIUM signature format */
    SIG_FMT_MLDSA,     /**< ML-DSA signature format */
    SIG_FMT_HYBRID,    /**< Hybrid signature format */
} sig_fmt_t;

/** Hash Digetst Algorithm */
typedef enum hash_alg
{
    SHA_1 = 0,     /**< SHA-1 Digest Algorithm */
    SHA_256,       /**< SHA-256 Digest Algorithm */
    SHA_384,       /**< SHA-384 Digest Algorithm */
    SHA_512,       /**< SHA-512 Digest Algorithm */
    SHA3_256,      /**< SHA3-256 Digest Algorithm */
    SHA3_384,      /**< SHA3-384 Digest Algorithm */
    SHA3_512,      /**< SHA3-512 Digest Algorithm */
    SHAKE128_256,  /**< SHAKE128 Output 256 Digest Algorithm */
    SHAKE256_512,  /**< SHAKE256 Output 512 Digest Algorithm */
    INVALID_DIGEST /**< Invalid Digest Algorithm */
} hash_alg_t;

/** AES key lengths supported */
typedef enum aes_key_bits
{
    AES_KEY_LEN_128 = 128, /**< 128 bits */
    AES_KEY_LEN_192 = 192, /**< 192 bits */
    AES_KEY_LEN_256 = 256, /**< 256 bits */
} aes_key_bits_t;

/** Encryption algorithms supported */
typedef enum aead_alg
{
    AES_CCM = 0, /**< Default encryption algorithm supported */
    AES_CBC
} aead_alg_t;

/** RSA signature types supported */
typedef enum
{
    RSA_SIG_PKCS1, /**< PKCS#1 v1.5 signature  */
    RSA_SIG_PSS    /**< RSA-PSS signature  */
} rsa_sig_t;


/*===========================================================================
                    STRUCTURES AND OTHER TYPEDEFS
=============================================================================*/

typedef struct _AEAD {
    uint8_t *uch;
} AEAD_t;

/*===========================================================================
                     GLOBAL VARIABLE DECLARATIONS
=============================================================================*/

/*===========================================================================
                         FUNCTION PROTOTYPES
=============================================================================*/
#ifdef __cplusplus
extern "C" {
#endif

/** Converts given digest value to equivalent OpenSSL string
 *
 * @param[in] hash_alg one of #hash_alg_t
 *
 * @returns Openssl string corresponding the given hash algorithm in
 *          @a hash_alg, if @a hash_alg is not valid #HASH_ALG_INVALID
 *          is returned.
 */
char *
get_digest_name(hash_alg_t hash_alg);

/** Generate Signature Data Function Pointer
 *
 * Hook for assiging the method that generates a signature from a backend
 * for the given data file, signer certificate,  hash algorithm and signature
 * format. The signature data is returned in a buffer provided by caller.
 *
 * @param[in] in_file path to file with binary data to sign
 *
 * @param[in] cert_file path to signer certificate file
 *
 * @param[in] hash_alg hash algorithm in #hash_alg_t
 *
 * @param[in] sig_fmt signature format in #sig_fmt_t
 *
 * @param[out] sig0_buf buffer to return signature data
 *
 * @param[in,out] sig0_buf_bytes input size of sig0_buf allocated by caller
 *                              output size of signature data returned by API
 *
 * @param[out] sig1_buf buffer to return PQC signature data when hybrid signing
 *             key is used.
 *
 * @param[in,out] sig1_buf_bytes input size of sig1_buf allocated by caller
 *                              output size of signature data returned by API
 * @post Errors are printed to STDERR
 *
 * @retval #CAL_SUCCESS API completed its task successfully
 *
 * @retval #CAL_FILE_NOT_FOUND invalid path in one of the arguments
 *
 * @retval #CAL_INVALID_SIG_DATA_SIZE size insufficient to generate sig data
 *
 * @retval #CAL_INVALID_ARGUMENT one of the input arguments is invalid
 */
typedef int32_t (*gen_sig_data_fptr)(const char *in_file, const char *cert_file,
                                     hash_alg_t hash_alg, sig_fmt_t sig_fmt,
                                     uint8_t *sig0_buf, size_t *sig0_buf_bytes,
                                     uint8_t *sig1_buf, size_t *sig1_buf_bytes,
                                     func_mode_t mode);

extern gen_sig_data_fptr gen_sig_data;

  /** Read Certificate Function Pointer
   *
   * Hook for the read_certificate() method supported from the backend. Reads
   * X.509 certificate data from the provided certificate file.
 *
 * @param[in] reference    reference to a certificate file
 *
 * @post if successful the contents of the certificate are extracted to X509
 * object.
 *
 * @pre  #openssl_initialize has been called previously
 *
 * @post caller is responsible for releasing X.509 certificate memory.
 *
 * @returns if successful function returns location of X509 object
 *   otherwise NULL.
 */
typedef X509*
(*read_certificate_fptr)(const char* reference);

extern read_certificate_fptr read_certificate;

/** Generate authenticated encrypted data
 *
 * API generates authenticated encrypted data for given plain-text data file
 *
 * @param[in] in_file plaintext, extracted and concatenated as for signing
 *
 * @param[out] out_file ciphertext (file name is input)
 *
 * @param[in] aead_alg only AES_CCM supported for now.
 *
 * @param[out] aad additional authenticated data
 *
 * @param[in] aad_bytes size of aad (additional authenticated data)
 *
 * @param[out] nonce nonce bytes to return
 *
 * @param[in] nonce_bytes size of nonce
 *
 * @param[out] mac output MAC
 *
 * @param[in] mac_bytes size of MAC
 *
 * @param[in] key_bytes size of symmetric key
 *
 * @param[in] cert_file certificate for DEK (data enctyption key) encryption
 *
 * @param[out] key_file encrypted symmetric key (file name is input)
 *
 * @retval #CAL_SUCCESS API completed its task successfully
 *
 * @retval #CAL_FILE_NOT_FOUND invalid path in one of the arguments
 *
 * @retval #CAL_FAILED_FILE_CREATE the output file cannot be created
 *
 * @retval #CAL_MAC_LEN_INCORRECT the mac_bytes is not correct
 */
int32_t gen_auth_encrypted_data(const char* in_file,
                     const char* out_file,
                     aead_alg_t aead_alg,
                     uint8_t *aad,
                     size_t aad_bytes,
                     uint8_t *nonce,
                     size_t nonce_bytes,
                     uint8_t *mac,
                     size_t mac_bytes,
                     size_t key_bytes,
                     const char* cert_file,
                     const char* key_file,
                     int reuse_dek);

/** Computes hash digest from a given input file
 *
 * This function differs from the generate_hash() function in
 * openssl_helper.c in that this function will hash an arbitrary amount of
 * data contained in @in_file. The generate_hash expects the data in a
 * contigous memory array with the data length already known.
 *
 * @param[in] in_file Character string holding the input data filename.
 *
 * @param[in] hash_alg Hash digest algorithm from #hash_alg_t
 *
 * @param[in,out] buf on input, used to read input data when computing
 *                hash value, on output holds the resulting hash value.
 *
 * @param[in,out] pbuf_bytes on input, holds the size of @a buf ib bytes,
 *                on output pbuf_bytes is updated to hold the size of the
 *                resulting hash in bytes.
 *
 * @pre @a in_file, @a buf, and @a pbuf_bytes must not be NULL
 *
 * @post On success @a buf is updated to hold the hash digest result and
 *       @a pbuf_bytes is updated to hold the length of the hash in bytes
 *
 * @retval #CAL_SUCCESS API completed its task successfully
 *
 * @retval #CAL_INVALID_ARGUMENTif @a hash_alg contains an unsupported
 *         algorithm
 *
 * @retval #CAL_CRYPTO_API_ERROR otherwise
 */
int32_t
calculate_hash(const char *in_file,
               hash_alg_t hash_alg,
               uint8_t *buf,
               int32_t *pbuf_bytes);

/** Verify Signature Data
 *
 * Verifies a signature for the given data file, signer certificate,
 * hash algorithm and signature format. The signature data is given
 * in a buffer provided by caller.
 *
 * @param[in] in_file path to file with binary data to sign
 *
 * @param[in] cert_file path to signer certificate file
 *
 * @param[in] hash_alg hash algorithm in #hash_alg_t
 *
 * @param[in] sig_fmt signature format in #sig_fmt_t
 *
 * @param[in] sig_buf buffer to give signature data
 *
 * @param[in] sig_buf_bytes input size of sig_buf allocated by caller
 *
 * @post Errors are printed to STDERR
 *
 * @retval #CAL_SUCCESS API completed its task successfully
 *
 * @retval #CAL_FILE_NOT_FOUND invalid path in one of the arguments
 *
 * @retval #CAL_INVALID_SIGNATURE invalid signature
 *
 * @retval #CAL_INVALID_ARGUMENT one of the input arguments is invalid
 */
int32_t
ver_sig_data(const char *in_file,
             const char *cert_file,
             hash_alg_t hash_alg,
             sig_fmt_t  sig_fmt,
             uint8_t    *sig_buf,
             size_t     sig_buf_bytes);

#ifdef __cplusplus
}
#endif

#endif /* ADAPT_LAYER_H */
