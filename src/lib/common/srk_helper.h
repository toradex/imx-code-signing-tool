/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2018-2019, 2023-2025 NXP
 */

#ifndef SRK_HELPER_H
#define SRK_HELPER_H
/*===========================================================================*/
/**
    @file    srk_helper.h

    @brief   Provide helper functions to ease SRK tasks and also defines
             common struct that can used across different tools
 */

/*===========================================================================
                            INCLUDE FILES
=============================================================================*/
#include "arch_types.h"
#include "openssl_helper.h"

/*===========================================================================
                    STRUCTURES AND OTHER TYPEDEFS
=============================================================================*/

/* SRK table */
typedef struct srk_table
{
    uint8_t *table;     /**< Contains table data */
    size_t table_bytes; /**< Size of table in bytes */
    uint8_t *hash;      /**< Contains hash of SRK table */
    size_t hash_bytes;  /**< Size SRK table hash in bytes */
} srk_table_t;

/* SRK table entry */
typedef struct srk_entry
{
    uint8_t index;       /**< Index of entry in table */
    uint8_t *entry;      /**< Contains key data */
    size_t entry_bytes;  /**< Size of entry in bytes */
} srk_entry_t;

/*===========================================================================
                         FUNCTION PROTOTYPES
=============================================================================*/

/** Generate SRK table key entry
 *
 * This function builds a PKCS#1 public key data structure as defined by
 * the HAB4 SIS from the given X.509 key data.
 *
 * @param[in] target Define which component is targeted, HAB4 or AHAB
 *
 * @param[in] pkey Pointer OpenSSL public key data structure
 *
 * @param[in] srk Pointer to a SRK table entry data structure
 *
 * @param[in] ca_flag If set this indicates key is from a CA certificate
 *
 * @param[in] sd_alg_str Define which signature hash algorithm will be used
 *                       in conjunction with the given key
 *
 * @param[in] hash_key_data Boolean flag to indicate if the key data should
 * be hashed.
 *
 * @pre @a pkey and @a srk must not be NULL
 *
 * @pre The data lacated at @a srk->entry follows the PKCS#1 key data
 *      format described in the HAB4 SIS.
 *
 * @post if successful, @a srk->entry contains the public key data and
 *       and srk->entry_bytes is updated.
 *
 * @returns #CST_SUCCESS if successful, #CST_FAILURE otherwise
 */
void srk_entry_pkcs1(tgt_t target, EVP_PKEY *pkey, srk_entry_t *srk,
                     bool ca_flag, const char *sd_alg_str, bool hash_key_data);

/** Generate SRK table key entry
 *
 * This function builds an EC public key data structure as defined by
 * the AHAB SIS from the given X.509 key data.
 *
 * @param[in] target Define which component is targeted, HAB4 or AHAB
 *
 * @param[in] pkey Pointer OpenSSL public key data structure
 *
 * @param[in] srk Pointer to a SRK table entry data structure
 *
 * @param[in] ca_flag If set this indicates key is from a CA certificate
 *
 * @param[in] sd_alg_str Define which signature hash algorithm will be used
 *                       in conjunction with the given key
 *
 * @param[in] hash_key_data Boolean flag to indicate if the key data should
 * be hashed.
 *
 * @pre @a pkey and @a srk must not be NULL
 *
 * @pre The data lacated at @a srk->entry follows the EC key data
 *      format described in the AHAB SIS.
 *
 * @post if successful, @a srk->entry contains the public key data and
 *       and srk->entry_bytes is updated.
 *
 * @returns #CST_SUCCESS if successful, #CST_FAILURE otherwise
 */
void srk_entry_ec(tgt_t target, EVP_PKEY *pkey, srk_entry_t *srk, bool ca_flag,
                  const char *sd_alg_str, bool hash_key_data);

/** Generate SRK table key entry
 *
 * This function builds a Dilithium algorithm public key data structure from the
 * given X.509 key data.
 *
 * @param[in] target Define which component is targeted.
 *
 * @param[in] pkey Pointer OpenSSL public key data structure
 *
 * @param[in] srk Pointer to a SRK table entry data structure
 *
 * @param[in] ca_flag If set this indicates key is from a CA certificate
 *
 * @param[in] sd_alg_str Define which signature hash algorithm will be used
 *                       in conjunction with the given key
 *
 * @param[in] hash_key_data Boolean flag to indicate if the key data should
 * be hashed.
 *
 * @pre @a pkey and @a srk must not be NULL
 *
 * @pre The data lacated at @a srk->entry follows the Dilithium algorithm key
 * data format described in the AHAB SIS.
 *
 * @post if successful, @a srk->entry contains the public key data and
 *       and srk->entry_bytes is updated.
 *
 * @returns #CST_SUCCESS if successful, #CST_FAILURE otherwise
 */
void srk_entry_dilithium(tgt_t target, EVP_PKEY *pkey, srk_entry_t *srk,
                         bool ca_flag, const char *sd_alg_str,
                         bool hash_key_data);

/** Generate SRK table key entry
 *
 * This function builds a ML-DSA algorithm public key data structure from the
 * given X.509 key data.
 *
 * @param[in] target Define which component is targeted.
 *
 * @param[in] pkey Pointer OpenSSL public key data structure
 *
 * @param[in] srk Pointer to a SRK table entry data structure
 *
 * @param[in] ca_flag If set this indicates key is from a CA certificate
 *
 * @param[in] sd_alg_str Define which signature hash algorithm will be used
 *                       in conjunction with the given key
 *
 * @param[in] hash_key_data Boolean flag to indicate if the key data should
 * be hashed.
 *
 * @pre @a pkey and @a srk must not be NULL
 *
 * @pre The data lacated at @a srk->entry follows the ML-DSA algorithm key data
 *      format described in the AHAB SIS.
 *
 * @post if successful, @a srk->entry contains the public key data and
 *       and srk->entry_bytes is updated.
 *
 * @returns #CST_SUCCESS if successful, #CST_FAILURE otherwise
 */
void srk_entry_mldsa(tgt_t target, EVP_PKEY *pkey, srk_entry_t *srk,
                     bool ca_flag, const char *sd_alg_str, bool hash_key_data);

/** Generate SRK table record from an hybrid key
 *
 * This function builds an SRK record data structure from the
 * given key data, table_index selects which key part to use
 * ( classical or quantum-resistant).
 *
 * @param[in] target Define which component is targeted.
 *
 * @param[in] pkey Pointer OpenSSL public key data structure
 *
 * @param[in] table_index Index of the SRK table
 *
 * @param[in] srk Pointer to a SRK table entry data structure
 *
 * @param[in] ca_flag If set this indicates key is from a CA certificate
 *
 * @param[in] sd_alg_str Define which signature hash algorithm will be used
 *                       in conjunction with the given key
 *
 * @param[in] hash_key_data Boolean flag to indicate if the key data should
 * be hashed.
 *
 * @pre @a pkey and @a srk must not be NULL
 *
 * @pre The data lacated at @a srk->entry follows the hybrid key data format.
 *
 * @post if successful, @a srk->entry contains the public key data and
 *       and srk->entry_bytes is updated.
 *
 * @returns #CST_SUCCESS if successful, #CST_FAILURE otherwise
 */
void srk_entry_hybrid(tgt_t target, EVP_PKEY *pkey, uint8_t table_index,
                      srk_entry_t *srk, bool ca_flag, const char *sd_alg_str,
                      bool hash_key_data);

/** Generate SRK data.
 *
 * @param[in] entry_idx Index of the SRK entry.
 * @param[in] key_data Pointer to the key data buffer.
 * @param[in] key_data_size Size of the key data buffer.
 * @param[out] srk_data_size Pointer to size of the generated SRK data.
 *
 * @returns uint8_t* Pointer to the generated SRK data buffer. NULL if
 * fails.
 */
uint8_t *generate_srk_data(uint8_t entry_idx, uint8_t *key_data,
                           size_t key_data_size, size_t *srk_data_size);

/**
 * Generate hash for the given SRK data.
 *
 * Hash of SRK data is fixed size at 512 bits. Left aligned and padded with
 * zero for hash sizes below 512 bits.
 *
 * @param[in] entry_idx Index of the SRK entry.
 * @param[in] key_data Pointer to the key data buffer.
 * @param[in] key_data_size Size of the key data buffer.
 * @param[in] sd_alg_str Define which signature hash algorithm will be used.
 * @param[out] srk_data_hash_size Pointer to size of the generated SRK data
 * hash.
 *
 * @returns uint8_t* Pointer to the generated SRK data hash buffer. NULL if
 * fails.
 */
uint8_t *generate_srk_data_hash(uint8_t entry_idx, uint8_t *key_data,
                                size_t key_data_size, const char *sd_alg_str,
                                size_t *srk_data_hash_size);

/** Generate SRK table array
 *
 * This function generates array of SRK tables into a single contiguous
 * memory block, including placeholders for SRK data.
 *
 * @param[in] tables Pointer to an array of SRK tables.
 * @param[in] num_tables Number of SRK tables.
 * @param[out] out_size Pointer to store the size of the generated SRK table
 * array.
 *
 * @return Pointer to the generated SRK table array, or NULL on failure.
 */
uint8_t *generate_srk_table_array(srk_table_t *tables, size_t num_tables,
                                  size_t *out_size);

/** Converts digest algorithm string to encoded tag value
 *
 * @param[in] digest_alg Case insensitive string containing "sha1",
 * "sha256", "sha384" or "sha512"
 *
 * @pre @a digest_alg is not NULL
 *
 * @returns encoded digest value based on given @a digest_alg string,
 *          otherwise 0 is returned if @a digest_alg is not supported
 *
 */
uint32_t digest_alg_tag(const char *digest_alg);

/** Checks for a valid signature digest command line argument and converts
 *  @a alg_str to a corresponding integer value.
 *
 * @param[in] alg_str Character string containing the digest algorithm
 *
 * @pre  @a alg_str is not NULL
 *
 * @remark If @a alg_str contains unknown algorithm string an error is
 *         displayed to STDOUT and the program exits.
 *
 * @retval #HAB_ALG_SHA256 if @a alg_str is "sha256",
 *
 * @retval #HAB_ALG_SHA384 if @a alg_str is "sha384",
 *
 * @retval #HAB_ALG_SHA512 if @a alg_str is "sha512".
 */
uint32_t check_sign_digest_alg(const char *alg_str);

/** Converts a certificate to an SRK table entry/record.
 *
 * This function reads an X.509 certificate, extracts the public key, and
 * converts it into an SRK table entry structure.
 *
 * @param[in] target The target component.
 * @param[in] certificate_path The file path to the certificate.
 * @param[in] table_index The SRK table index.
 * @param[in] entry_index Index of SRK entry/record in the SRK table.
 * @param[in] sd_alg_str Define which signature hash algorithm will be used
 *                       in conjunction with the given key
 * @param[in] hash_key_data Boolean flag to indicate if the key data should
 * be hashed.
 *
 * @return Pointer to the newly created srk_entry_t structure, or NULL on
 * failure.
 */
srk_entry_t *cert_to_srk_entry(tgt_t target, const char *certificate_path,
                               uint8_t table_index, uint8_t entry_index,
                               const char *sd_alg_str, bool hash_key_data);

/** Retrieves the hash size based on the given SRK hash type.
 *
 * @param hash_type The type of the SRK hash algorithm (e.g., SRK_SHA256, SRK_SHA384).
 * @return int32_t The size of the hash output in bytes, or -1 if the hash type is invalid.
 */
int32_t ahab_get_hash_size_by_hash_type(uint8_t hash_type);

#endif /* SRK_HELPER_H */
