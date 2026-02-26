// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2018-2020, 2022-2025 NXP
 */

/*===========================================================================*/
/**
    @file    srk_helper.c

    @brief   Provide helper functions to ease SRK tasks and also defines
             common struct that can used across different tools
 */

/*===========================================================================
                                INCLUDE FILES
=============================================================================*/
#include <strings.h>
#include "err.h"
#include "srk_helper.h"
#include "hab_types.h"
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#include <openssl/core_names.h>
#endif

/*===========================================================================
                                LOCAL FUNCTIONS
=============================================================================*/

static uint8_t hash_to_srk_type(const char *sd_alg_str)
{
    switch (digest_alg_tag(sd_alg_str))
    {
        case HAB_ALG_SHA256:
            return SRK_SHA256;
        case HAB_ALG_SHA384:
            return SRK_SHA384;
        case HAB_ALG_SHA512:
            return SRK_SHA512;
#if CST_WITH_PQC
        case HAB_ALG_SHA3_256:
            return SRK_SHA3_256;
        case HAB_ALG_SHA3_384:
            return SRK_SHA3_384;
        case HAB_ALG_SHA3_512:
            return SRK_SHA3_512;
        case HAB_ALG_SHAKE128_256:
            return SRK_SHAKE128_256;
        case HAB_ALG_SHAKE256_512:
            return SRK_SHAKE256_512;
#endif
        default:
            error("Unsupported signature hash algorithm");
            return 0;
    }
}

/*===========================================================================
                               GLOBAL FUNCTIONS
=============================================================================*/

/*--------------------------
  generate_srk_table_array
---------------------------*/
uint8_t *generate_srk_table_array(srk_table_t *tables, size_t num_tables,
                                  size_t *out_size)
{
    size_t idx = 0; /**< Index in SRK table/array data buffer */
    uint8_t *srk_table_array = NULL; /**< SRK table array buffer */
    size_t srk_data_size = 0;        /**< Size of SRK data */
    uint8_t *srk_data = NULL;        /**< SRK data buffer */

    if (tables == NULL || out_size == NULL)
    {
        return NULL;
    }

    if (num_tables == 0 || num_tables > CNTN_MAX_NR_SRK_TABLE)
    {
        *out_size = 0;
        return NULL;
    }

    /* Calculate the total size of the SRK table array */
    size_t total_size = sizeof(struct ahab_container_srk_table_array_s);
    for (size_t i = 0; i < num_tables; i++)
    {
        if (tables[i].table == NULL || tables[i].table_bytes == 0)
        {
            *out_size = 0;
            return NULL;
        }

        total_size += tables[i].table_bytes +
                      sizeof(struct ahab_container_srk_data_s) +
                      ((struct ahab_container_srk_s
                            *) (tables[i].table +
                                sizeof(struct ahab_container_srk_table_s)))
                          ->modulus_or_x_or_pk_length +
                      ((struct ahab_container_srk_s
                            *) (tables[i].table +
                                sizeof(struct ahab_container_srk_table_s)))
                          ->exponent_or_y_length;
    }

    srk_table_array = (uint8_t *) malloc(total_size);

    if (!srk_table_array)
    {
        *out_size = 0;
        return NULL;
    }

    /* Version */
    srk_table_array[idx++] = SRK_TABLE_ARRAY_VERSION;

    /* Size of the SRK Table Data */
    srk_table_array[idx++] = EXTRACT_BYTE(total_size, 0);
    srk_table_array[idx++] = EXTRACT_BYTE(total_size, 8);

    /* Tag */
    srk_table_array[idx++] = SRK_TABLE_ARRAY_TAG;

    /* # of SRK Tables */
    srk_table_array[idx++] = num_tables;

    /* Reserved */
    for (int i = 0; i < 3; ++i)
    {
        srk_table_array[idx++] = 0;
    }

    /* SRK tables */
    for (size_t i = 0; i < num_tables; ++i)
    {
        /* Copy the table data */
        memcpy(&srk_table_array[idx], tables[i].table, tables[i].table_bytes);
        idx += tables[i].table_bytes;

        /* Placeholder for SRK Data */
        srk_data_size = sizeof(struct ahab_container_srk_data_s) +
                        ((struct ahab_container_srk_s
                              *) (tables[i].table +
                                  sizeof(struct ahab_container_srk_table_s)))
                            ->modulus_or_x_or_pk_length +
                        ((struct ahab_container_srk_s
                              *) (tables[i].table +
                                  sizeof(struct ahab_container_srk_table_s)))
                            ->exponent_or_y_length;

        srk_data = (uint8_t *) &srk_table_array[idx];
        memset(&srk_data[0], 0, srk_data_size);
        srk_data[0] = SRK_DATA_VERSION;
        srk_data[1] = EXTRACT_BYTE(srk_data_size, 0);
        srk_data[2] = EXTRACT_BYTE(srk_data_size, 8);
        srk_data[3] = SRK_DATA_TAG;
        idx += srk_data_size;
    }

    *out_size = idx;

    return srk_table_array;
}

/*--------------------------
  generate_srk_data
---------------------------*/
uint8_t *generate_srk_data(uint8_t entry_idx, uint8_t *key_data,
                           size_t key_data_size, size_t *srk_data_size)
{

    size_t idx = 0;           /**< Index in SRK data buffer */
    uint8_t *srk_data = NULL; /**< SRK data buffer */

    *srk_data_size = sizeof(struct ahab_container_srk_data_s) + key_data_size;
    srk_data = (uint8_t *) malloc(*srk_data_size);

    if (!srk_data)
    {
        *srk_data_size = 0;
        return NULL;
    }

    /* Version */
    srk_data[idx++] = SRK_DATA_VERSION;

    /* Size of the SRK Data */
    srk_data[idx++] = EXTRACT_BYTE(*srk_data_size, 0);
    srk_data[idx++] = EXTRACT_BYTE(*srk_data_size, 8);

    /* Tag */
    srk_data[idx++] = SRK_DATA_TAG;

    /* SRK Record # */
    srk_data[idx++] = entry_idx;

    /* Reserved */
    for (int i = 0; i < 3; ++i)
    {
        srk_data[idx++] = 0;
    }

    /* Key data */
    for (size_t i = 0; i < key_data_size; ++i)
    {
        srk_data[idx++] = key_data[i];
    }

    *srk_data_size = idx;

    return srk_data;
}

/*--------------------------
  generate_srk_data_hash
---------------------------*/
uint8_t *generate_srk_data_hash(uint8_t entry_idx, uint8_t *key_data,
                                size_t key_data_size, const char *sd_alg_str,
                                size_t *srk_data_hash_size)
{
    uint8_t *srk_data = NULL;      /**< SRK data buffer */
    size_t srk_data_size = 0;      /**< Size of SRK data buffer */
    uint8_t *srk_data_hash = NULL; /**< SRK data hash buffer */
    size_t hash_size = 0;          /**< Size of hash */
    size_t padding_size = 0;       /**< Size of required padding in bytes */
    uint8_t *result = NULL;

    /* Generate SRK data */
    srk_data =
        generate_srk_data(entry_idx, key_data, key_data_size, &srk_data_size);
    if (!srk_data)
    {
        return NULL;
    }

    /* Generate hash of SRK data */
    srk_data_hash =
        generate_hash(srk_data, srk_data_size, sd_alg_str, &hash_size);
    if (srk_data_hash == NULL)
    {
        free(srk_data);
        return NULL;
    }

    /* Padd it */
    result = (uint8_t *) malloc(SRK_DATA_HASH_SIZE);
    if (!result)
    {
        free(srk_data);
        free(srk_data_hash);
        return NULL;
    }
    padding_size = SRK_DATA_HASH_SIZE - hash_size;

    memset(result, 0, SRK_DATA_HASH_SIZE);
    memcpy(result, srk_data_hash, hash_size);
    *srk_data_hash_size = SRK_DATA_HASH_SIZE;

    /* Clean up */
    free(srk_data);
    free(srk_data_hash);

    return result;
}

/*--------------------------
  srk_entry_pkcs1
---------------------------*/
void srk_entry_pkcs1(tgt_t target, EVP_PKEY *pkey, srk_entry_t *srk,
                     bool ca_flag, const char *sd_alg_str, bool hash_key_data)
{
    uint32_t idx = 0;              /**< Index in SRK entry buffer */
    uint32_t key_data_idx = 0;     /**< Index of key data in entry */
    size_t key_data_size = 0;      /**< Size of key data in entry */
    uint8_t *srk_data_hash = NULL; /**< SRK data hash */
    size_t srk_data_hash_size = 0; /**< Size of SRK data hash */
    uint8_t *modulus; /**< Public key modulus */
    uint8_t *exponent; /**< Public key exponent */
    size_t mod_bytes; /**< Modulus size in bytes */
    size_t exp_bytes; /**< Exponent size in bytes */
    int crypto_algo = HAB_ALG_PKCS1;
    uint8_t hash_algo = 0;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    BIGNUM *n = NULL, *e = NULL; /**< modulus and exponent defined as OpenSSL BIGNUM */
#else
    const BIGNUM *n = NULL, *e = NULL; /**< modulus and exponent defined as OpenSSL BIGNUM */
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    /* Every RSA key has an 'n' */
    EVP_PKEY_get_bn_param(pkey, "n", &n);

    /* Every RSA key has an 'e' */
    EVP_PKEY_get_bn_param(pkey, "e", &e);
#else
    RSA_get0_key(EVP_PKEY_get0_RSA(pkey), &n, &e, NULL);
#endif

    /* Get bigNUM modulus */
    modulus = get_bn(n, &mod_bytes);
    if (modulus == NULL)
    {
        error("Cannot allocate memory for modulus");
    }

    /* Get bigNUM exponent */
    exponent = get_bn(e, &exp_bytes);
    if (exponent == NULL)
    {
        error("Cannot allocate memory for exponent");
    }

    /* Build the entry */
    srk->entry = (uint8_t *)malloc(SRK_KEY_HEADER_BYTES +
                                   mod_bytes + exp_bytes);
    if (!srk->entry)
    {
        error("Cannot allocate SRK entry buffer");
    }

    srk->entry_bytes = SRK_KEY_HEADER_BYTES + mod_bytes + exp_bytes;

    /* Determine if the algorithm is rsa-pss */
    if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA_PSS) {
        crypto_algo = HAB_ALG_RSA_PSS;
    }

    /* Set hash type */
    hash_algo = hash_to_srk_type(sd_alg_str);
    if (hash_algo > MAX_SRK_HASH_TYPE)
    {
        error("Unsupported signature hash algorithm");
    }

    /* Fill in header, ... */
    srk->entry[idx++] = HAB_KEY_PUBLIC;
    if (IS_AHAB(target))
    {
        srk->entry[idx++] = EXTRACT_BYTE(srk->entry_bytes, 0);
        srk->entry[idx++] = EXTRACT_BYTE(srk->entry_bytes, 8);
        srk->entry[idx++] = crypto_algo;
        srk->entry[idx++] = hash_algo;

        /* Key size */
        switch (EVP_PKEY_bits((EVP_PKEY *)pkey))
        {
            case 2048:
                srk->entry[idx++] = SRK_RSA2048;
                break;
            case 3072:
                srk->entry[idx++] = SRK_RSA3072;
                break;
            case 4096:
                srk->entry[idx++] = SRK_RSA4096;
                break;
            default:
                error("Unsupported RSA key size");
        }
    }
    else
    {
        srk->entry[idx++] = EXTRACT_BYTE(srk->entry_bytes, 8);
        srk->entry[idx++] = EXTRACT_BYTE(srk->entry_bytes, 0);
        srk->entry[idx++] = crypto_algo;
        srk->entry[idx++] = 0;
        srk->entry[idx++] = 0;
    }
    srk->entry[idx++] = 0;

    /* Set CA flag in SRK consistent with the CA flag from the cert */
    if (ca_flag == TRUE)
    {
        srk->entry[idx++] = HAB_KEY_FLG_CA;
    }
    else
    {
        srk->entry[idx++] = 0;
    }

    /* then modulus bytes and exponent bytes, ... */
    if (IS_HAB(target))
    {
        srk->entry[idx++] = EXTRACT_BYTE(mod_bytes, 8);
        srk->entry[idx++] = EXTRACT_BYTE(mod_bytes, 0);
        srk->entry[idx++] = EXTRACT_BYTE(exp_bytes, 8);
        srk->entry[idx++] = EXTRACT_BYTE(exp_bytes, 0);
    }
    else
    {
        srk->entry[idx++] = EXTRACT_BYTE(mod_bytes, 0);
        srk->entry[idx++] = EXTRACT_BYTE(mod_bytes, 8);
        srk->entry[idx++] = EXTRACT_BYTE(exp_bytes, 0);
        srk->entry[idx++] = EXTRACT_BYTE(exp_bytes, 8);
    }

    /* Save index of public key data */
    key_data_idx = idx;

    /* followed by modulus, ...  */
    memcpy(&srk->entry[idx], modulus, mod_bytes);
    idx += mod_bytes;

    /* and finally exponent */
    memcpy(&srk->entry[idx], exponent, exp_bytes);

    idx += exp_bytes;

    /* Set size of key data */
    key_data_size = idx - key_data_idx;

    /* Generate SRK data hash */
    if (hash_key_data)
    {
        srk_data_hash = generate_srk_data_hash(
            srk->index, &srk->entry[key_data_idx], key_data_size, sd_alg_str,
            &srk_data_hash_size);

        if (!srk_data_hash)
        {
            free(exponent);
            free(modulus);
            error("Can't generate SRK data hash for entry at index %u",
                  srk->index);
        }

        memcpy(&srk->entry[key_data_idx], srk_data_hash, srk_data_hash_size);

        idx = key_data_idx + srk_data_hash_size;

        /* Update the size of the SRK record */
        srk->entry[1] = EXTRACT_BYTE(idx, 0);
        srk->entry[2] = EXTRACT_BYTE(idx, 8);

        free(srk_data_hash);
    }

    /* Done */
    srk->entry_bytes = idx;

    /* Clean up */
    free(exponent);
    free(modulus);
}

/*--------------------------
  srk_entry_ec
---------------------------*/
void srk_entry_ec(tgt_t target, EVP_PKEY *pkey, srk_entry_t *srk, bool ca_flag,
                  const char *sd_alg_str, bool hash_key_data)
{
    uint32_t idx = 0;              /**< Index in SRK entry buffer */
    uint32_t key_data_idx = 0;     /**< Index of key data in entry */
    size_t key_data_size = 0;      /**< Size of key data in entry */
    uint8_t *srk_data_hash = NULL; /**< SRK data hash */
    size_t srk_data_hash_size = 0; /**< Size of SRK data hash */
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
    const EC_POINT *pub_key;      /**< EC public key          */
#endif
    BIGNUM         *num_x = NULL; /**< Public key number X    */
    BIGNUM         *num_y = NULL; /**< Public key number Y    */
    size_t         num_x_bytes;   /**< Number X size in bytes */
    size_t         num_y_bytes;   /**< Number Y size in bytes */
    size_t         num_bytes = 0;
    uint8_t hash_algo = 0;
    uint8_t        curve_id = 0;

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    EC_POINT *pub_key = NULL;      /**< EC public key          */
    EC_GROUP *group = NULL;
    unsigned char *out_pubkey = NULL;
    size_t out_pubkey_len = 0 ;
    char name[50];
    size_t len = 0;

    if (EVP_PKEY_get_group_name(pkey, name, sizeof(name), &len) != 1)
    {
        error("Cannot get group name of key");
    }

    group = EC_GROUP_new_by_curve_name(OBJ_txt2nid(name));
    if (group == NULL)
    {
        error("Cannot create EC GROUP by curve name ");
    }

    /* NOTE - Function only used in AHAB context at the moment */
    /* Get the size to allocate memory for public key*/
    EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        NULL, 0,
                                        &out_pubkey_len);
    out_pubkey = OPENSSL_malloc(out_pubkey_len);
    if (out_pubkey == NULL)
    {
        error("Cannot allocate memory for public key\n");
    }
    if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        out_pubkey, out_pubkey_len,
                                        NULL)) {
        OPENSSL_free(out_pubkey);
        error("Failed to get public key\n");
    }
    if (!(pub_key = EC_POINT_new(group)) ||
    EC_POINT_oct2point(group, pub_key,out_pubkey, out_pubkey_len, NULL)!= 1) {

        OPENSSL_free(out_pubkey);
        EC_GROUP_free(group);
        EC_POINT_free(pub_key);
        error("Cannot retrive EC public key");
    }

#else
    pub_key = EC_KEY_get0_public_key(EVP_PKEY_get0_EC_KEY(pkey));
    if (NULL == pub_key)
    {
        error("Cannot retrive EC public key");
    }
#endif
    num_x = BN_new();
    if (NULL == num_x)
    {
        error("Cannot allocate memory for number X");
    }
    num_y = BN_new();
    if (NULL == num_y)
    {
        BN_free(num_x);
        error("Cannot allocate memory for number Y");
    }
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)

    if (!EC_POINT_get_affine_coordinates(group,pub_key, num_x, num_y, NULL))
    {
        BN_free(num_x);
        BN_free(num_y);
        error("Cannot retrieve X and Y numbers");
    }
#else
    if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pkey)),
                                             pub_key, num_x, num_y, NULL))
    {
        BN_free(num_x);
        BN_free(num_y);
        error("Cannot retrieve X and Y numbers");
    }
#endif
    num_x_bytes = BN_num_bytes(num_x);
    num_y_bytes = BN_num_bytes(num_y);

    switch (EVP_PKEY_bits((EVP_PKEY *)pkey))
    {
        case 256:
            num_bytes = 32;
            break;
        case 384:
            num_bytes = 48;
            break;
        case 521:
            num_bytes = 66;
            break;
        default:
            BN_free(num_x);
            BN_free(num_y);
            error("Unsupported ellyptic curve");
    }

    /* Build the entry */
    srk->entry = (uint8_t *)malloc(SRK_KEY_HEADER_BYTES +
                                   num_bytes * 2);
    if (NULL == srk->entry)
    {
        BN_free(num_x);
        BN_free(num_y);
        error("Cannot allocate SRK table entry buffer");
    }

    srk->entry_bytes = SRK_KEY_HEADER_BYTES + num_bytes * 2;

    if (IS_AHAB(target))
    {
        /* Fill in header, ... */
        srk->entry[idx++] = HAB_KEY_PUBLIC;
        srk->entry[idx++] = EXTRACT_BYTE(srk->entry_bytes, 0);
        srk->entry[idx++] = EXTRACT_BYTE(srk->entry_bytes, 8);
        srk->entry[idx++] = SRK_ECDSA;
    }
    else
    {
        /* Fill in header, ... */
        srk->entry[idx++] = HAB_KEY_PUBLIC;
        srk->entry[idx++] = EXTRACT_BYTE(srk->entry_bytes, 8);
        srk->entry[idx++] = EXTRACT_BYTE(srk->entry_bytes, 0);
        srk->entry[idx++] = SRK_ECDSA;
    }

    /* Set hash type */
    hash_algo = hash_to_srk_type(sd_alg_str);
    if (hash_algo > MAX_SRK_HASH_TYPE)
    {
        error("Unsupported signature hash algorithm");
    }

    if (IS_AHAB(target))
    {
        /* Curve */
        switch (EVP_PKEY_bits((EVP_PKEY *)pkey))
        {
        case 256:
            curve_id = SRK_PRIME256V1;
            break;
        case 384:
            curve_id = SRK_SEC384R1;
            break;
        case 521:
            curve_id = SRK_SEC521R1;
            break;
        default:
            BN_free(num_x);
            BN_free(num_y);
            error("Unsupported ellyptic curve");
        }
        srk->entry[idx++] = hash_algo;
        srk->entry[idx++] = curve_id;
    }
    else
    {
        /* Curve */
        switch (EVP_PKEY_bits((EVP_PKEY *)pkey))
        {
        case 256:
            curve_id = HAB_EC_P256;
            break;
        case 384:
            curve_id = HAB_EC_P384;
            break;
        case 521:
            curve_id = HAB_EC_P521;
            break;
        default:
            BN_free(num_x);
            BN_free(num_y);
            error("Unsupported ellyptic curve");
        }
        srk->entry[idx++] = 0;
        srk->entry[idx++] = 0;
    }
    srk->entry[idx++] = 0;

    /* Set CA flag in SRK consistent with the CA flag from the cert */
    if (ca_flag == TRUE)
    {
        srk->entry[idx++] = HAB_KEY_FLG_CA;
    }
    else
    {
        srk->entry[idx++] = 0;
    }

    if (IS_AHAB(target))
    {
        /* then number X bytes and number Y bytes, ... */
        srk->entry[idx++] = EXTRACT_BYTE(num_bytes, 0);
        srk->entry[idx++] = EXTRACT_BYTE(num_bytes, 8);
        srk->entry[idx++] = EXTRACT_BYTE(num_bytes, 0);
        srk->entry[idx++] = EXTRACT_BYTE(num_bytes, 8);
    }
    else
    {
        srk->entry[idx++] = curve_id;
        srk->entry[idx++] = 0;
        srk->entry[idx++] = EXTRACT_BYTE(EVP_PKEY_bits((EVP_PKEY *)pkey), 8);
        srk->entry[idx++] = EXTRACT_BYTE(EVP_PKEY_bits((EVP_PKEY *)pkey), 0);
    }

    /* Save index of public key data */
    key_data_idx = idx;

    /* followed by number X, ...  */
    if (num_bytes != num_x_bytes) {
        for (uint32_t i = 0; i < (num_bytes - num_x_bytes); i++) {
            srk->entry[idx++] = 0;
        }
    }
    BN_bn2bin(num_x, &srk->entry[idx]);
    idx += num_x_bytes;

    /* and finally number Y */
    if (num_bytes != num_y_bytes) {
        for (uint32_t i = 0; i < (num_bytes - num_y_bytes); i++) {
            srk->entry[idx++] = 0;
        }
    }
    BN_bn2bin(num_y, &srk->entry[idx]);
    idx += num_y_bytes;

    /* Set size of key data */
    key_data_size = idx - key_data_idx;

    /* Generate SRK data hash */
    if (hash_key_data)
    {
        srk_data_hash = generate_srk_data_hash(
            srk->index, &srk->entry[key_data_idx], key_data_size, sd_alg_str,
            &srk_data_hash_size);

        if (!srk_data_hash)
        {
            BN_free(num_x);
            BN_free(num_y);
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
            OPENSSL_free(out_pubkey);
#endif
            error("Can't generate SRK data hash for entry at index %u",
                  srk->index);
        }

        memcpy(&srk->entry[key_data_idx], srk_data_hash, srk_data_hash_size);

        idx = key_data_idx + srk_data_hash_size;

        /* Update the size of the SRK record */
        srk->entry[1] = EXTRACT_BYTE(idx, 0);
        srk->entry[2] = EXTRACT_BYTE(idx, 8);

        free(srk_data_hash);
    }

    /* Done */
    srk->entry_bytes = idx;

    /* Clean up */
    BN_free(num_x);
    BN_free(num_y);
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    OPENSSL_free(out_pubkey);
#endif
}

#if CST_WITH_PQC
/*--------------------------
  srk_entry_dilithium
---------------------------*/
void srk_entry_dilithium(tgt_t target, EVP_PKEY *pkey, srk_entry_t *srk,
                         bool ca_flag, const char *sd_alg_str,
                         bool hash_key_data)
{
    uint8_t *pk = NULL;            /**< Dilithium public key */
    size_t pk_size = 0;            /**< Dilithium public key size*/
    uint32_t idx = 0;              /**< Index in SRK entry buffer */
    uint8_t *srk_data_hash = NULL; /**< SRK data hash */
    size_t srk_data_hash_size = 0; /**< Size of SRK data hash */
    uint8_t hash_algo = 0;         /**< SRK Hash type */
    uint32_t key_data_idx = 0; /**< Index of key data in entry */
    size_t key_data_size = 0;  /**< Size of key data in entry */

    /* Check if the provided public key algorithm is supported */
    if (!EVP_PKEY_is_a(pkey, "dilithium3") &&
        !EVP_PKEY_is_a(pkey, "dilithium5"))
    {
        error("Only level 3 and 5 are supported for Dilithium algorithm");
    }

    /* Retrieve public key data */
    if (get_param_octet_string(pkey, OSSL_PKEY_PARAM_PUB_KEY, &pk, &pk_size))
    {
        error("Cannot get Dilithium public key data");
    }

    /* Build the entry */
    srk->entry = (uint8_t *) malloc(SRK_KEY_HEADER_BYTES + pk_size);
    if (!srk->entry)
    {
        error("Cannot allocate SRK entry buffer");
    }

    srk->entry_bytes = SRK_KEY_HEADER_BYTES + pk_size;

    /* Fill in header, ... */
    srk->entry[idx++] = HAB_KEY_PUBLIC;
    srk->entry[idx++] = EXTRACT_BYTE(srk->entry_bytes, 0);
    srk->entry[idx++] = EXTRACT_BYTE(srk->entry_bytes, 8);
    srk->entry[idx++] = SRK_DILITHIUM;

    hash_algo = hash_to_srk_type(sd_alg_str);
    if (hash_algo > MAX_SRK_HASH_TYPE)
    {
        error("Unsupported signature hash algorithm");
    }

    /* Hash algo */
    srk->entry[idx++] = hash_algo;

    /* Key size */
    srk->entry[idx++] =
        EVP_PKEY_is_a(pkey, "dilithium3") ? SRK_DILITHIUM3 : SRK_DILITHIUM5;

    /* Reserved */
    srk->entry[idx++] = 0;

    /* Set CA flag in SRK consistent with the CA flag from the cert */
    if (ca_flag == TRUE)
    {
        srk->entry[idx++] = HAB_KEY_FLG_CA;
    }
    else
    {
        srk->entry[idx++] = 0;
    }

    /* Parameters length */
    srk->entry[idx++] = EXTRACT_BYTE(pk_size, 0);
    srk->entry[idx++] = EXTRACT_BYTE(pk_size, 8);
    srk->entry[idx++] = 0;
    srk->entry[idx++] = 0;

    /* Save index of public key data */
    key_data_idx = idx;

    /* Public key */
    memcpy(&srk->entry[idx], pk, pk_size);
    idx += pk_size;

    /* Set size of key data */
    key_data_size = idx - key_data_idx;

    /* Generate SRK data hash */
    if (hash_key_data)
    {
        srk_data_hash = generate_srk_data_hash(
            srk->index, &srk->entry[key_data_idx], key_data_size, sd_alg_str,
            &srk_data_hash_size);

        if (!srk_data_hash)
        {
            free(pk);
            error("Can't generate SRK data hash for entry at index %u",
                  srk->index);
        }

        memcpy(&srk->entry[key_data_idx], srk_data_hash, srk_data_hash_size);

        idx = key_data_idx + srk_data_hash_size;

        /* Update the size of the SRK record */
        srk->entry[1] = EXTRACT_BYTE(idx, 0);
        srk->entry[2] = EXTRACT_BYTE(idx, 8);

        free(srk_data_hash);
    }

    /* Done */
    srk->entry_bytes = idx;

    free(pk);
}

/*--------------------------
  srk_entry_mldsa
---------------------------*/
void srk_entry_mldsa(tgt_t target, EVP_PKEY *pkey, srk_entry_t *srk,
                     bool ca_flag, const char *sd_alg_str, bool hash_key_data)
{
    uint8_t *pk = NULL;            /**< ML-DSA public key */
    size_t pk_size = 0;            /**< ML-DSA public key size*/
    uint32_t idx = 0;              /**< Index in SRK entry buffer */
    uint8_t *srk_data_hash = NULL; /**< SRK data hash */
    size_t srk_data_hash_size = 0; /**< Size of SRK data hash */
    uint8_t hash_algo = 0;         /**< SRK Hash type */
    uint32_t key_data_idx = 0; /**< Index of key data in entry */
    size_t key_data_size = 0;  /**< Size of key data in entry */

    /* Check if the provided public key algorithm is supported */
    if (!EVP_PKEY_is_a(pkey, "mldsa65") && !EVP_PKEY_is_a(pkey, "mldsa87"))
    {
        error("Only ML-DSA65 and ML-DSA87 are supported");
    }

    /* Retrieve public key data */
    if (get_param_octet_string(pkey, OSSL_PKEY_PARAM_PUB_KEY, &pk, &pk_size))
    {
        error("Cannot get ML-DSA public key data");
    }

    /* Build the entry */
    srk->entry = (uint8_t *) malloc(SRK_KEY_HEADER_BYTES + pk_size);
    if (!srk->entry)
    {
        error("Cannot allocate SRK entry buffer");
    }

    srk->entry_bytes = SRK_KEY_HEADER_BYTES + pk_size;

    /* Fill in header, ... */
    srk->entry[idx++] = HAB_KEY_PUBLIC;
    srk->entry[idx++] = EXTRACT_BYTE(srk->entry_bytes, 0);
    srk->entry[idx++] = EXTRACT_BYTE(srk->entry_bytes, 8);
    srk->entry[idx++] = SRK_MLDSA;

    hash_algo = hash_to_srk_type(sd_alg_str);
    if (hash_algo > MAX_SRK_HASH_TYPE)
    {
        error("Unsupported signature hash algorithm");
    }

    /* Hash algo */
    srk->entry[idx++] = hash_algo;

    /* Key size */
    srk->entry[idx++] =
        EVP_PKEY_is_a(pkey, "mldsa65") ? SRK_MLDSA65 : SRK_MLDSA87;

    /* Reserved */
    srk->entry[idx++] = 0;

    /* Set CA flag in SRK consistent with the CA flag from the cert */
    if (ca_flag == TRUE)
    {
        srk->entry[idx++] = HAB_KEY_FLG_CA;
    }
    else
    {
        srk->entry[idx++] = 0;
    }

    /* Parameters length */
    srk->entry[idx++] = EXTRACT_BYTE(pk_size, 0);
    srk->entry[idx++] = EXTRACT_BYTE(pk_size, 8);
    srk->entry[idx++] = 0;
    srk->entry[idx++] = 0;

    /* Save index of public key data */
    key_data_idx = idx;

    /* Public key */
    memcpy(&srk->entry[idx], pk, pk_size);
    idx += pk_size;

    /* Set size of key data */
    key_data_size = idx - key_data_idx;

    /* Generate SRK data hash */
    if (hash_key_data)
    {
        srk_data_hash = generate_srk_data_hash(
            srk->index, &srk->entry[key_data_idx], key_data_size, sd_alg_str,
            &srk_data_hash_size);

        if (!srk_data_hash)
        {
            free(pk);
            error("Can't generate SRK data hash for entry at index %u",
                  srk->index);
        }

        memcpy(&srk->entry[key_data_idx], srk_data_hash, srk_data_hash_size);

        idx = key_data_idx + srk_data_hash_size;

        /* Update the size of the SRK record */
        srk->entry[1] = EXTRACT_BYTE(idx, 0);
        srk->entry[2] = EXTRACT_BYTE(idx, 8);

        free(srk_data_hash);
    }

    /* Done */
    srk->entry_bytes = idx;

    free(pk);
}

/*--------------------------
  srk_entry_hybrid
---------------------------*/
void srk_entry_hybrid(tgt_t target, EVP_PKEY *pkey, uint8_t table_index,
                      srk_entry_t *srk, bool ca_flag, const char *sd_alg_str,
                      bool hash_key_data)
{
    EVP_PKEY *classical_key =
        NULL; /**< EVP public key of the classical part of an hybrid key */
    EVP_PKEY *pqc_key = NULL; /**< EVP public key of the quantum-resistant
                                      part of an hybrid key */
    char classical_alg_name[64] = {0}; /**< Name of the classical algorithm */
    char pqc_alg_name[64] = {0};       /**< Name of the pqc algorithm */

    /* Extract the classical algorithm name prefix */
    EXTRACT_CLASSICAL_ALGO(EVP_PKEY_get0_type_name(pkey), classical_alg_name);

    /* Extract the quantum-resistant algorithm name prefix */
    EXTRACT_PQC_ALGO(EVP_PKEY_get0_type_name(pkey), pqc_alg_name);

    /* Extract classical and quantum-resistant keys */
    if (partition_hybrid_key(get_libctx(), pkey, &classical_key, &pqc_key) != 1)
    {
        error("Can't extract classical and quantum-resistant keys from the "
              "given hybrid key");
    }

    if (table_index == 0)
    {
        /* SRK table 0 holds always key data of classical algorithm */
        if (strcmp(classical_alg_name, "p256") == 0 ||
            strcmp(classical_alg_name, "p384") == 0 ||
            strcmp(classical_alg_name, "p521") == 0)
        {
            srk_entry_ec(target, classical_key, srk, ca_flag, sd_alg_str,
                         hash_key_data);
        }
        else if (strncmp(classical_alg_name, "rsa", 3) == 0 ||
                 strncmp(classical_alg_name, "pss", 3) == 0)
        {
            srk_entry_pkcs1(target, classical_key, srk, ca_flag, sd_alg_str,
                            hash_key_data);
        }
        else
        {
            EVP_PKEY_free(classical_key);
            EVP_PKEY_free(pqc_key);
            error("Unsupported algorithm for SRK table 0");
        }
    }
    else
    {
        if ((strcmp(pqc_alg_name, "dilithium3") == 0) ||
            (strcmp(pqc_alg_name, "dilithium5") == 0))
        {
            srk_entry_dilithium(target, pqc_key, srk, ca_flag, sd_alg_str,
                                hash_key_data);
        }
        else if ((strcmp(pqc_alg_name, "mldsa65") == 0) ||
                 (strcmp(pqc_alg_name, "mldsa87") == 0))
        {
            srk_entry_mldsa(target, pqc_key, srk, ca_flag, sd_alg_str,
                            hash_key_data);
        }
        else
        {
            error("Unsupported algorithm for SRK table 1");
        }
    }

    EVP_PKEY_free(classical_key);
    EVP_PKEY_free(pqc_key);
}
#endif

/*--------------------------
  digest_alg_tag
---------------------------*/
uint32_t
digest_alg_tag(const char *digest_alg)
{
    uint32_t algorithm = 0;

    if (digest_alg)
    {
        if (strncasecmp((digest_alg), HASH_ALG_SHA1,
                        sizeof(HASH_ALG_SHA1)) == 0)
        {
            algorithm = HAB_ALG_SHA1;
        }
        else if (strncasecmp((digest_alg), HASH_ALG_SHA256,
                             sizeof(HASH_ALG_SHA256)) == 0)
        {
            algorithm = HAB_ALG_SHA256;
        }
        else if (strncasecmp((digest_alg), HASH_ALG_SHA384,
                             sizeof(HASH_ALG_SHA384)) == 0)
        {
            algorithm = HAB_ALG_SHA384;
        }
        else if (strncasecmp((digest_alg), HASH_ALG_SHA512,
                             sizeof(HASH_ALG_SHA512)) == 0)
        {
            algorithm = HAB_ALG_SHA512;
        }
#if CST_WITH_PQC
        else if (strncasecmp((digest_alg), HASH_ALG_SHA3_256,
                             sizeof(HASH_ALG_SHA3_256)) == 0)
        {
            algorithm = HAB_ALG_SHA3_256;
        }
        else if (strncasecmp((digest_alg), HASH_ALG_SHA3_384,
                             sizeof(HASH_ALG_SHA3_384)) == 0)
        {
            algorithm = HAB_ALG_SHA3_384;
        }
        else if (strncasecmp((digest_alg), HASH_ALG_SHA3_512,
                             sizeof(HASH_ALG_SHA3_512)) == 0)
        {
            algorithm = HAB_ALG_SHA3_512;
        }
        else if (strncasecmp((digest_alg), HASH_ALG_SHAKE128_256, 8) == 0)
        {
            algorithm = HAB_ALG_SHAKE128_256;
        }
        else if (strncasecmp((digest_alg), HASH_ALG_SHAKE256_512, 8) == 0)
        {
            algorithm = HAB_ALG_SHAKE256_512;
        }
#endif
        else
        {
            error("Unsupported digest algorithm");
        }
    }
    else
    {
        error("Missing digest algorithm");
    }

    return algorithm;
}

/*--------------------------
  check_digest_alg
---------------------------*/
uint32_t
check_sign_digest_alg(const char *alg_str)
{
    uint32_t algorithm = digest_alg_tag(alg_str);

    if ((algorithm != HAB_ALG_SHA256) && (algorithm != HAB_ALG_SHA384) &&
        (algorithm != HAB_ALG_SHA512)
#if CST_WITH_PQC
        && (algorithm != HAB_ALG_SHA3_256) && (algorithm != HAB_ALG_SHA3_384) &&
        (algorithm != HAB_ALG_SHA3_512) &&
        (algorithm != HAB_ALG_SHAKE128_256) &&
        (algorithm != HAB_ALG_SHAKE256_512)
#endif
    )
    {
        error("Unsupported signature digest algorithm");
    }

    return algorithm;
}

/*--------------------------
  cert_to_srk_entry
---------------------------*/
srk_entry_t *cert_to_srk_entry(tgt_t target, const char *certificate_path,
                               uint8_t table_index, uint8_t entry_index,
                               const char *sd_alg_str, bool hash_key_data)
{
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    bool ca_flag = FALSE;
    srk_entry_t *srk_entry = NULL;

    srk_entry = (srk_entry_t *) malloc(sizeof(srk_entry_t));
    if (!srk_entry)
    {
        return NULL;
    }

    cert = read_certificate(certificate_path);
    if (cert == NULL)
    {
        free(srk_entry);
        return NULL;
    }

    pkey = X509_get_pubkey(cert);
    if (pkey == NULL)
    {
        X509_free(cert);
        free(srk_entry);
        return NULL;
    }

    ca_flag = (X509_check_ca(cert) == X509_CA_CERT) ? TRUE : FALSE;

    /* Set SRK entry index in table */
    srk_entry->index = entry_index;

    if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA ||
        EVP_PKEY_id(pkey) == EVP_PKEY_RSA_PSS)
    {
        srk_entry_pkcs1(target, pkey, srk_entry, ca_flag, sd_alg_str,
                        hash_key_data);
    }
    else if (EVP_PKEY_id(pkey) == EVP_PKEY_EC)
    {
        srk_entry_ec(target, pkey, srk_entry, ca_flag, sd_alg_str,
                     hash_key_data);
    }
#ifdef CST_WITH_PQC
    else if (EVP_PKEY_is_a(pkey, "dilithium3") ||
             EVP_PKEY_is_a(pkey, "dilithium5"))
    {
        srk_entry_dilithium(target, pkey, srk_entry, ca_flag, sd_alg_str,
                            hash_key_data);
    }
    else if (EVP_PKEY_is_a(pkey, "mldsa65") || EVP_PKEY_is_a(pkey, "mldsa87"))
    {
        srk_entry_mldsa(target, pkey, srk_entry, ca_flag, sd_alg_str,
                        hash_key_data);
    }
    else if (IS_HYBRID(EVP_PKEY_get0_type_name(pkey)))
    {
        srk_entry_hybrid(target, pkey, table_index, srk_entry, ca_flag,
                         sd_alg_str, hash_key_data);
    }
#endif
    else
    {
        error("Unsupported algorithm in X.509 certificate\n");
    }

    X509_free(cert);
    EVP_PKEY_free(pkey);

    return srk_entry;
}

/*--------------------------
  ahab_get_hash_size_by_hash_type
---------------------------*/
int32_t ahab_get_hash_size_by_hash_type(uint8_t hash_type)
{
    int32_t hash_size = -1;

    if (hash_type > MAX_SRK_HASH_TYPE)
    {
        return hash_size;
    }

    switch (hash_type)
    {
        case SRK_SHA256:
            hash_size = HASH_BYTES_SHA256;
            break;
        case SRK_SHA384:
            hash_size = HASH_BYTES_SHA384;
            break;
        case SRK_SHA512:
            hash_size = HASH_BYTES_SHA512;
            break;
        case SRK_SHA3_256:
            hash_size = HASH_BYTES_SHA3_256;
            break;
        case SRK_SHA3_384:
            hash_size = HASH_BYTES_SHA3_384;
            break;
        case SRK_SHA3_512:
            hash_size = HASH_BYTES_SHA3_512;
            break;
        case SRK_SHAKE128_256:
            hash_size = HASH_BYTES_SHAKE128_256;
            break;
        case SRK_SHAKE256_512:
            hash_size = HASH_BYTES_SHAKE256_512;
            break;
        default:
            break;
    }

    return hash_size;
}
