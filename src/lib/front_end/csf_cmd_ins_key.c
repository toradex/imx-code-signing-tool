// SPDX-License-Identifier: BSD-3-Clause
/*
 * (c) Freescale Semiconductor, Inc. 2011-2015. All rights reserved.
 * Copyright 2018-2025 NXP
 */

/*===========================================================================*/
/**
    @file    csf_cmd_ins_key.c

    @brief   Code signing tool's CSF command handler for commands
             install key, install csfk and install srk.
 */

/*===========================================================================
                                INCLUDE FILES
=============================================================================*/
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#define HAB_FUTURE
#include <hab_cmd.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl_helper.h>
#include <misc_helper.h>
#include "srk_helper.h"
#include "err.h"
/*===========================================================================
                                MACROS
=============================================================================*/
#define HAB4_INSTALL_KEY_CMD_CERT_OFFSET    (8)     /**< Offset to cert data */
/*===========================================================================
                          LOCAL FUNCTION DECLARATIONS
=============================================================================*/
static int32_t process_installkey_arguments(
    command_t *cmd, char **cert_file, int32_t *src_index, int32_t *tgt_index,
    int32_t *hash_alg, int32_t *cert_format, char **key_file,
    int32_t *key_length, uint32_t *blob_address, char **src, int32_t *perm,
    char **sign, int32_t *src_set, int32_t *revocations,
    uint32_t *key_identifier, uint32_t *image_indexes, triple_t *perm_data,
    quadruple_t *uuid, uint8_t *fuse_version, uint8_t *check_all_signatures,
    uint8_t *fast_boot);

static int32_t hab4_install_key(int32_t src_index, int32_t tgt_index,
        int32_t hash_alg, int32_t cert_format, uint8_t* crt_hash,
        size_t hash_len, uint8_t* buf, int32_t* cmd_len);

static int32_t hab4_install_secret_key(int32_t src_index, int32_t tgt_index,
        uint32_t blob_address, uint8_t *buf, int32_t *cmd_len);

extern int g_no_ca;

extern int32_t g_srk_set_hab4;

/*===========================================================================
                             LOCAL FUNCTION DEFINITIONS
=============================================================================*/
/**
 * process arguments list for install key command
 *
 * @par Purpose
 *
 * Scan through the arguments list for the command and return requested
 * argument values. The sender will send a valid pointer to return the
 * value. If pointer is NULL then sender is not interested in that argument.
 *
 * @par Operation
 *
 * @param[in] cmd, the command is only used to get arguments list
 *
 * @param[out] cert_file, returns pointer to string for arg FILENAME
 *
 * @param[out] src_index, returns value for arg SOURCEINDEX
 *
 * @param[out] tgt_index, returns value for arg TARGETINDEX
 *
 * @param[out] hash_alg, returns value for arg HASHALGORITHM
 *
 * @param[out] cert_format, returns value for arg CERTIFICATEFORMAT
 *
 * @param[out] key_file, returns pointer to string for arg KEY
 *
 * @param[out] key_length, returns value for arg KEYLENGTH
 *
 * @param[out] blob_address, returns value for arg BLOBADDRESS
 *
 * @param[out] perm_data, returns value for arg PERMISSIONSDATA
 *
 * @param[out] uuid, returns value for arg UUID
 *
 * @param[out] fuse_version, returns value for arg FUSEVERSION
 *
 * @retval #SUCCESS  completed its task successfully
 */
static int32_t process_installkey_arguments(
    command_t *cmd, char **cert_file, int32_t *src_index, int32_t *tgt_index,
    int32_t *hash_alg, int32_t *cert_format, char **key_file,
    int32_t *key_length, uint32_t *blob_address, char **src, int32_t *perm,
    char **sign, int32_t *src_set, int32_t *revocations,
    uint32_t *key_identifier, uint32_t *image_indexes, triple_t *perm_data,
    quadruple_t *uuid, uint8_t *fuse_version, uint8_t *check_all_signatures,
    uint8_t *fast_boot)
{
    uint32_t i;                      /**< Loop index        */
    argument_t *arg = cmd->argument; /**< Ptr to argument_t */

    bool flag_fname         = false;
    bool flag_src_vfy_idx   = false;
    bool flag_tgt_idx       = false;
    bool flag_hsh_alg       = false;
    bool flag_crt_fmt       = false;
    bool flag_key           = false;
    bool flag_key_len       = false;
    bool flag_blob          = false;
    bool flag_src           = false;
    bool flag_perm          = false;
    bool flag_sig           = false;
    bool flag_src_set       = false;
    bool flag_revoc         = false;
    bool flag_key_id        = false;
    bool flag_img_idx       = false;
    bool flag_perm_data = false;
    bool flag_uuid = false;
    bool flag_fuse_version = false;
    bool flag_check_all_signatures = false;
    bool flag_fast_boot = false;

    for(i=0; i<cmd->argument_count; i++)
    {
        switch((arguments_t)arg->type)
        {
        case Filename:
            ERR_IF_INIT_MULT_TIMES(flag_fname);
            if(cert_file != NULL)
                *cert_file = arg->value.keyword->string_value;
            else
            {
                log_arg_cmd(arg->type, NULL, cmd->type);
                return ERROR_UNSUPPORTED_ARGUMENT;
            }
            break;
        case SourceIndex:
        case VerificationIndex:
            ERR_IF_INIT_MULT_TIMES(flag_src_vfy_idx);
            if(src_index != NULL)
                *src_index = arg->value.number->num_value;
            else
            {
                log_arg_cmd(arg->type, NULL, cmd->type);
                return ERROR_UNSUPPORTED_ARGUMENT;
            }
            break;
        case TargetIndex:
            ERR_IF_INIT_MULT_TIMES(flag_tgt_idx);
            if(tgt_index != NULL)
                *tgt_index = arg->value.number->num_value;
            else
            {
                log_arg_cmd(arg->type, NULL, cmd->type);
                return ERROR_UNSUPPORTED_ARGUMENT;
            }
            break;
        case HashAlgorithm:
            ERR_IF_INIT_MULT_TIMES(flag_hsh_alg);
            if(hash_alg != NULL)
                *hash_alg = arg->value.keyword->unsigned_value;
            else
            {
                log_arg_cmd(arg->type, NULL, cmd->type);
                return ERROR_UNSUPPORTED_ARGUMENT;
            }
            break;
        case CertificateFormat:
            ERR_IF_INIT_MULT_TIMES(flag_crt_fmt);
            if (cert_format != NULL)
                *cert_format = arg->value.keyword->unsigned_value;
            else
            {
                log_arg_cmd(arg->type, NULL, cmd->type);
                return ERROR_UNSUPPORTED_ARGUMENT;
            }
            break;
        case Key:
            ERR_IF_INIT_MULT_TIMES(flag_key);
            if(key_file != NULL)
            {
                *key_file = arg->value.keyword->string_value;
            }
            else
            {
                log_arg_cmd(arg->type, NULL, cmd->type);
                return ERROR_UNSUPPORTED_ARGUMENT;
            }
            break;
        case KeyLength:
            ERR_IF_INIT_MULT_TIMES(flag_key_len);
            if (key_length != NULL)
            {
                *key_length = arg->value.number->num_value;
            }
            else
            {
                log_arg_cmd(arg->type, NULL, cmd->type);
                return ERROR_UNSUPPORTED_ARGUMENT;
            }
            break;
        case BlobAddress:
            ERR_IF_INIT_MULT_TIMES(flag_blob);
            if (blob_address != NULL)
            {
                *blob_address = arg->value.number->num_value;
            }
            else
            {
                log_arg_cmd(arg->type, NULL, cmd->type);
                return ERROR_UNSUPPORTED_ARGUMENT;
            }
            break;
        case Source:
            ERR_IF_INIT_MULT_TIMES(flag_src);
            if(src != NULL)
                *src = arg->value.keyword->string_value;
            else
            {
                log_arg_cmd(arg->type, NULL, cmd->type);
                return ERROR_UNSUPPORTED_ARGUMENT;
            }
            break;
        case Permissions:
            ERR_IF_INIT_MULT_TIMES(flag_perm);
            if (perm != NULL)
            {
                *perm = arg->value.number->num_value;
            }
            else
            {
                log_arg_cmd(arg->type, NULL, cmd->type);
                return ERROR_UNSUPPORTED_ARGUMENT;
            }
            break;
        case PermissionsData:
            ERR_IF_INIT_MULT_TIMES(flag_perm_data);
            if (perm_data != NULL)
            {
                perm_data->first = arg->value.triple->first;
                perm_data->second = arg->value.triple->second;
                perm_data->third = arg->value.triple->third;
            }
            else
            {
                log_arg_cmd(arg->type, NULL, cmd->type);
                return ERROR_UNSUPPORTED_ARGUMENT;
            }
            break;
        case Uuid:
            ERR_IF_INIT_MULT_TIMES(flag_uuid);
            if (uuid != NULL)
            {
                uuid->first = arg->value.quadruple->first;
                uuid->second = arg->value.quadruple->second;
                uuid->third = arg->value.quadruple->third;
                uuid->fourth = arg->value.quadruple->fourth;
            }
            else
            {
                log_arg_cmd(arg->type, NULL, cmd->type);
                return ERROR_UNSUPPORTED_ARGUMENT;
            }
            break;
        case FuseVersion:
            ERR_IF_INIT_MULT_TIMES(flag_fuse_version);
            if (fuse_version != NULL)
            {
                *fuse_version = arg->value.number->num_value;
            }
            else
            {
                log_arg_cmd(arg->type, NULL, cmd->type);
                return ERROR_UNSUPPORTED_ARGUMENT;
            }
            break;
        case Signature:
            ERR_IF_INIT_MULT_TIMES(flag_sig);
            if(sign != NULL)
                *sign = arg->value.keyword->string_value;
            else
            {
                log_arg_cmd(arg->type, NULL, cmd->type);
                return ERROR_UNSUPPORTED_ARGUMENT;
            }
            break;
        case SourceSet:
            ERR_IF_INIT_MULT_TIMES(flag_src_set);
            if (src_set != NULL)
            {
                *src_set = arg->value.keyword->unsigned_value;
            }
            else
            {
                log_arg_cmd(arg->type, NULL, cmd->type);
                return ERROR_UNSUPPORTED_ARGUMENT;
            }
            break;
        case Revocations:
            ERR_IF_INIT_MULT_TIMES(flag_revoc);
            if (revocations != NULL)
            {
                *revocations = arg->value.number->num_value;
            }
            else
            {
                log_arg_cmd(arg->type, NULL, cmd->type);
                return ERROR_UNSUPPORTED_ARGUMENT;
            }
            break;
        case KeyIdentifier:
            ERR_IF_INIT_MULT_TIMES(flag_key_id);
            if (key_identifier != NULL)
            {
                *key_identifier = arg->value.number->num_value;
            }
            else
            {
                log_arg_cmd(arg->type, NULL, cmd->type);
                return ERROR_UNSUPPORTED_ARGUMENT;
            }
            break;
        case ImageIndexes:
            ERR_IF_INIT_MULT_TIMES(flag_img_idx);
            if (image_indexes != NULL)
            {
                *image_indexes = arg->value.number->num_value;
            }
            else
            {
                log_arg_cmd(arg->type, NULL, cmd->type);
                return ERROR_UNSUPPORTED_ARGUMENT;
            }
            break;
        case CheckAllSignatures:
            ERR_IF_INIT_MULT_TIMES(flag_check_all_signatures);
            if (check_all_signatures != NULL)
            {
                *check_all_signatures = arg->value.keyword->unsigned_value;
            }
            else
            {
                log_arg_cmd(arg->type, NULL, cmd->type);
                return ERROR_UNSUPPORTED_ARGUMENT;
            }
            break;
        case FastBoot:
            ERR_IF_INIT_MULT_TIMES(flag_fast_boot);
            if (fast_boot != NULL)
            {
                *fast_boot = arg->value.number->num_value;
            }
            else
            {
                log_arg_cmd(arg->type, NULL, cmd->type);
                return ERROR_UNSUPPORTED_ARGUMENT;
            }
            break;
        default:
            log_arg_cmd(arg->type, NULL, cmd->type);
            return ERROR_UNSUPPORTED_ARGUMENT;
        };

        arg = arg->next; /* go to next argument */
    }

    return SUCCESS;
}

/**
 * Updates buf[] with HAB4 install key command
 *
 * @par Purpose
 *
 * This function is called for HAB4 to generate command bytes for install srk,
 * install csfk and install key (imgk) commands. The function copies crt_hash
 * bytes to the buffer at offset INS_KEY_BASE_BYTES and calls INS_KEY macro
 * to generate bytes for install key command and copies them into buf. Function
 * returns command length in cmd_len argument.
 *
 * @par Operation
 *
 * @param[in] src_index, source index to use in the command
 *
 * @param[in] tgt_index, target index to use in the command
 *
 * @param[in] hash_alg, hash algorithm to use for calculating hash length
 *
 * @param[in] cert_format, certificate format an argument for the command
 *
 * @param[in] crt_hash, the hash bytes of the certificate, this will be
 *            appended to the command if pointer is not null.
 *
 * @param[out] buf, address of buffer where csf command will be generated
 *
 * @param[out] cmd_len, returns length of entire command
 *
 * @retval #SUCCESS  completed its task successfully
 */
static int32_t hab4_install_key(int32_t src_index, int32_t tgt_index, int32_t hash_alg,
             int32_t cert_format, uint8_t* crt_hash, size_t hash_len, uint8_t* buf,
             int32_t* cmd_len)
{
    int32_t flag = HAB_CMD_INS_KEY_CLR;   /**< Let flag be set for relative
                                               addresses */

    if(tgt_index == HAB_IDX_CSFK || tgt_index == HAB_IDX_CSFK1)
        flag |= HAB_CMD_INS_KEY_CSF;

    *cmd_len = INS_KEY_BASE_BYTES;

    if(crt_hash && hash_alg != HAB_ALG_ANY)
    {
        /* include hash bytes */
        memcpy(&buf[INS_KEY_BASE_BYTES], crt_hash, hash_len);

        *cmd_len += hash_len;
    }
    {
        uint8_t ins_key_cmd[] = {
            INS_KEY(*cmd_len, flag, cert_format, hash_alg,
                src_index, tgt_index, 0)
        };                     /**< Macro will output install key
                                    command bytes in aut_csf buffer */
        memcpy(buf, ins_key_cmd, INS_KEY_BASE_BYTES);
    }
    return SUCCESS;
}

/**
 * Updates buf[] install secret key command
 *
 * @par Purpose
 *
 * This function is called for HAB ver > 4.0 to generate command bytes for
 * install secret key command. The function copies the command bytes into buf.
 * Function returns command length in cmd_len argument.
 *
 * @par Operation
 *
 * @param[in] src_index, source index to use in the command
 *
 * @param[in] tgt_index, target index to use in the command
 *
 * @param[in] blob_address, 32 bit absolute address of blob location
 *
 * @param[out] buf, address of buffer where csf command will be generated
 *
 * @param[out] cmd_len, returns length of entire command
 *
 * @pre function should be called for HAB version >= 4.1
 *
 * @retval #SUCCESS  completed its task successfully
 */
static int32_t hab4_install_secret_key(int32_t src_index, int32_t tgt_index,
          uint32_t blob_address, uint8_t *buf, int32_t *cmd_len)
{
    *cmd_len = INS_KEY_BASE_BYTES;

    {
        uint8_t ins_key_cmd[] = {
            INS_KEY(INS_KEY_BASE_BYTES, HAB_CMD_INS_KEY_ABS, HAB_PCL_BLOB,
                HAB_ALG_ANY, src_index, tgt_index, blob_address)
        };                     /**< Macro will output install key
                                    command bytes in ins_key_cmd buffer */
        memcpy(buf, ins_key_cmd, INS_KEY_BASE_BYTES);
    }
    return SUCCESS;
}
/*===========================================================================
                             GLOBAL FUNCTION DEFINITIONS
=============================================================================*/
/**
 * Handler to install srk command
 *
 * @par Purpose
 *
 * Collects necessary arguments from csf file, validate the arguments, set
 * default values for arguments if missing from csf file.
 * For HAB4 only, it calls hab4_install_key to generate install key command
 * into csf buffer. It also calls save_file_data to read certificate data into
 * memory and save the pointer of memory into command.
 *
 * @par Operation
 *
 * @param[in] cmd, the csf command
 *
 * @retval #SUCCESS  completed its task successfully
 *
 * @retval #ERROR_INSUFFICIENT_ARGUMENTS, if necassary args are missing in csf
 *
 * @retval #ERROR_INVALID_ARGUMENT, passed in arguments are invalid or do not
 *          make sense
 *
 * @retval Errors returned by hab4_install_key
 */
int32_t cmd_handler_installsrk(command_t* cmd)
{
    int32_t ret_val = SUCCESS;  /**< Used for returning error value */
    int32_t src_index = -1;     /**< Hold cmd's source index argument value */
    int32_t hash_alg = -1;      /**< Holds hash algorithm argument value */
    int32_t cert_format = -1;   /**< Holds certificate format argument value */
    int32_t cmd_len = 0;        /**< Used to keep track of cmd length */
    int32_t src_set = -1;       /**< Holds source set argument value */
    int32_t revocations = -1;   /**< Holds revocation mask argument value */
    int8_t check_all_signatures =
        -1; /**< Holds signature verification policy value */
    int8_t fast_boot = -1; /**< Holds fast boot argument value */
    char *key_cert = NULL;
    uint32_t srk_idx;
    struct ahab_container_srk_table_array_s *srk_array = NULL;
    struct ahab_container_srk_table_s *srk_table = NULL;
    struct ahab_container_srk_s *srk_entry = NULL;
    struct ahab_container_srk_data_s *srk_data = NULL;
    uint8_t *srk_key_data = NULL;
    size_t num_tables = 1;
    size_t srk_table_offset = 0;
    uint8_t *sd_alg_str = NULL;
    srk_entry_t *temp_srk_entry = NULL;

    PRINT_V("Install SRK\n");

    /* get the arguments */
    /* srk key cert is at index 0 */

    if (IS_AHAB(g_target))
    {
        ret_val = process_installkey_arguments(
            cmd, &g_ahab_data.srk_file, &src_index, NULL, NULL, NULL, NULL,
            NULL, NULL, &g_ahab_data.srk_entry, NULL, NULL, &src_set,
            &revocations, NULL, NULL, NULL, NULL, NULL, &check_all_signatures,
            &fast_boot);
    }
    else
    {
        ret_val = process_installkey_arguments(
            cmd, &key_cert, &src_index, NULL, &hash_alg, &cert_format, NULL,
            NULL, NULL, NULL, NULL, NULL, &src_set, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL);
    }

    if(ret_val != SUCCESS)
    {
        return ret_val;
    }

    do {
        if (IS_AHAB(g_target))
        {
            byte_str_t srk_buff = {NULL, 0};

            if (NULL == g_ahab_data.srk_file)
            {
                log_arg_cmd(Filename, NULL, cmd->type);
                ret_val = ERROR_INSUFFICIENT_ARGUMENTS;
                break;
            }

            /* Read the srk table file into temporary buffer */
            /*** NOTE: read_file() allocates memory that must be freed ***/
            read_file(g_ahab_data.srk_file, &srk_buff, NULL);

            g_ahab_data.srk_buff = srk_buff.entry;
            g_ahab_data.srk_buff_size = srk_buff.entry_bytes;

            if (!g_ahab_data.srk_buff || g_ahab_data.srk_buff_size <= 0)
            {
                log_arg_cmd(Filename, NULL, cmd->type);
                ret_val = ERROR_INSUFFICIENT_MEMORY;
                break;
            }

            if (IS_AHAB_2(g_target))
            {

                srk_array =
                    (struct ahab_container_srk_table_array_s *) (g_ahab_data
                                                                     .srk_buff);

                if ((srk_array->tag != SRK_TABLE_ARRAY_TAG) ||
                    (srk_array->version != SRK_TABLE_ARRAY_VERSION))
                {
                    log_arg_cmd(Filename, g_ahab_data.srk_file, cmd->type);
                    ret_val = ERROR_INVALID_SRK_TABLE;
                    free(g_ahab_data.srk_buff);
                    break;
                }

                num_tables = srk_array->number_srk_table;
                srk_table_offset = sizeof(ahab_container_srk_table_array_t);
            }
            else if (IS_AHAB_1(g_target))
            {
                srk_table_offset = 0;
                num_tables = 1; /* Only one SRK table for AHAB 1 */
            }

            if (num_tables > CNTN_MAX_NR_SRK_TABLE)
            {
                log_arg_cmd(Filename, NULL, cmd->type);
                ret_val = ERROR_INVALID_SRK_TABLE;
                break;
            }

            for (size_t i = 0; i < num_tables; i++)
            {
                srk_table = (struct ahab_container_srk_table_s
                                 *) ((uint8_t *) g_ahab_data.srk_buff +
                                     srk_table_offset);

                if ((srk_table->tag != SRK_TABLE_TAG) ||
                    ((IS_AHAB_2(g_target) &&
                      srk_table->version != SRK_TABLE_VERSION_2) ||
                     (IS_AHAB_1(g_target) &&
                      srk_table->version != SRK_TABLE_VERSION_1)))
                {
                    log_arg_cmd(Filename, g_ahab_data.srk_file, cmd->type);
                    ret_val = ERROR_INVALID_SRK_TABLE;
                    free(g_ahab_data.srk_buff);
                    break;
                }

                if (IS_AHAB_2(g_target))
                {

                    /* Fill key data field in SRK Data */
                    srk_entry =
                        (struct ahab_container_srk_s
                             *) ((uint8_t *) srk_table +
                                 sizeof(struct ahab_container_srk_table_s));
                    srk_data =
                        (struct ahab_container_srk_data_s
                             *) ((uint8_t *) srk_table + srk_table->length);

                    if ((srk_data->tag != SRK_DATA_TAG) ||
                        (srk_data->version != SRK_DATA_VERSION))
                    {
                        log_arg_cmd(Filename, g_ahab_data.srk_file, cmd->type);
                        ret_val = ERROR_INVALID_SRK_TABLE;
                        free(g_ahab_data.srk_buff);
                        break;
                    }

                    srk_key_data = (uint8_t *) srk_data +
                                   sizeof(struct ahab_container_srk_data_s);

                    switch (srk_entry->hash_alg)
                    {
                        case SRK_SHA256:
                            sd_alg_str = "sha256";
                            break;
                        case SRK_SHA384:
                            sd_alg_str = "sha384";
                            break;
                        case SRK_SHA512:
                            sd_alg_str = "sha512";
                            break;
#if CST_WITH_PQC
                        case SRK_SHA3_256:
                            sd_alg_str = "sha3-256";
                            break;
                        case SRK_SHA3_384:
                            sd_alg_str = "sha3-384";
                            break;
                        case SRK_SHA3_512:
                            sd_alg_str = "sha3-512";
                            break;
                        case SRK_SHAKE128_256:
                            sd_alg_str = "shake128";
                            break;
                        case SRK_SHAKE256_512:
                            sd_alg_str = "shake256";
                            break;
#endif
                        default:
                            log_arg_cmd(Filename, g_ahab_data.srk_file,
                                        cmd->type);
                            ret_val = ERROR_INVALID_SRK_TABLE;
                            free(g_ahab_data.srk_buff);
                            break;
                    }

                    /* Build an SRK entry from the provided certificate */
                    temp_srk_entry =
                        cert_to_srk_entry(g_target, g_ahab_data.srk_entry, i,
                                          src_index, sd_alg_str, false);

                    if (!temp_srk_entry)
                    {
                        log_arg_cmd(Source, g_ahab_data.srk_file, cmd->type);
                        ret_val = ERROR_INVALID_PKEY_CERTIFICATE;
                        free(g_ahab_data.srk_buff);
                        break;
                    }

                    /* Copy key data */
                    if (srk_data->length >
                        (temp_srk_entry->entry_bytes -
                         sizeof(struct ahab_container_srk_s)))
                    {
                        memcpy(srk_key_data,
                               (uint8_t *) temp_srk_entry->entry +
                                   sizeof(struct ahab_container_srk_s),
                               temp_srk_entry->entry_bytes -
                                   sizeof(struct ahab_container_srk_s));
                    }
                    else
                    {
                        log_arg_cmd(Filename, g_ahab_data.srk_file, cmd->type);
                        ret_val = ERROR_INSUFFICIENT_MEMORY;
                        free(g_ahab_data.srk_buff);
                        free(temp_srk_entry->entry);
                        temp_srk_entry->entry = NULL;
                        free(temp_srk_entry);
                        temp_srk_entry = NULL;
                        break;
                    }

                    /* Free allocated buffer */
                    free(temp_srk_entry->entry);
                    temp_srk_entry->entry = NULL;
                    free(temp_srk_entry);
                    temp_srk_entry = NULL;

                    srk_data->srk_record_number = src_index;

                    /* Next table */
                    srk_table_offset += srk_table->length + srk_data->length;
                }
            }

            /* Break here if we run out error */
            if (ret_val != SUCCESS)
            {
                return ret_val;
            }

            if (src_index == -1)
            {
                log_arg_cmd(SourceIndex, NULL, cmd->type);
                ret_val = ERROR_INSUFFICIENT_ARGUMENTS;
                break;
            }
            else if (src_index < 0 || src_index > 3)
            {
                log_arg_cmd(SourceIndex, " must be between 0 and 3", cmd->type);
                ret_val = ERROR_INVALID_ARGUMENT;
                break;
            }
            else
            {
                g_ahab_data.srk_index = src_index;
            }
            if (src_set == -1)
            {
                log_arg_cmd(SourceSet, NULL, cmd->type);
                ret_val = ERROR_INSUFFICIENT_ARGUMENTS;
                break;
            }
            else if ((src_set != SRK_SET_OEM) && (src_set != SRK_SET_NXP))
            {
                log_arg_cmd(SourceSet, " must be equal to OEM or NXP", cmd->type);
                ret_val = ERROR_INVALID_ARGUMENT;
                break;
            }
            else
            {
                g_ahab_data.srk_set = (src_set == SRK_SET_NXP) ?
                                      HEADER_FLAGS_SRK_SET_NXP :
                                      HEADER_FLAGS_SRK_SET_OEM;
            }
            if (revocations == -1)
            {
                log_arg_cmd(Revocations, NULL, cmd->type);
                ret_val = ERROR_INSUFFICIENT_ARGUMENTS;
                break;
            }
            else if (revocations < 0 || revocations > 0xF)
            {
                log_arg_cmd(Revocations, " must define a 4-bit bitmask", cmd->type);
                ret_val = ERROR_INVALID_ARGUMENT;
                break;
            }
            else
            {
                g_ahab_data.revocations = revocations;
            }

            if (IS_AHAB_2(g_target))
            {
                if (check_all_signatures == -1)
                {
                    /* If not set then apply default fuse policy */
                    g_ahab_data.check_all_signatures =
                        HEADER_FLAGS_CHECK_ALL_SIGNATURES_FUSE;
                }
                else if ((check_all_signatures != CHECK_ALL_SIGNATURES_FUSE) &&
                         (check_all_signatures != CHECK_ALL_SIGNATURES_ALL))
                {
                    log_arg_cmd(CheckAllSignatures,
                                " must be equal to 'Fuse' or 'All'", cmd->type);
                    ret_val = ERROR_INVALID_ARGUMENT;
                    break;
                }
                else
                {
                    g_ahab_data.check_all_signatures =
                        (check_all_signatures == CHECK_ALL_SIGNATURES_FUSE)
                            ? HEADER_FLAGS_CHECK_ALL_SIGNATURES_FUSE
                            : HEADER_FLAGS_CHECK_ALL_SIGNATURES_ALL;
                }

                if (fast_boot == -1)
                {
                    /* Hash&Copyand Use external accelerator accelerator */
                    /* are both disabled by default */
                    g_ahab_data.fast_boot = 0;
                }
                else if (fast_boot < 0 || fast_boot > 0x7)
                {
                    log_arg_cmd(FastBoot, " must define a 3-bit bitmask",
                                cmd->type);
                    ret_val = ERROR_INVALID_ARGUMENT;
                    break;
                }
                else
                {
                    g_ahab_data.fast_boot = fast_boot;
                }
            }
        }
        else
        if(g_hab_version >= HAB4)
        {
            /* SRK set */
            if (src_set == -1)
            {
                src_set = SRK_SET_OEM;
            }
            else if ((src_set != SRK_SET_OEM) && (src_set != SRK_SET_NXP))
            {
                log_arg_cmd(SourceSet, " must be equal to OEM or NXP", cmd->type);
                ret_val = ERROR_INVALID_ARGUMENT;
                break;
            }
            g_srk_set_hab4 = src_set;

            srk_idx = (g_srk_set_hab4 == SRK_SET_OEM) ? HAB_IDX_SRK : HAB_IDX_SRK1;

            g_key_certs[srk_idx] = key_cert;

            /* validate the arguments */
            if(g_key_certs[srk_idx] == NULL)
            {
                log_arg_cmd(Filename, NULL, cmd->type);
                ret_val = ERROR_INSUFFICIENT_ARGUMENTS;
                break;
            }
            if(src_index == -1)
            {
                log_arg_cmd(SourceIndex, NULL, cmd->type);
                ret_val = ERROR_INSUFFICIENT_ARGUMENTS;
                break;
            }
            else if (src_index < SRC_IDX_INS_KEY_MIN || src_index > SRC_IDX_INS_KEY_MAX)
            {
                log_arg_cmd(SourceIndex, NULL, cmd->type);
                ret_val = ERROR_INVALID_ARGUMENT;
                break;
            }

            /* certificate format is not an option */
            if(cert_format != -1)
            {
                log_arg_cmd(CertificateFormat, NULL, cmd->type);
                ret_val = ERROR_INVALID_ARGUMENT;
                break;
            }
            /* set the defaults if not provided */
            if(cert_format == -1)
                cert_format = HAB_PCL_SRK;
            if(hash_alg == -1)
                hash_alg = g_hash_alg;

            /* Read data from cert and save the data pointer into command */
            ret_val = save_file_data(cmd, g_key_certs[srk_idx], NULL, 0,
                0, NULL, NULL, hash_alg);
            if(ret_val != SUCCESS)
                break;

            /* Check for valid tag and HAB version in Super Root Key table
             * saved at cmd->cert_sig_data
             */
            if((cmd->cert_sig_data[SRK_TABLE_TAG_OFFSET] != HAB_TAG_CRT) || \
               (cmd->cert_sig_data[SRK_TABLE_VER_OFFSET] != HAB4))
            {
                ret_val = ERROR_INVALID_SRK_TABLE;
                log_error_msg(g_key_certs[srk_idx]);
                break;
            }
            cmd->start_offset_cert_sig = g_csf_buffer_index +
                HAB4_INSTALL_KEY_CMD_CERT_OFFSET;

            /* generate INS_SRK command */
            ret_val = hab4_install_key(src_index, srk_idx,
                hash_alg, cert_format, NULL, 0,
                &g_csf_buffer[g_csf_buffer_index], &cmd_len);
            if(ret_val != SUCCESS)
                break;

            g_csf_buffer_index += cmd_len;
        }
    } while(0);

    return ret_val;
}

/**
 * Handler to install csfk command
 *
 * @par Purpose
 *
 * Collects necessary arguments from csf file, validate the arguments, set
 * default values for arguments if missing from csf file.
 * For HAB4 only, it calls hab4_install_key to generate install key command
 * into csf buffer. It also calls save_file_data to read certificate data into
 * memory and save the pointer of memory into command.
 *
 * @par Operation
 *
 * @param[in] cmd, the csf command
 *
 * @retval #SUCCESS  completed its task successfully
 *
 * @retval #ERROR_INSUFFICIENT_ARGUMENTS, if necassary args are missing in csf
 *
 * @retval #ERROR_INVALID_ARGUMENT, passed in arguments are invalid or do not
 *          make sense
 *
 * @retval Errors returned by hab4_install_key
 */
int32_t cmd_handler_installcsfk(command_t* cmd)
{
    int32_t ret_val = SUCCESS;  /**< Used for returning error value */
    int32_t cert_format = -1;   /**< Holds certificate format argument value */
    int32_t cmd_len = 0;        /**< Used to keep track of cmd length */
    uint8_t *cert_data = NULL;  /**< DER encoded certificate data */
    int32_t cert_len = 0;       /**< length of certificate data */

    uint32_t srk_idx = (g_srk_set_hab4 == SRK_SET_OEM) ? HAB_IDX_SRK : HAB_IDX_SRK1;
    uint32_t csfk_idx = (g_srk_set_hab4 == SRK_SET_OEM) ? HAB_IDX_CSFK : HAB_IDX_CSFK1;

    /* The Install CSFK command is invalid when AHAB is targeted */
    if (IS_AHAB(g_target))
    {
        log_cmd(cmd->type, STR_ILLEGAL);
        return ERROR_INVALID_COMMAND;
    }

    PRINT_V("Install CSFK\n");

    /* get the arguments */
    /* csf key is at index 1 */
    ret_val = process_installkey_arguments(
        cmd, &g_key_certs[csfk_idx], NULL, NULL, NULL, &cert_format, NULL, NULL,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL);

    if(ret_val != SUCCESS)
    {
        return ret_val;
    }

    /* generate install key csf command */
    do {
        if(g_hab_version >= HAB4)
        {
            /* validate the arguments */
            if(g_key_certs[csfk_idx] == NULL)
            {
                log_arg_cmd(Filename, NULL, cmd->type);
                ret_val = ERROR_INSUFFICIENT_ARGUMENTS;
                break;
            }
            if(cert_format == HAB_PCL_SRK)
            {
                log_arg_cmd(CertificateFormat, NULL, cmd->type);
                ret_val = ERROR_INVALID_ARGUMENT;
                break;
            }
            /* set the defaults if not provided */
            if(cert_format == -1)
                cert_format = g_cert_format;

            /* Read data from cert and save the data pointer into command */
            cert_len = get_der_encoded_certificate_data(
                g_key_certs[csfk_idx], &cert_data);
            if(cert_len == 0)
            {
                ret_val = ERROR_INVALID_PKEY_CERTIFICATE;
                log_error_msg(g_key_certs[csfk_idx]);
                break;
            }

            ret_val = save_file_data(cmd, NULL, cert_data, cert_len,
                1, NULL, NULL, HAB_ALG_ANY);
            if(ret_val != SUCCESS)
                break;

            cmd->start_offset_cert_sig = g_csf_buffer_index +
                HAB4_INSTALL_KEY_CMD_CERT_OFFSET;

            /* generate INS_CSFK command */
            ret_val = hab4_install_key(srk_idx,
                csfk_idx, HAB_ALG_ANY, cert_format, NULL, 0,
                &g_csf_buffer[g_csf_buffer_index], &cmd_len);
            if(ret_val != SUCCESS)
                break;
            g_csf_buffer_index += cmd_len;
        }
    } while(0);

    return ret_val;
}

/**
 * Handler to install NOCAk command
 *
 * @par Purpose
 *
 * Collects necessary arguments from csf file, validate the arguments, set
 * default values for arguments if missing from csf file.
 * For HAB4 only, this is the same as cmd_handler_installcsfk(), except it
 * does not generate and write the install key command in the csf buffer.
 *
 * @par Operation
 *
 * @param[in] cmd, the csf command
 *
 * @retval #SUCCESS  completed its task successfully
 *
 * @retval #ERROR_INSUFFICIENT_ARGUMENTS, if necassary args are missing in csf
 *
 * @retval #ERROR_INVALID_ARGUMENT, passed in arguments are invalid or do not
 *          make sense
 *
 * @retval Errors returned by hab4_install_key
 */
int32_t cmd_handler_installnocak(command_t* cmd)
{
    int32_t ret_val = SUCCESS;  /**< Used for returning error value */
    int32_t cert_format = -1;   /**< Holds certificate format argument value */
    int32_t cmd_len = 0;        /**< Used to keep track of cmd length */
    uint8_t *cert_data = NULL;  /**< DER encoded certificate data */
    int32_t cert_len = 0;       /**< length of certificate data */

    uint32_t csfk_idx = HAB_IDX_CSFK;

   /* The Install NOCAK command is invalid when AHAB is targeted */
    if (IS_AHAB(g_target))
    {
        log_cmd(cmd->type, STR_ILLEGAL);
        return ERROR_INVALID_COMMAND;
    }

    PRINT_V("Install no CAK\n");

    g_no_ca = 1;
    /* get the arguments */
    /* csf key is at index 1 */
    ret_val = process_installkey_arguments(
        cmd, &g_key_certs[csfk_idx], NULL, NULL, NULL, &cert_format, NULL, NULL,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL);

    if(ret_val != SUCCESS)
    {
        return ret_val;
    }

    /* generate install key csf command */
    do {
        if(g_hab_version >= HAB4)
        {
            /* validate the arguments */
            if(g_key_certs[csfk_idx] == NULL)
            {
                log_arg_cmd(Filename, NULL, cmd->type);
                ret_val = ERROR_INSUFFICIENT_ARGUMENTS;
                break;
            }
            if(cert_format == HAB_PCL_SRK)
            {
                log_arg_cmd(CertificateFormat, NULL, cmd->type);
                ret_val = ERROR_INVALID_ARGUMENT;
                break;
            }
            /* set the defaults if not provided */
            if(cert_format == -1)
                cert_format = g_cert_format;

            /* Read data from cert and save the data pointer into command */
            cert_len = get_der_encoded_certificate_data(
                g_key_certs[csfk_idx], &cert_data);
            if(cert_len == 0)
            {
                ret_val = ERROR_INVALID_PKEY_CERTIFICATE;
                log_error_msg(g_key_certs[csfk_idx]);
                break;
            }

            ret_val = save_file_data(cmd, NULL, cert_data, cert_len,
                1, NULL, NULL, HAB_ALG_ANY);
            if(ret_val != SUCCESS)
                break;

            cmd->start_offset_cert_sig = g_csf_buffer_index +
                HAB4_INSTALL_KEY_CMD_CERT_OFFSET;

            g_csf_buffer_index += cmd_len;
        }
    } while(0);

    return ret_val;
}

/**
 * Handler to install imgk command
 *
 * @par Purpose
 *
 * Collects necessary arguments from csf file, validate the arguments, set
 * default values for arguments if missing from csf file.
 * For HAB4 it calls hab4_install_key to generate install key command
 * into csf buffer. It also calls save_file_data to read certificate data into
 * memory and save the pointer of memory into command.
 *
 * @par Operation
 *
 * @param[in] cmd, the csf command
 *
 * @retval #SUCCESS  completed its task successfully
 *
 * @retval #ERROR_INSUFFICIENT_ARGUMENTS, if necassary args are missing in csf
 *
 * @retval #ERROR_INVALID_ARGUMENT, passed in arguments are invalid or do not
 *          make sense
 *
 * @retval Errors returned by hab4_install_key
 */
int32_t cmd_handler_installkey(command_t* cmd)
{
    int32_t ret_val = SUCCESS;  /**< Used for returning error value */
    int32_t vfy_index = -1;     /**< Holds verification index argument value */
    int32_t tgt_index = -1;     /**< Holds target index argument value */
    int32_t hash_alg = -1;      /**< Holds hash algorithm argument value */
    int32_t cert_format = -1;   /**< Holds certificate format argument value */
    uint8_t *crt_hash = NULL;   /**< Buffer for certificate hash bytes */
    size_t hash_len = 0;        /**< Number of hash bytes in crt_hash */
    int32_t cmd_len = 0;        /**< Used to keep track of cmd length */
    char * img_key_crt = NULL;  /**< Points to image key file name */
    uint8_t *cert_data = NULL;  /**< DER encoded certificate data */
    int32_t cert_len = 0;       /**< length of certificate data */

    /* The Install Key command is invalid when AHAB is targeted */
    if (IS_AHAB(g_target))
    {
        log_cmd(cmd->type, STR_ILLEGAL);
        return ERROR_INVALID_COMMAND;
    }

    PRINT_V("Install key\n");

    /* get the arguments */
    ret_val = process_installkey_arguments(
        cmd, &img_key_crt, &vfy_index, &tgt_index, &hash_alg, &cert_format,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL);

    if(ret_val != SUCCESS)
    {
        return ret_val;
    }

    /* generate install key csf command */
    do {
        if(g_hab_version >= HAB4)
        {
            /* validate the arguments */
            if(img_key_crt == NULL)
            {
                log_arg_cmd(Filename, NULL, cmd->type);
                ret_val = ERROR_INSUFFICIENT_ARGUMENTS;
                break;
            }
            if(vfy_index == -1)
            {
                log_arg_cmd(VerificationIndex, NULL, cmd->type);
                ret_val = ERROR_INSUFFICIENT_ARGUMENTS;
                break;
            }
            else if ((vfy_index != VFY_IDX_INS_KEY_SRK) && \
	             (vfy_index < VFY_IDX_INS_KEY_MIN || vfy_index > VFY_IDX_INS_KEY_MAX))
            {
                log_arg_cmd(VerificationIndex, NULL, cmd->type);
                ret_val = ERROR_INVALID_ARGUMENT;
                break;
            }

            if(tgt_index == -1)
            {
                log_arg_cmd(TargetIndex, NULL, cmd->type);
                ret_val = ERROR_INSUFFICIENT_ARGUMENTS;
                break;
            }
            if(
                tgt_index == HAB_IDX_SRK
                || tgt_index == HAB_IDX_CSFK
                || tgt_index == HAB_IDX_SRK1
                || tgt_index == HAB_IDX_CSFK1
            ) {
                log_arg_cmd(TargetIndex, NULL, cmd->type);
                ret_val = ERROR_INVALID_ARGUMENT;
                break;
            }
            if(cert_format == HAB_PCL_SRK)
            {
                log_arg_cmd(CertificateFormat, NULL, cmd->type);
                ret_val = ERROR_INVALID_ARGUMENT;
                break;
            }

            if(tgt_index >= HAB_KEY_PUBLIC_MAX)
            {
                log_arg_cmd(TargetIndex, STR_EXCEED_MAX, cmd->type);
                ret_val = ERROR_INVALID_ARGUMENT;
                break;
            }
            /* set the defaults if not provided */
            if(cert_format == -1)
                cert_format = g_cert_format;
            if(hash_alg == -1)
                hash_alg = HAB_ALG_ANY;

            /* Save the file name pointer at tgt_index of g_key_certs */
            g_key_certs[tgt_index] = img_key_crt;

            /* Read data from cert and save the data pointer into command */
            cert_len = get_der_encoded_certificate_data(img_key_crt,
                &cert_data);
            if(cert_len == 0)
            {
                ret_val = ERROR_INVALID_PKEY_CERTIFICATE;
                log_error_msg(img_key_crt);
                break;
            }

            ret_val = save_file_data(cmd, NULL, cert_data, cert_len,
                1, NULL, NULL, HAB_ALG_ANY);
            if(ret_val != SUCCESS)
                break;

            cmd->start_offset_cert_sig = g_csf_buffer_index +
                HAB4_INSTALL_KEY_CMD_CERT_OFFSET;

            /* generate INS_IMGK command */
            ret_val = hab4_install_key(vfy_index, tgt_index,
                hash_alg, cert_format, crt_hash, hash_len,
                &g_csf_buffer[g_csf_buffer_index], &cmd_len);
            if(ret_val != SUCCESS)
                break;

            g_csf_buffer_index += cmd_len;
        }
    } while(0);

    if(crt_hash)
        free (crt_hash);

    return ret_val;
}

/**
 * Handler to install secret key command
 *
 * @par Purpose
 *
 * Collects necessary arguments from csf file, validate the arguments, set
 * default values for arguments if missing from csf file.
 * This command is applicable from HAB 4.1 onwards and only on processors
 * which include CAAM and SNVS. Each instance of this command generates a
 * CSF command to install a secret key in CAAM's secret key store with
 * protocol set to HAB_PCL_BLOB. The blob is unwrapped using a master key
 * encryption key (KEK) supplied by SNVS. A random key is generated.
 * The key is  encrypted by the CST back end, only if a a certificate was provided.
 * This file is intended for later use by the mfgtool
 * to create the blob. The encryption is done with public key certificate
 * passed to CST on command line. Crt_hash is not generated for this command
 * as it is not required by HAB.
 *
 * @par Operation
 *
 * @param[in] cmd, the csf command
 *
 * @retval #SUCCESS  completed its task successfully
 *
 * @retval #ERROR_INSUFFICIENT_ARGUMENTS, if necassary args are missing in csf
 *
 * @retval #ERROR_INVALID_ARGUMENT, passed in arguments are invalid or do not
 *          make sense
 */
int32_t cmd_handler_installsecretkey(command_t* cmd)
{
    int32_t ret_val = SUCCESS;      /**< Used for returning error value */
    int32_t vfy_index = -1;         /**< Holds verification index argument value */
    int32_t tgt_index = -1;         /**< Holds target index argument value */
    int32_t cmd_len = 0;            /**< Used to keep track of cmd length */
    char * secret_key = NULL;       /**< Points to secret key file name */
    uint32_t blob_address = 0;      /**< Memory location for blob data */
    int32_t key_length = -1;        /**< Holds key length argument value */
    uint32_t key_identifier = 0;    /**< Holds key identifier value (default 0) */
    uint32_t images_indexes = 0xFFFFFFFF; /**< Holds indexes of image to be encrypted (default all) */

    PRINT_V("Install Secret Key\n");

    /* get the arguments */
    if (IS_HAB(g_target))
    {
        /* This command is supported from HAB 4.1 onwards */
        if(g_hab_version <= HAB4)
        {
            ret_val = ERROR_INVALID_COMMAND;
            return ret_val;
        }

        ret_val = process_installkey_arguments(
            cmd, NULL, &vfy_index, &tgt_index, NULL, NULL, &secret_key,
            &key_length, &blob_address, NULL, NULL, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL, NULL, NULL);
    }
    else {
        ret_val = process_installkey_arguments(
            cmd, NULL, NULL, NULL, NULL, NULL, &secret_key, &key_length, NULL,
            NULL, NULL, NULL, NULL, NULL, &key_identifier, &images_indexes,
            NULL, NULL, NULL, NULL, NULL);
    }

    if(ret_val != SUCCESS)
    {
        return ret_val;
    }

    /* generate install secret key command */
    do {
        /* validate the arguments */

        /* Output key file is a must */
        if(secret_key == NULL)
        {
            log_arg_cmd(Key, NULL, cmd->type);
            ret_val = ERROR_INSUFFICIENT_ARGUMENTS;
            break;
        }

        if (IS_HAB(g_target))
        {
            /* Target index is a must */
            if(tgt_index == -1)
            {
                log_arg_cmd(TargetIndex, NULL, cmd->type);
                ret_val = ERROR_INSUFFICIENT_ARGUMENTS;
                break;
            }
            /* Blob address is also needed */
            if(blob_address == 0)
            {
                log_arg_cmd(BlobAddress, NULL, cmd->type);
                ret_val = ERROR_INSUFFICIENT_ARGUMENTS;
                break;
            }
            /* Target index cannot be greater than max allowed */
            if(tgt_index >= HAB_KEY_SECRET_MAX)
            {
                log_arg_cmd(TargetIndex, STR_EXCEED_MAX, cmd->type);
                ret_val = ERROR_INVALID_ARGUMENT;
                break;
            }
            /* set the defaults if not provided */
            if(vfy_index == -1)
            {
                vfy_index = HAB_SNVS_OTPMK;
            }
            else
            {
                if(vfy_index > HAB_SNVS_CMK)
                {
                    log_arg_cmd(VerificationIndex, STR_EXCEED_MAX, cmd->type);
                    ret_val = ERROR_INVALID_ARGUMENT;
                    break;
            }
            }
        }

       /* Valid values for Key_length: 128, 192 and 256 */
        if(key_length == -1)
        {
            /* Default to 128 bits */
            key_length = AES_KEY_LEN_128;
        }
        else
        {
            /* Check for invalid length */
            if((key_length != AES_KEY_LEN_128) &&
               (key_length != AES_KEY_LEN_192) &&
               (key_length != AES_KEY_LEN_256))
            {
                log_arg_cmd(KeyLength, STR_ILLEGAL, cmd->type);
                ret_val = ERROR_INVALID_ARGUMENT;
                break;
            }
        }

        if (IS_HAB(g_target))
        {
            /* Calculate dek length in bytes and save secret_key name */
            g_aes_keys[tgt_index].key_bytes = (key_length / BYTE_SIZE_BITS);
            g_aes_keys[tgt_index].key_file = secret_key;

            /* Generate Install key command for the secret key */
            ret_val = hab4_install_secret_key(vfy_index, tgt_index,
                blob_address, &g_csf_buffer[g_csf_buffer_index], &cmd_len);
            if(ret_val != SUCCESS)
                break;

            g_csf_buffer_index += cmd_len;
        }
        else {
            g_ahab_data.dek = secret_key;
            g_ahab_data.dek_length = (key_length / BYTE_SIZE_BITS);
            g_ahab_data.key_identifier = key_identifier;
            g_ahab_data.image_indexes = images_indexes;
        }
    } while(0);

    return ret_val;
}

/**
 * Handler to install Certificate command
 *
 * @par Purpose
 *
 * Collects necessary arguments from csf file, validate the arguments, set
 * default values for arguments if missing from csf file.
 * This command is applicable from AHAB onwards.
 *
 * @par Operation
 *
 * @param[in] cmd, the csf command
 *
 * @retval #SUCCESS  completed its task successfully
 *
 * @retval #ERROR_INSUFFICIENT_ARGUMENTS, if necassary args are missing in csf
 *
 * @retval #ERROR_INVALID_ARGUMENT, passed in arguments are invalid or do not
 *          make sense
 */
int32_t cmd_handler_installcrt(command_t* cmd)
{
    int32_t ret_val;          /**< Used for returning error value   */
    int32_t permissions = -1; /**< Holds permissions argument value */

    /* The Install Certificate command is invalid when AHAB is not targeted */
    if (IS_HAB(g_target))
    {
        log_cmd(cmd->type, STR_ILLEGAL);
        return ERROR_INVALID_COMMAND;
    }

    PRINT_V("Install Certificate\n");

    /* get the arguments */
    ret_val = process_installkey_arguments(
        cmd, &g_ahab_data.certificate, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, &permissions, &g_ahab_data.cert_sign, NULL, NULL, NULL, NULL,
        &g_ahab_data.permissions_data, &g_ahab_data.uuid,
        &g_ahab_data.fuse_version, NULL, NULL);

    if (SUCCESS != ret_val)
    {
        return ret_val;
    }

    do {
        /* validate the arguments */
        if (NULL == g_ahab_data.certificate)
        {
            log_arg_cmd(Filename, NULL, cmd->type);
            ret_val = ERROR_INSUFFICIENT_ARGUMENTS;
            break;
        }
        if (-1 == permissions)
        {
            log_arg_cmd(Permissions, NULL, cmd->type);
            ret_val = ERROR_INSUFFICIENT_ARGUMENTS;
            break;
        }
        else if (0xFF < permissions)
        {
            log_arg_cmd(Permissions, STR_GREATER_THAN_255, cmd->type);
            ret_val = ERROR_INVALID_ARGUMENT;
            break;
        }
        else
        {
            g_ahab_data.permissions = EXTRACT_BYTE(permissions, 0);
        }
    } while(0);

    return ret_val;
}
