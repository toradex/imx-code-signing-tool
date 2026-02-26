// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

/*===========================================================================*/
/**
 *   @file    ahab_signed_message.c
 *
 *   @brief   Generate Signed Message for AHAB devices
 *
 */

/*===========================================================================
                                INCLUDE FILES
=============================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <getopt.h>
#include <unistd.h>
#include <json-c/json.h>
#include "version.h"

/*===========================================================================
                               LOCAL CONSTANTS
=============================================================================*/

#define INITIAL_WORD_COUNT \
    128 /**< Initial number of words to be allocated for an output buffer */

const char *g_tool_name = "ahab_signed_message"; /**< Global holds tool name */
const char *g_tool_version = CST_VERSION; /**< Global holds tool version */

#define AHAB_FIPS_KEY_ZEROIZATION 0xC3
#define AHAB_FIPS_CLUSTER_DEGRADE 0xB5
#define AHAB_RETURN_LIFECYCLE_UPDATE 0xA0
#define AHAB_ENABLE_DEBUG 0x94
#define AHAB_WRITE_SEC_FUSE 0x91
#define SAB_KEY_EXCHANGE_KEK_GENERATION_EN 0x03
#define SAB_ROOT_KEY_ENCRYPTION_KEY_EXPORT_EN 0x02
#define SAB_KEY_STORE_SEC_PROV 0x01

/*===========================================================================
                  LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
=============================================================================*/

/* Structure to hold field data */
typedef struct
{
    const char *name;          /**< Field name */
    const char *format;        /**< Field format (word:size:position) */
    const char *default_value; /**< Field default value */
} field_info_t;

/* Structure to hold message payload structure */
typedef struct
{
    field_info_t *fields /**< All message payload fields */;
    const char **required_fields /**< Required message payload fields */;
} message_payload_fields_t;

/*===========================================================================
                          LOCAL FUNCTION PROTOTYPES
=============================================================================*/
/**
 * @brief Processes a single field and updates the output data structures
 * accordingly.
 *
 * @param[in] field           Pointer to the field_info_t structure representing
 *                            the field to be processed.
 * @param[in] container_obj   Pointer to a JSON object that contains the field
 *                            value.
 * @param[out] output_words   Pointer to an array where the processed field data
 *                            will be stored.
 * @param[in,out] word_count  Pointer to a size_t variable that will be updated
 *                            with the number of words processed.
 * @param[in] verbose         Integer flag that enables verbose output if set to
 *                            a non-zero value.
 */
static void process_single_field(const field_info_t *field,
                                 struct json_object *container_obj,
                                 uint32_t *output_words, size_t *word_count,
                                 int verbose);

/**
 * @brief Processes the given fields and populates the output words and word
 * count.
 *
 * @param[in] fields        Pointer to an array of field_info_t structures
 *                          representing the fields to be processed.
 * @param[in] container_obj Pointer to a JSON object that contains the data
 *                          required for processing the fields.
 * @param[out] output_words Pointer to an array where the processed output words
 *                          will be stored.
 * @param[in,out] word_count Pointer to a size_t variable that will be updated
 *                           with the total count of processed words.
 * @param[in] verbose       Integer flag that enables verbose output if set to a
 *                          non-zero value.
 */
static void process_fields(const field_info_t *fields,
                           struct json_object *container_obj,
                           uint32_t *output_words, size_t *word_count,
                           int verbose);

/**
 * @brief Processes the fields of a message payload, storing the output in a
 * dynamically allocated buffer.
 *
 * @param[in] fields        Pointer to a message_payload_fields_t structure
 *                          containing the fields of the message payload.
 * @param[in] message_obj   Pointer to the JSON object representing the message
 *                          payload.
 * @param[out] output_words Pointer to a pointer to a buffer where the processed
 *                          words will be stored.
 * @param[out] word_count   Pointer to a size_t variable where the number of
 *                          processed words will be stored.
 * @param[in] verbose       Integer flag to control verbosity of the function's
 *                          output (e.g., 0 for silent, >0 for verbose).
 *
 * @note The buffer for `output_words` is dynamically allocated within this
 *       function. The caller is responsible for freeing this memory.
 *
 * @exception Exits the program with a failure code if any error occurs (e.g.,
 *            missing required fields, memory allocation failures).
 */
static void process_message_payload_fields(message_payload_fields_t *fields,
                                           struct json_object *message_obj,
                                           uint32_t **output_words,
                                           size_t *word_count, int verbose);

/**
 * @brief Processes a message payload from a file and extracts relevant
 * information.
 *
 * @param[in] message_payload_file  Path to the file containing the message
 *                                  payload.
 * @param[out] message_words        Pointer to a pointer to an array where the
 *                                  processed message words will be stored.
 * @param[out] message_word_count   Pointer to a size_t variable where the total
 *                                  count of processed message words will be
                                    stored.
 * @param[out] message_desc         Double pointer to a JSON object where the
 *                                  message description will be stored.
 * @param[in] verbose               Integer flag that enables verbose output if
 *                                  set to a non-zero value.
 */
static void process_message_payload(const char *message_payload_file,
                                    uint32_t **message_words,
                                    size_t *message_word_count,
                                    struct json_object **message_desc,
                                    int verbose);

/**
 * @brief Prints information about the message, including its ID and name.
 *
 * @param[in] payload Pointer to the message_payload_fields_t structure
 *                    containing the fields.
 */
static void print_message_payload_info(message_payload_fields_t *payload);

/**
 * @brief Initializes the message header fields.
 *
 * @param[out] fields  Pointer to an array of field_info_t structures that will
 *                     be initialized.
 */
static void initialize_message_header_fields(field_info_t *fields);

/**
 * @brief Generates a signed message by processing a message template and a
 * message payload.
 *
 * @param[in] message_template_file       Path to the JSON file containing the
 *                                        message template.
 * @param[in] message_payload_file        Path to the file containing the
 *                                        message payload.
 * @param[out] container_header_words     Pointer to a pointer to a buffer where
 *                                        the container header words will be
 *                                        stored.
 * @param[out] container_header_word_count Pointer to a size_t variable where
 *                                         the number of container header words
 *                                         will be stored.
 * @param[out] message_words              Pointer to a pointer to a buffer where
 *                                        the message words will be stored.
 * @param[out] message_word_count         Pointer to a size_t variable where the
 *                                        number of message words will be stored.
 * @param[in] verbose                     Integer flag to control verbosity of
 *                                        the function's output (e.g., 0 for
 *                                        silent, >0 for verbose).
 *
 * @note The buffers for `container_header_words` and `message_words` are
 *       dynamically allocated within this function. The caller is responsible for
 *       freeing this memory.
 *
 * @exception Exits the program with a failure code if any error occurs (e.g.,
 *            file I/O errors, memory allocation failures).
 */
static void generate_signed_message(const char *message_template_file,
                                    const char *message_payload_file,
                                    uint32_t **container_header_words,
                                    size_t *container_header_word_count,
                                    uint32_t **message_words,
                                    size_t *message_word_count, int verbose);

/**
 * @brief Calculates the offset for the signature block based on the message
 *        payload size.
 *
 * @param[in] message_payload_word_count  The number of words in the message
 *                                        payload.
 *
 * @return The calculated offset for the signature block as a 16-bit unsigned
 *         integer.
 */
static uint16_t
calculate_signature_block_offset(size_t message_payload_word_count);

/**
 * @brief Reverses the order of elements in a byte array.
 *
 * @param[in,out] array   Pointer to the byte array to be reversed.
 * @param[in] length      The number of elements in the array.
 */
static void reverse_byte_array(uint8_t *array, size_t length);

/**
 * @brief Handles an error by displaying a message and performing error-specific
 * actions.
 *
 * @param[in] message  A string containing the error message to be displayed or
 *                     logged.
 * @param[in] code     An integer error code that specifies the type of error or
 *                     action to be taken.
 */
static void handle_error(const char *message, int code);

/**
 * @brief Prints the tool version.
 */
static void print_version();

/**
 * @brief Prints the usage information for the program.
 */
static void print_usage();

/*===========================================================================
                               LOCAL VARIABLES
=============================================================================*/

/* Container Header fields */
static field_info_t container_header_fields[] = {
    {"version", "0:0:8", "0x0"},
    {"length", "0:8:16", "0x0"},
    {"tag", "0:24:8", "0x89"},
    {"flags", "1:0:32", "0x0"},
    {"SW version", "2:0:16", "0x0"},
    {"fuse version", "2:16:8", "0x0"},
    {"unused", "2:24:8", "0x0"},
    {"signature block offset", "3:0:16", "0x0"},
    {"unused2", "3:16:16", "0x0"},
    {NULL, NULL, NULL}};

/* Message Descriptor + Message header fields */
static field_info_t message_descriptor_header_fields[] = {
    {"flags", "0:0:8", "0x0"},
    {"reserved", "0:8:24", "0x0"},
    {"IV", "1:0:256",
     "0000000000000000000000000000000000000000000000000000000000000000"},
    {"issue date", "9:0:16", "0x0"},
    {"permission", "9:16:8", "0x0"},
    {"cert version", "9:24:8", "0x0"},
    {"monotonic counter", "10:0:16", "0x0"},
    {"Id", "10:16:8", "0x0"},
    {"reserved2", "10:24:8", "0x0"},
    {"UID", "11:0:64", "0000000000000000"},
    {NULL, NULL, NULL}};

/* HAB_FIPS_KEY_ZEROIZATION (0xC3) */
static message_payload_fields_t fips_key_zeroization_req_fields = {
    .fields =
        (field_info_t[]){{"Id", "0xc3", NULL},
                         {"message", "AHAB_FIPS_KEY_ZEROIZATION_REQ", NULL},
                         {"size", "1", NULL},
                         {"zeroization_target", "0:0:32", NULL},
                         {NULL, NULL, NULL}},
    .required_fields = (const char *[]){"zeroization_target", NULL}};

/* AHAB_RETURN_LIFECYCLE_UPDATE (0xB5) */
static message_payload_fields_t fips_cluster_degrade_req_fields = {
    .fields =
        (field_info_t[]){{"Id", "0xb5", NULL},
                         {"message", "AHAB_FIPS_CLUSTER_DEGRADE_REQ", NULL},
                         {"size", "1", NULL},
                         {"fips_degrade_target", "0:0:32", NULL},
                         {NULL, NULL, NULL}},
    .required_fields = (const char *[]){"fips_degrade_target", NULL}};

/* AHAB_RETURN_LIFECYCLE_UPDATE (0xA0) */
static message_payload_fields_t return_lifecycle_update_fields = {
    .fields =
        (field_info_t[]){{"Id", "0xa0", NULL},
                         {"message", "AHAB_RETURN_LIFECYCLE_UPDATE_REQ", NULL},
                         {"size", "1", NULL},
                         {"lifecycle", "0:0:16", NULL},
                         {"unused", "0:16:16", NULL},
                         {NULL, NULL, NULL}},
    .required_fields = (const char *[]){"lifecycle", "unused", NULL}};

/* AHAB_ENABLE_DEBUG  (0x94) */
static message_payload_fields_t enable_debug_fields = {
    .fields = (field_info_t[]){{"Id", "0x94", NULL},
                               {"message", "AHAB_ENABLE_DEBUG_REQ", NULL},
                               {"size", "1", NULL},
                               {"domain", "0:0:8", NULL},
                               {"debug vector", "0:8:8", NULL},
                               {"unused", "0:16:16", NULL},
                               {NULL, NULL, NULL}},
    .required_fields =
        (const char *[]){"domain", "debug vector", "unused", NULL}};

/* AHAB_WRITE_SEC_FUSE  (0x91) */
static message_payload_fields_t write_secure_fuse_fields = {
    .fields = (field_info_t[]){{"Id", "0x91", NULL},
                               {"message", "AHAB_WRITE_SEC_FUSE_REQ", NULL},
                               {"min size", "2", NULL},
                               {"fuse", "0:0:16", NULL},
                               {"fuse length", "0:16:8", NULL},
                               {"flags", "0:24:8", NULL},
                               {"fuse data", "1:0:32", NULL},
                               {NULL, NULL, NULL}},
    .required_fields =
        (const char *[]){"fuse", "fuse length", "flags", "fuse data", NULL}};

/* SAB_KEY_EXCHANGE_KEK_GENERATION_EN (0x03) */
static message_payload_fields_t sab_key_exchange_kek_gen_en_fields = {
    .fields = (field_info_t[]){{"Id", "0x03", NULL},
                               {"message",
                                "SAB_KEY_EXCHANGE_KEK_GENERATION_EN_REQ", NULL},
                               {"size", "3", NULL},
                               {"key_store_id", "0:0:32", NULL},
                               {"user_sab_id", "1:0:32", NULL},
                               {"target", "2:0:8", NULL},
                               {"unused", "2:8:24", NULL},
                               {NULL, NULL, NULL}},
    .required_fields = (const char *[]){"key_store_id", "user_sab_id", "target",
                                        "unused", NULL}};

/* SAB_ROOT_KEY_ENCRYPTION_KEY_EXPORT_EN (0x02) */
static message_payload_fields_t sab_key_import_key_export_en_fields = {
    .fields = (field_info_t[]){{"Id", "0x02", NULL},
                               {"message", "SAB_ROOT_KEK_EXPORT_REQ", NULL},
                               {"size", "1", NULL},
                               {"flags", "0:0:8", NULL},
                               {"unused", "0:8:24", NULL},
                               {NULL, NULL, NULL}},
    .required_fields = (const char *[]){"flags", "unused", NULL}};

/* SAB_KEY_STORE_SEC_PROV (0x01) */
static message_payload_fields_t sab_key_store_sec_provisioning_fields = {
    .fields = (field_info_t[]){{"Id", "0x01", NULL},
                               {"message", "SAB_KEY_STORE_SEC_PROV_REQ", NULL},
                               {"size", "3", NULL},
                               {"key_store_id", "0:0:32", NULL},
                               {"flags", "1:0:8", NULL},
                               {"unused", "1:8:24", NULL},
                               {"user_sab_id", "2:0:32", NULL},
                               {NULL, NULL, NULL}},
    .required_fields = (const char *[]){"key_store_id", "flags", "unused",
                                        "user_sab_id", NULL}};

/*===========================================================================
                               GLOBAL VARIABLES
=============================================================================*/

/*===========================================================================
                               LOCAL FUNCTIONS
=============================================================================*/

/*--------------------------
  process_single_field
---------------------------*/
void process_single_field(const field_info_t *field,
                          struct json_object *container_obj,
                          uint32_t *output_words, size_t *word_count,
                          int verbose)
{
    struct json_object *field_value_obj = NULL;
    const char *field_value_str = NULL;
    int field_fmt_lst[3] = {0, 0, 0};
    int word_index = 0;
    uint32_t field_value = 0;
    int bit_position = 0;
    int remaining_bits = 0;
    size_t hex_len = 0;
    size_t expected_len = 0;
    size_t j = 0;
    uint32_t byte_value = 0;
    int bits_to_write = 0;
    uint8_t *byte_array = NULL;

    sscanf(field->format, "%d:%d:%d", &field_fmt_lst[0], &field_fmt_lst[1],
           &field_fmt_lst[2]);

    /* Check if the field exists in the JSON object */
    if (json_object_object_get_ex(container_obj, field->name, &field_value_obj))
    {
        field_value_str = json_object_get_string(field_value_obj);
        if (verbose)
        {
            printf("Using provided value for field %s: %s\n", field->name,
                   field_value_str);
        }
    }
    else if (field->default_value)
    {
        /* If the field doesn't exist, use the default value if provided */
        field_value_str = field->default_value;
        if (verbose)
        {
            printf("Using default value for missing field %s: %s\n",
                   field->name, field_value_str);
        }
    }
    else
    {
        /* If the field doesn't exist and there's no default value, skip
         * processing this field */
        if (verbose)
        {
            printf("Skipping missing field %s with no default value\n",
                   field->name);
        }
        return;
    }

    /* Handle fields up to 32 bits */
    if (field_fmt_lst[2] <= 32)
    {
        field_value = strtoul(field_value_str, NULL, 0);
        field_value &= (1U << field_fmt_lst[2]) - 1;
        output_words[field_fmt_lst[0]] |= field_value << field_fmt_lst[1];

        /* Ensure the word count reflects the highest word index used */
        if (*word_count <= field_fmt_lst[0])
        {
            *word_count = field_fmt_lst[0] + 1;
        }
    }
    else
    { /* Handle fields larger than 32 bits */
        bit_position = field_fmt_lst[1];
        remaining_bits = field_fmt_lst[2];
        word_index = field_fmt_lst[0];

        hex_len = strlen(field_value_str);
        expected_len =
            (remaining_bits + 3) / 4; /* Calculate expected hex string length */
        if (hex_len != expected_len)
        {
            fprintf(stderr,
                    "Error: Field %s must have a size of %d bits, found %zu "
                    "characters\n",
                    field->name, remaining_bits, hex_len);
            exit(EXIT_FAILURE);
        }

        byte_array = (uint8_t *) malloc(expected_len / 2 * sizeof(uint8_t));
        if (byte_array == NULL)
        {
            fprintf(stderr, "Error: Memory allocation failed for byte array\n");
            exit(EXIT_FAILURE);
        }

        for (j = 0; j < hex_len; j += 2)
        {
            sscanf(&field_value_str[j], "%2hhx", &byte_array[j / 2]);
        }

        /* Valid for UID */
        if (field_fmt_lst[2] == 64)
        {
            reverse_byte_array(byte_array, expected_len / 2);
        }

        /* Place the bytes into the correct bit positions across multiple words
         */
        for (j = 0; j < expected_len / 2; j++)
        {
            byte_value = byte_array[j];
            bits_to_write = (remaining_bits < 8) ? remaining_bits : 8;

            /* Mask and place the bits into the current word */
            output_words[word_index] |=
                (byte_value & ((1U << bits_to_write) - 1)) << bit_position;

            bit_position += bits_to_write;
            if (bit_position >= 32)
            {
                word_index++;
                bit_position = 0;
                /* Increment word_count when we move to a new word */
                (*word_count)++;
            }
            remaining_bits -= bits_to_write;
        }

        /* Final update to word_count if we didn't use the full word in the last
         * iteration */
        if (bit_position > 0)
        {
            word_index++;
            (*word_count)++;
        }

        free(byte_array);
    }
}

/*--------------------------
  process_fields
---------------------------*/
void process_fields(const field_info_t *fields,
                    struct json_object *container_obj, uint32_t *output_words,
                    size_t *word_count, int verbose)
{
    const field_info_t *field_info = NULL;
    for (field_info = fields; field_info->name != NULL; field_info++)
    {
        process_single_field(field_info, container_obj, output_words,
                             word_count, verbose);
    }
}

/*--------------------------
  process_message_payload_fields
---------------------------*/
void process_message_payload_fields(message_payload_fields_t *fields,
                                    struct json_object *message_obj,
                                    uint32_t **output_words, size_t *word_count,
                                    int verbose)
{

    uint32_t *tmp_output_words = NULL;
    int output_alloc_size = INITIAL_WORD_COUNT;
    const field_info_t *field_info = NULL;
    const char **required_field = NULL;

    print_message_payload_info(fields);

    tmp_output_words =
        (uint32_t *) malloc(INITIAL_WORD_COUNT * sizeof(uint32_t));
    if (tmp_output_words == NULL)
    {
        handle_error("Memory allocation failed for output_words", EXIT_FAILURE);
    }

    *word_count = 0;

    memset(tmp_output_words, 0, INITIAL_WORD_COUNT * sizeof(uint32_t));

    /* Process each field */
    for (field_info = fields->fields; field_info->name != NULL; field_info++)
    {
        /* Ensure there is enough space to store the processed word */
        if (*word_count >= output_alloc_size)
        {
            output_alloc_size *= 2;
            tmp_output_words = (uint32_t *) realloc(
                tmp_output_words, output_alloc_size * sizeof(uint32_t));
            if (tmp_output_words == NULL)
            {
                handle_error("Memory reallocation failed for output_words",
                             EXIT_FAILURE);
            }
        }

        process_single_field(field_info, message_obj, tmp_output_words,
                             word_count, verbose);
    }

    *output_words = tmp_output_words;

    /* Check for required fields */
    for (required_field = fields->required_fields; *required_field != NULL;
         required_field++)
    {
        if (strncmp(*required_field, "unused", 6) &&
            strncmp(*required_field, "reserved", 8) &&
            (!json_object_object_get_ex(message_obj, *required_field, NULL)))
        {
            fprintf(stderr,
                    "Error: Missing required field '%s' in the message\n",
                    *required_field);
            exit(EXIT_FAILURE);
        }
    }
}

/*--------------------------
  print_message_payload_info
---------------------------*/
void print_message_payload_info(message_payload_fields_t *payload)
{
    const char *message = NULL;
    const char *id = NULL;

    /* Iterate over the fields to find "message" and "Id" */
    for (field_info_t *field = payload->fields;
         field != NULL && field->name != NULL; ++field)
    {
        if (strcmp(field->name, "message") == 0)
        {
            message = field->format;
        }
        else if (strcmp(field->name, "Id") == 0)
        {
            id = field->format;
        }
    }

    if (message != NULL && id != NULL)
    {
        printf("%s (%s)\n", message, id);
    }
}

/*--------------------------
  process_message_payload
---------------------------*/
void process_message_payload(const char *message_payload_file,
                             uint32_t **message_payload_words,
                             size_t *message_payload_word_count,
                             struct json_object **message_desc, int verbose)
{
    FILE *fp = NULL;
    char *json_str = NULL;
    uint8_t message_id = 0;
    long file_size = 0;
    struct json_object *id_obj = NULL;
    struct json_object *temp_message_desc = NULL;
    size_t bytes_read = 0;

    if (message_payload_file == NULL || message_payload_words == NULL ||
        message_payload_word_count == NULL || message_desc == NULL)
    {
        handle_error("One or more arguments are NULL", EXIT_FAILURE);
    }

    *message_payload_word_count = 0;
    *message_desc = NULL;

    fp = fopen(message_payload_file, "r");
    if (fp == NULL)
    {
        handle_error("Error opening message file", EXIT_FAILURE);
    }

    if (fseek(fp, 0, SEEK_END) != 0)
    {
        perror("Error seeking to the end of the file");
        fclose(fp);
        return;
    }

    file_size = ftell(fp);
    if (file_size == -1L)
    {
        perror("Error determining file size");
        fclose(fp);
        return;
    }

    if (fseek(fp, 0, SEEK_SET) != 0)
    {
        perror("Error seeking to the start of the file");
        fclose(fp);
        return;
    }

    json_str = (char *) malloc(file_size + 1);
    if (json_str == NULL)
    {
        fclose(fp);
        handle_error("Memory allocation error", EXIT_FAILURE);
    }

    bytes_read = fread(json_str, 1, file_size, fp);
    if (bytes_read != file_size)
    {
        if (ferror(fp))
        {
            perror("Error reading file");
        }
        else if (feof(fp))
        {
            fprintf(stderr, "Unexpected end of file\n");
        }
        fclose(fp);
        free(json_str);
        return;
    }

    json_str[file_size] = '\0';
    fclose(fp);

    temp_message_desc = json_tokener_parse(json_str);
    if (temp_message_desc == NULL)
    {
        free(json_str);
        handle_error("Error parsing JSON message file", EXIT_FAILURE);
    }

    if (!json_object_object_get_ex(temp_message_desc, "Id", &id_obj))
    {
        json_object_put(temp_message_desc);
        free(json_str);
        handle_error("Id field not found in JSON message", EXIT_FAILURE);
    }

    message_id = strtol(json_object_get_string(id_obj), NULL, 16);

    /* Lookup the template and process the fields according to the template */
    if (message_id == AHAB_FIPS_KEY_ZEROIZATION)
    {
        *message_desc = temp_message_desc;
        process_message_payload_fields(&fips_key_zeroization_req_fields,
                                       *message_desc, message_payload_words,
                                       message_payload_word_count, verbose);
    }
    else if (message_id == AHAB_FIPS_CLUSTER_DEGRADE)
    {
        *message_desc = temp_message_desc;
        process_message_payload_fields(&fips_cluster_degrade_req_fields,
                                       *message_desc, message_payload_words,
                                       message_payload_word_count, verbose);
    }
    else if (message_id == AHAB_RETURN_LIFECYCLE_UPDATE)
    {
        *message_desc = temp_message_desc;
        process_message_payload_fields(&return_lifecycle_update_fields,
                                       *message_desc, message_payload_words,
                                       message_payload_word_count, verbose);
    }
    else if (message_id == AHAB_ENABLE_DEBUG)
    {
        *message_desc = temp_message_desc;
        process_message_payload_fields(&enable_debug_fields, *message_desc,
                                       message_payload_words,
                                       message_payload_word_count, verbose);
    }
    else if (message_id == AHAB_WRITE_SEC_FUSE)
    {
        *message_desc = temp_message_desc;
        process_message_payload_fields(&write_secure_fuse_fields, *message_desc,
                                       message_payload_words,
                                       message_payload_word_count, verbose);
    }
    else if (message_id == SAB_KEY_EXCHANGE_KEK_GENERATION_EN)
    {
        *message_desc = temp_message_desc;
        process_message_payload_fields(&sab_key_exchange_kek_gen_en_fields,
                                       *message_desc, message_payload_words,
                                       message_payload_word_count, verbose);
    }
    else if (message_id == SAB_ROOT_KEY_ENCRYPTION_KEY_EXPORT_EN)
    {
        *message_desc = temp_message_desc;
        process_message_payload_fields(&sab_key_import_key_export_en_fields,
                                       *message_desc, message_payload_words,
                                       message_payload_word_count, verbose);
    }
    else if (message_id == SAB_KEY_STORE_SEC_PROV)
    {
        *message_desc = temp_message_desc;
        process_message_payload_fields(&sab_key_store_sec_provisioning_fields,
                                       *message_desc, message_payload_words,
                                       message_payload_word_count, verbose);
    }
    else
    {
        fprintf(stderr, "Message Id: %s is not supported.\n",
                json_object_get_string(id_obj));
        json_object_put(temp_message_desc);
        free(json_str);
        exit(EXIT_FAILURE);
    }

    free(json_str);
}

/*--------------------------
  initialize_message_header_fields
---------------------------*/
void initialize_message_header_fields(field_info_t *fields)
{
    time_t t = 0;
    struct tm tm = {0};
    struct tm *tmp = NULL;
    int year = 0;
    int month = 0;
    static char issue_date_default[7] = {0};
    int i = 0;

    t = time(NULL);
    if (t == (time_t) -1)
    {
        perror("Error getting current time");
        return;
    }

    tmp = localtime(&t);
    if (tmp == NULL) {
        perror("Failed to convert time to local time");
        return;
    }
    
    tm = *tmp;

    year = tm.tm_year + 1900;
    month = tm.tm_mon + 1;

    snprintf(issue_date_default, sizeof(issue_date_default), "0x%04x",
             (month << 12) | (year & 0x0FFF));

    for (i = 0; fields[i].name != NULL; i++)
    {
        if (strcmp(fields[i].name, "issue date") == 0)
        {
            fields[i].default_value = issue_date_default;
        }
    }
}

/*--------------------------
  generate_signed_message
---------------------------*/
void generate_signed_message(const char *message_template_file,
                             const char *message_payload_file,
                             uint32_t **container_header_words,
                             size_t *container_header_word_count,
                             uint32_t **message_words,
                             size_t *message_word_count, int verbose)
{
    FILE *fp = NULL;
    char *json_str = NULL;
    struct json_object *container_obj = NULL;
    struct json_object *header_obj = NULL;
    struct json_object *message_obj = NULL;
    long file_size = 0;
    struct json_object *container_desc = NULL;
    struct json_object *message_desc = NULL;
    size_t i = 0;
    size_t message_payload_word_count = 0;
    uint32_t *message_payload_words = NULL;
    int message_alloc_size = INITIAL_WORD_COUNT;
    uint16_t signature_block_offset = 0;
    size_t bytes_read = 0;

    if (message_template_file == NULL || message_payload_file == NULL ||
        container_header_words == NULL || container_header_word_count == NULL ||
        message_words == NULL || message_word_count == NULL)
    {
        handle_error("One or more arguments are NULL", EXIT_FAILURE);
    }

    *container_header_words =
        (uint32_t *) malloc(INITIAL_WORD_COUNT * sizeof(uint32_t));
    if (*container_header_words == NULL)
    {
        handle_error("Memory allocation for container_header_words failed",
                     EXIT_FAILURE);
    }

    *message_words = (uint32_t *) malloc(INITIAL_WORD_COUNT * sizeof(uint32_t));
    if (*message_words == NULL)
    {
        free(*container_header_words);
        handle_error("Memory allocation for message_words failed",
                     EXIT_FAILURE);
    }

    memset(*container_header_words, 0, INITIAL_WORD_COUNT * sizeof(uint32_t));
    memset(*message_words, 0, INITIAL_WORD_COUNT * sizeof(uint32_t));

    *container_header_word_count = 0;
    *message_word_count = 0;

    fp = fopen(message_template_file, "r");
    if (fp == NULL)
    {
        handle_error("Error opening template file", EXIT_FAILURE);
    }

    if (fseek(fp, 0, SEEK_END) != 0)
    {
        perror("Error seeking to the end of the file");
        fclose(fp);
        return;
    }

    file_size = ftell(fp);
    if (file_size == -1L)
    {
        perror("Error determining file size");
        fclose(fp);
        return;
    }

    if (fseek(fp, 0, SEEK_SET) != 0)
    {
        perror("Error seeking to the start of the file");
        fclose(fp);
        return;
    }

    json_str = (char *) malloc(file_size + 1);
    if (json_str == NULL)
    {
        fclose(fp);
        handle_error("Memory allocation error", EXIT_FAILURE);
    }

    bytes_read = fread(json_str, 1, file_size, fp);
    if (bytes_read != file_size)
    {
        if (ferror(fp))
        {
            perror("Error reading file");
        }
        else if (feof(fp))
        {
            fprintf(stderr, "Unexpected end of file\n");
        }
        fclose(fp);
        free(json_str);
        return;
    }

    json_str[file_size] = '\0';
    fclose(fp);

    /* Parse template file */
    container_desc = json_tokener_parse(json_str);
    if (container_desc == NULL)
    {
        free(json_str);
        handle_error("Error parsing JSON container file", EXIT_FAILURE);
    }

    if (!json_object_object_get_ex(container_desc, "container", &container_obj))
    {
        json_object_put(container_desc);
        free(json_str);
        handle_error("Container object not found in JSON", EXIT_FAILURE);
    }

    /* Process container header fields */
    if (json_object_object_get_ex(container_obj, "header", &header_obj))
    {
        process_fields(container_header_fields, header_obj,
                       *container_header_words, container_header_word_count,
                       verbose);
    }

    /* Process message fields (descriptor + header + payload) */
    if (json_object_object_get_ex(container_obj, "message", &message_obj))
    {
        /* Process the message payload from the second argument */

        process_message_payload(message_payload_file, &message_payload_words,
                                &message_payload_word_count, &message_desc,
                                verbose);

        /* Merge message payload data with message descriptor and message header
         */
        json_object_object_foreach(message_desc, key, val)
        {
            json_object_object_add(message_obj, key, json_object_get(val));
        }

        /* Set signed message generation month and year */
        initialize_message_header_fields(message_descriptor_header_fields);

        /* Process message descriptor fields */
        process_fields(message_descriptor_header_fields, message_obj,
                       *message_words, message_word_count, verbose);

        /* Ensure there is enough space to append the message payload */
        if (*message_word_count + message_payload_word_count >
            message_alloc_size)
        {
            message_alloc_size =
                *message_word_count + message_payload_word_count;
            *message_words = (uint32_t *) realloc(
                *message_words, message_alloc_size * sizeof(uint32_t));
            if (*message_words == NULL)
            {
                free(message_payload_words);
                json_object_put(message_desc);
                json_object_put(container_desc);
                free(json_str);
                handle_error("Memory reallocation failed", EXIT_FAILURE);
            }
        }

        /* Append message payload words to message output */
        for (i = 0; i < message_payload_word_count; i++)
        {
            (*message_words)[(*message_word_count)++] =
                message_payload_words[i];
        }

        /* Calculate the signature block offset */
        signature_block_offset =
            calculate_signature_block_offset(message_payload_word_count);

        (*container_header_words)[3] |= signature_block_offset;

        free(message_payload_words);
    }

    /* Clean-up */
    json_object_put(message_desc);
    json_object_put(container_desc);
    free(json_str);
}

/*--------------------------
  calculate_signature_block_offset
---------------------------*/
uint16_t calculate_signature_block_offset(size_t message_payload_word_count)
{

    /* Message payload is padded to be on a 4 bytes boundary. */
    uint16_t offset = 68 + 4 * message_payload_word_count;

    /* message + container header must end on an 8 bytes boundary. */
    if (offset % 8 > 0)
    {
        offset += (8 - (offset % 8));
    }

    return offset;
}

/*--------------------------
  handle_error
---------------------------*/
void handle_error(const char *message, int code)
{
    fprintf(stderr, "%s\n", message);
    exit(code);
}

/*--------------------------
  reverse_byte_array
---------------------------*/
void reverse_byte_array(uint8_t *array, size_t length)
{
    size_t start = 0;
    size_t end = length - 1;
    while (start < end)
    {
        uint8_t temp = array[start];
        array[start] = array[end];
        array[end] = temp;
        start++;
        end--;
    }
}

/*--------------------------
  print_version
---------------------------*/
void print_version()
{
    printf("%s version %s\n", g_tool_name, g_tool_version);
}

/*--------------------------
  print_usage
---------------------------*/
void print_usage()
{
    printf("Usage: %s -t <message_template_file> -m <message_payload_file> "
           "[options]\n",
           g_tool_name);
    printf("Required options:\n");
    printf("  -t <message_template_file> Specify the template file\n");
    printf("  -m <message_payload_file>  Specify the message payload file\n");
    printf("  -o <signed_message_file>        Specify output file\n");
    printf("Optional options:\n");
    printf("  -v                         Enable verbose output\n");
    printf("  -V                         Print version information\n");
    printf("  -h                         Display this help message and exit\n");
}

/*===========================================================================
                               GLOBAL FUNCTIONS
=============================================================================*/

/** main
 *
 * Entry point main function for the app, processes input arguments and
 * call necessary local function to generate signed message.
 *
 * @param[in] argc, number of arguments in argv
 *
 * @param[in] argv, array of arguments.
 *
 * @pre  none
 *
 * @post  if successful, generate a signed message file.
 *
 * @returns #EXIT_SUCCESS on success and #EXIT_FAILURE otherwise.
 */

int main(int argc, char *argv[])
{
    int verbose = 0;
    int opt = 0;
    char *message_template_file = NULL;
    char *message_payload_file = NULL;
    char *signed_message_file = NULL;
    uint16_t signature_block_offset = 0;
    uint32_t *container_header_words = NULL;
    size_t container_header_word_count = 0;
    uint32_t *message_words = NULL;
    size_t message_word_count = 0;
    FILE *fp = NULL;

    /* Parse the options using getopt */
    while ((opt = getopt(argc, argv, "t:m:o:Vvh")) != -1)
    {
        switch (opt)
        {
            case 't':
                message_template_file = optarg;
                break;
            case 'm':
                message_payload_file = optarg;
                break;
            case 'o':
                signed_message_file = optarg;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'V':
                print_version();
                exit(EXIT_SUCCESS);
            case 'h':
                print_usage();
                exit(EXIT_SUCCESS);
            default:
                print_usage();
                exit(EXIT_FAILURE);
        }
    }

    if (message_template_file == NULL || message_payload_file == NULL ||
        signed_message_file == NULL)
    {
        fprintf(stderr,
                "Error: -t <message_template_file>, -m <message_payload_file>, "
                "and -o <signed_message_file> are required.\n");
        print_usage();
        exit(EXIT_FAILURE);
    }

    /* Verbose mode output */
    if (verbose)
    {
        printf("Container file: %s\n", message_template_file);
        printf("Message file: %s\n", message_payload_file);
        printf("Output file: %s\n", signed_message_file);
    }

    /* Build the signed message including signature block offset calculation */
    generate_signed_message(message_template_file, message_payload_file,
                            &container_header_words,
                            &container_header_word_count, &message_words,
                            &message_word_count, verbose);

    signature_block_offset = container_header_words[3];

    /* Write the container header words and message words to the output file */
    fp = fopen(signed_message_file, "wb");
    if (fp == NULL)
    {
        perror("Error opening output file");
        free(container_header_words);
        free(message_words);
        exit(EXIT_FAILURE);
    }

    fwrite(container_header_words, sizeof(uint32_t),
           container_header_word_count, fp);
    fwrite(message_words, sizeof(uint32_t), message_word_count, fp);

    fclose(fp);

    if (verbose)
    {
        printf("CST: CONTAINER 0 offset: 0x00\n");
        printf("CST: CONTAINER 0: Signature Block: offset is at 0x%x\n",
               signature_block_offset);
    }

    printf("Offsets = 0x%x 0x%x\n", 0, signature_block_offset);

    /* Clean-up */
    free(container_header_words);
    free(message_words);

    return EXIT_SUCCESS;
}
