// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

/*===========================================================================*/
/**
 *   @file    ahab_split_container.c
 *
 *   @brief   Split NXP-signed AHAB container into ELE and V2X containers to
 *            enable double authentication feature.
 *
 */

/*===========================================================================
                                INCLUDE FILES
=============================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "ahab_types.h"
#include "version.h"

/*===========================================================================
                               LOCAL CONSTANTS
=============================================================================*/

#define AHAB_MAX_CONTAINER_SIZE 0x400
#define ELE_FW_IMAGE_OFFSET 0x2000
#define MAX_FILE_NAME_LENGTH 256

const char *g_tool_name = "ahab_split_container"; /**< Global holds tool name */
const char *g_tool_version = CST_VERSION; /**< Global holds tool version */

/*===========================================================================
                  LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
=============================================================================*/

/*===========================================================================
                          LOCAL FUNCTION PROTOTYPES
=============================================================================*/

/**
 * @brief Reads the entire content of a file into memory.
 *
 * @param[in] filename The name of the file to be read.
 * @param[out] size Pointer to a variable where the size of the file (in bytes)
 *                  will be stored.
 *
 * @return A pointer to the dynamically allocated buffer containing the file
 *         content, or NULL if the file could not be read or memory allocation
 *         failed. The caller is responsible for freeing this memory.
 */
static uint8_t *read_file(const char *filename, size_t *size);

/**
 * @brief Writes data to a file.
 *
 *
 * @param[in] filename The name of the file to which the data should be written.
 * @param[in] data Pointer to the data to be written to the file.
 * @param[in] size The number of bytes to write from the `data` buffer.
 *
 * @return An integer indicating success (0) or failure (-1). Failure may occur
 *         if the file could not be opened or if there was an error during the
 *         write operation.
 */
static int write_file(const char *filename, const uint8_t *data, size_t size);

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

/*===========================================================================
                               GLOBAL VARIABLES
=============================================================================*/

/*===========================================================================
                               LOCAL FUNCTIONS
=============================================================================*/

/*--------------------------
  read_file
---------------------------*/
uint8_t *read_file(const char *filename, size_t *size)
{
    FILE *file = NULL;
    uint8_t *buffer = NULL;
    long file_size = 0;
    size_t bytes_read = 0;

    file = fopen(filename, "rb");
    if (!file)
    {
        fprintf(stderr, "Error opening file %s: %s\n", filename,
                strerror(errno));
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) != 0)
    {
        perror("Error seeking to the end of the file");
        fclose(file);
        return NULL;
    }

    file_size = ftell(file);
    if (file_size == -1L)
    {
        perror("Error determining file size");
        fclose(file);
        return NULL;
    }

    if (fseek(file, 0, SEEK_SET) != 0)
    {
        perror("Error seeking to the start of the file");
        fclose(file);
        return NULL;
    }

    buffer = (uint8_t *) malloc((size_t) file_size);
    if (!buffer)
    {
        fprintf(stderr, "Memory allocation error\n");
        fclose(file);
        return NULL;
    }

    bytes_read = fread(buffer, 1, (size_t) file_size, file);
    if (bytes_read != (size_t) file_size)
    {
        fprintf(stderr, "Error reading file %s\n", filename);
        free(buffer);
        fclose(file);
        return NULL;
    }

    fclose(file);

    *size = (size_t) file_size;

    return buffer;
}

/*--------------------------
  write_file
---------------------------*/
int write_file(const char *filename, const uint8_t *data, size_t size)
{
    FILE *file = NULL;

    file = fopen(filename, "wb");
    if (!file)
    {
        fprintf(stderr, "Error opening file %s: %s\n", filename,
                strerror(errno));
        return -1;
    }

    if (fwrite(data, 1, size, file) != size)
    {
        fprintf(stderr, "Error writing to file %s\n", filename);
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
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
    printf("Usage: %s [options] <input_file>\n", g_tool_name);
    printf("Options:\n");
    printf("  -h           Display this help message.\n");
    printf("  -v           Display the version information.\n");
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

    uint8_t *data = NULL;
    size_t data_size = 0;
    char ele_filename[MAX_FILE_NAME_LENGTH] = {0};
    char v2xfh_filename[MAX_FILE_NAME_LENGTH] = {0};
    uint8_t *ele_data = NULL;
    uint8_t *v2xfh_data = NULL;
    struct ahab_container_header_s *container_header = NULL;
    struct ahab_container_image_s *container_image = NULL;
    uint32_t ele_fw_size = 0;
    size_t ele_total_size = 0;
    size_t v2xfh_total_size = 0;
    uint32_t v2xfhp_offset = 0;
    uint32_t v2xfhs_offset = 0;
    uint32_t v2xfhs_fw_size = 0;

    if (argc < 2)
    {
        print_usage();
        return EXIT_FAILURE;
    }

    /* Parse command-line options */
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-h") == 0)
        {
            print_usage();
            return EXIT_SUCCESS;
        }
        else if (strcmp(argv[i], "-v") == 0)
        {
            printf("%s version %s\n", g_tool_name, g_tool_version);
            return EXIT_SUCCESS;
        }
    }

    /* Read input container data */
    data = read_file(argv[1], &data_size);
    if (!data)
    {
        return EXIT_FAILURE;
    }

    /* Format splitted output containers names */
    snprintf(ele_filename, sizeof(ele_filename), "%s.ele", argv[1]);
    snprintf(v2xfh_filename, sizeof(v2xfh_filename), "%s.v2xfh", argv[1]);

    container_header = (struct ahab_container_header_s *) data;
    container_image =
        (struct ahab_container_image_s *) ((uint8_t *) container_header +
                                           sizeof(
                                               struct ahab_container_header_s));

    if (container_header->tag != CONTAINER_HEADER_TAG)
    {
        fprintf(stderr, "Invalid input file.\n");
        free(data);
        return EXIT_FAILURE;
    }

    /* Get the ELE FW size */
    ele_fw_size = container_image->image_size;

    /* Get the V2X-FH FW offsets and sizes */
    container_header =
        (struct ahab_container_header_s *) (data + AHAB_MAX_CONTAINER_SIZE);

    if (container_header->tag != CONTAINER_HEADER_TAG)
    {
        fprintf(stderr, "Invalid input file.\n");
        free(data);
        return EXIT_FAILURE;
    }

    container_image =
        (struct ahab_container_image_s *) ((uint8_t *) container_header +
                                           sizeof(
                                               struct ahab_container_header_s));
    v2xfhp_offset = container_image->image_offset;

    container_image =
        (struct ahab_container_image_s *) ((uint8_t *) container_header +
                                           sizeof(
                                               struct ahab_container_header_s) +
                                           sizeof(
                                               struct ahab_container_image_s));

    v2xfhs_offset = container_image->image_offset;
    v2xfhs_fw_size = container_image->image_size;

    /* Validate the offsets and sizes before proceeding */
    if ((ELE_FW_IMAGE_OFFSET + ele_fw_size) > data_size ||
        v2xfhp_offset >= data_size || v2xfhs_offset >= data_size ||
        v2xfhs_fw_size >= data_size ||
        (v2xfhs_offset + v2xfhs_fw_size) > data_size)
    {
        fprintf(stderr, "Invalid offsets or sizes in the input file.\n");
        free(data);
        return EXIT_FAILURE;
    }

    /* Allocate memory for ele and v2xfh buffers */
    ele_total_size = ELE_FW_IMAGE_OFFSET + ele_fw_size;
    v2xfh_total_size = v2xfhs_offset + v2xfhs_fw_size;

    ele_data = (uint8_t *) malloc(ele_total_size);
    if (!ele_data)
    {
        fprintf(stderr, "Memory allocation error for ele_data.\n");
        free(data);
        return EXIT_FAILURE;
    }

    v2xfh_data = (uint8_t *) malloc(v2xfh_total_size);
    if (!v2xfh_data)
    {
        fprintf(stderr, "Memory allocation error for v2xfh_data.\n");
        free(data);
        free(ele_data);  // Free previously allocated memory
        return EXIT_FAILURE;
    }

    /* Clear the allocated memory to avoid any garbage data */
    memset(ele_data, 0, ele_total_size);
    memset(v2xfh_data, 0, v2xfh_total_size);

    /* Copy the container headers */
    memcpy(ele_data, data, AHAB_MAX_CONTAINER_SIZE);
    memcpy(v2xfh_data, data + AHAB_MAX_CONTAINER_SIZE, AHAB_MAX_CONTAINER_SIZE);

    /* Add padding */
    memset(ele_data + AHAB_MAX_CONTAINER_SIZE, 0,
           ELE_FW_IMAGE_OFFSET - AHAB_MAX_CONTAINER_SIZE);
    memset(v2xfh_data + AHAB_MAX_CONTAINER_SIZE, 0,
           v2xfhp_offset - AHAB_MAX_CONTAINER_SIZE);

    /* Copy the images */
    memcpy(ele_data + ELE_FW_IMAGE_OFFSET, data + ELE_FW_IMAGE_OFFSET,
           ele_fw_size);
    memcpy(v2xfh_data + v2xfhp_offset,
           data + v2xfhp_offset + AHAB_MAX_CONTAINER_SIZE,
           (v2xfhs_offset + AHAB_MAX_CONTAINER_SIZE + v2xfhs_fw_size) -
               (v2xfhp_offset + AHAB_MAX_CONTAINER_SIZE));

    /* Write the ele and v2xfh files */
    if (write_file(ele_filename, ele_data, ele_total_size) != 0)
    {
        free(data);
        free(ele_data);
        free(v2xfh_data);
        return EXIT_FAILURE;
    }

    if (write_file(v2xfh_filename, v2xfh_data, v2xfh_total_size) != 0)
    {
        free(data);
        free(ele_data);
        free(v2xfh_data);
        return EXIT_FAILURE;
    }

    /* Clean up */
    free(data);
    free(ele_data);
    free(v2xfh_data);

    return EXIT_SUCCESS;
}
