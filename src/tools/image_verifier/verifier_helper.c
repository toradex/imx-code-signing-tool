// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include "verifier_helper.h"

/** Global variable for tracking the current indentation level. */
static int g_indent_level = 0;

/*--------------------------
  print_with_indent
---------------------------*/
void print_with_indent(const char *format, ...)
{
    va_list args;
    va_start(args, format);

    /* Print indentation based on the current indent level */
    for (int i = 0; i < g_indent_level; i++)
    {
        printf("  "); /* Two spaces per indent level */
    }

    /* Print the formatted string */
    vprintf(format, args);
    va_end(args);
}

/*--------------------------
  increase_indent
---------------------------*/
void increase_indent(void)
{
    g_indent_level++;
}

/*--------------------------
  decrease_indent
---------------------------*/
void decrease_indent(void)
{
    if (g_indent_level > 0)
    {
        g_indent_level--;
    }
}

/*--------------------------
  read_data
---------------------------*/
void read_data(FILE *file, void *buffer, size_t size, long offset)
{
    /* Seek to the specified offset in the file */
    if (fseek(file, offset, SEEK_SET) != 0)
    {
        perror("Failed to seek to the specified offset");
        exit(EXIT_FAILURE);
    }

    /* Read the specified amount of data from the file */
    if (fread(buffer, size, 1, file) != 1)
    {
        perror("Failed to read data from file");
        exit(EXIT_FAILURE);
    }
}

/*--------------------------
  read_word
---------------------------*/
void read_word(FILE *file, uint32_t *word, long offset)
{
    if (fseek(file, offset, SEEK_SET) != 0)
    {
        perror("Failed to seek to the specified offset");
        exit(EXIT_FAILURE);
    }

    if (fread(word, sizeof(uint32_t), 1, file) != 1)
    {
        perror("Failed to read word");
        exit(EXIT_FAILURE);
    }
}

/*--------------------------
  read_short_be
---------------------------*/
uint16_t read_short_be(FILE *file, long offset)
{
    uint8_t buffer[2];
    uint16_t result = 0;

    read_data(file, buffer, sizeof(buffer), offset);

    result = (buffer[0] << 8) | buffer[1];

    return result;
}

/*--------------------------
  read_word_be
---------------------------*/
uint32_t read_word_be(FILE *file, long offset)
{
    uint32_t result = 0;
    uint8_t buffer[4];

    read_data(file, buffer, sizeof(buffer), offset);
    result =
        (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];
    return result;
}

/*--------------------------
  read_byte
---------------------------*/
uint8_t read_byte(FILE *file, long offset)
{
    uint8_t result = 0;

    read_data(file, &result, sizeof(result), offset);

    return result;
}

/*--------------------------
  swap_bytes
---------------------------*/
void swap_bytes(uint8_t *data, size_t size)
{
    int i, j;
    for (i = 0, j = size - 1; i < j; i++, j--)
    {
        SPA_SWAP(data[i], data[j]);
    }
}

/*--------------------------
  dump_buffer_with_label
---------------------------*/
void dump_buffer_with_label(const char *label, const unsigned char *buffer,
                            int length)
{
    /* Print the label with indentation */
    print_with_indent(label);

    /* Print the buffer in hexadecimal format */
    for (int i = 0; i < length; i++)
    {
        /* Print byte in hexadecimal */
        printf("%02X", buffer[i]);
        if ((i + 1) % 32 == 0)
        {
            /* Print a newline after every 32 bytes */
            printf("\n");
        }
    }

    /* Add a newline if the last line was not complete */
    if (length % 32 != 0)
    {
        printf("\n");
    }
}
