/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024 NXP
 */

#ifndef VERIFIER_HELPER_H
#define VERIFIER_HELPER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>

/** Prints formatted output with current indentation level.
 *
 * @param[in] format The format string (similar to printf).
 * @param[in] ... Additional arguments for the format string.
 */
void print_with_indent(const char *format, ...);

/** Increases the current indentation level.
 *
 * This function increases the indentation level by one,
 * adding more indentation for future print statements.
 */
void increase_indent(void);

/** Decreases the current indentation level.
 *
 * This function decreases the indentation level by one,
 * reducing the amount of indentation for future print statements.
 */
void decrease_indent(void);

/** Reads data from a file at a specific offset.
 *
 * @param[in] file The file pointer from which data is to be read.
 * @param[in] buffer A pointer to the buffer where the data will be stored.
 * @param[in] size The size of the data to be read.
 * @param[in] offset The offset in the file from which to start reading.
 */
void read_data(FILE *file, void *buffer, size_t size, long offset);

/** Reads a 32-bit word from the file at the specified offset.
 * 
 * @param file A pointer to the file to read from.
 * @param word A pointer to a 32-bit unsigned integer where the read word will
 *             be stored.
 * @param offset The offset in the file from which to read the word.
 */
void read_word(FILE *file, uint32_t *word, long offset);

/** Reads a 16-bit unsigned short in big-endian format from the file at the
 *  specified offset.
 * 
 * @param file A pointer to the file to read from.
 * @param offset The offset in the file from which to read the 16-bit value.
 * 
 * @return A 16-bit unsigned integer in big-endian format.
 */
uint16_t read_short_be(FILE *file, long offset);

/** Reads a 32-bit unsigned word in big-endian format from the file at the
 *  specified offset.
 * 
 * @param file A pointer to the file to read from.
 * @param offset The offset in the file from which to read the 32-bit value.
 * 
 * @return A 32-bit unsigned integer in big-endian format.
 */
uint32_t read_word_be(FILE *file, long offset);

/** Reads an 8-bit byte from the file at the specified offset.
 * 
 * @param file A pointer to the file to read from.
 * @param offset The offset in the file from which to read the byte.
 * 
 * @return An 8-bit unsigned integer.
 */
uint8_t read_byte(FILE *file, long offset);

/** Swaps two variables of the same type.
 *
 * This macro swaps the values of two variables of the same type.
 *
 * @param a First variable.
 * @param b Second variable.
 */
#define SPA_SWAP(a, b)          \
    ({                          \
        __typeof__(a) _t = (a); \
        (a) = b;                \
        (b) = _t;               \
    })

/**
 * @brief Swaps the bytes in a data buffer.
 *
 * This function swaps the bytes in the given buffer. It's typically
 * used for converting data between little-endian and big-endian formats.
 *
 * @param data Pointer to the buffer containing the data.
 * @param size The size of the buffer.
 */
void swap_bytes(uint8_t *data, size_t size);

/** brief Dumps a buffer with a label and formatted output.
 *
 * @param[in] label The label to print before the buffer.
 * @param[in] buffer Pointer to the buffer containing the data.
 * @param[in] length The length of the buffer.
 */
void dump_buffer_with_label(const char *label, const unsigned char *buffer,
                            int length);

#endif /* VERIFIER_HELPER_H */
