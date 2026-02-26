/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024 NXP
 */

#ifndef __PKI_HELPER_H
#define __PKI_HELPER_H
/*===========================================================================*/
/**
    @file    pki_helper.h

    @brief   Helper functions to generate basic HAB/AHAB PKI tree.
 */

/*===========================================================================
                                INCLUDES
=============================================================================*/

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

/*===========================================================================
                                MACROS
=============================================================================*/

#if (defined(_WIN32) || defined(__WIN32__))
#define mkdir(A, B) mkdir(A)
#endif

#define MAX_PATH_LENGTH 1024
#define MAX_KEY_NAME_LENGTH 256

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/*============================================================================
                           GLOBAL VARIABLE DECLARATIONS
=============================================================================*/

#define KEY_DIR "./keys"
#define CRT_DIR "./crts"
#define SERIAL_FILE "./crts/serial.txt"
#define KEY_PASS_FILE "./keys/key_pass.txt"
#define SERIAL "12345678"
#define KEY_PASS "test"

/*===========================================================================
                              GLOBAL FUNCTIONS
=============================================================================*/

/** Prompts the user until a valid response is received.
 *
 * @param[in] prompt The prompt message to display.
 * @param[out] response Output buffer for the user's response.
 * @param[in] size Size of the response buffer.
 * @param[in] valid_values Array of valid values.
 * @param[in] valid_values_count Number of valid values.
 */
extern void ask_until_valid(const char *prompt, char *response, size_t size,
                            const char *valid_values[],
                            size_t valid_values_count);

/** Create a directory.
 *
 * @param[in] dir The directory path.
 */
extern int create_directory(const char *dir);

/** Safely copies argument value to a destination buffer.
 *
 * @param dest    Destination buffer.
 * @param src     Source string.
 * @param max_len Maximum length of the destination buffer, including the null terminator.
 *
 * @return 0 on success, 1 if the source string is too long.
 */
extern int copy_arg(char *dest, const char *src, size_t max_len);

/** Generates a serial file.
 *
 * @param[in] serial_file Path to the serial file.
 */
extern void generate_serial_file(const char *serial_file);

/** Reads the serial number from a file.
 *
 * @param[in] serial_file Path to the serial file.
 *
 * @return The serial number.
 */
extern unsigned long read_serial(const char *serial_file);

/** Writes a serial number to a file.
 *
 * @param[in] serial_file Path to the serial file.
 * @param[in] serial The serial number to write.
 */
extern void write_serial(const char *serial_file, unsigned long serial);

/** Generates a key passphrase file.
 *
 * @param[in] key_pass_file Path to the key passphrase file.
 */
extern void generate_key_pass_file(const char *key_pass_file);

/** Reads the key passphrase from a file.
 *
 * @param[in] key_pass_file Path to the key passphrase file.
 *
 * @return Pointer to the dynamically allocated passphrase string.
 *
 * @note The caller is responsible for freeing the returned string.
 */
extern char *read_key_pass(const char *key_pass_file);

/** Generates a key.
 *
 * @param[in] kt Key type.
 * @param[in] kl Key length.
 *
 * @return Pointer to the generated EVP_PKEY structure.
 *
 * @note The caller is responsible for freeing the returned EVP_PKEY structure.
 */
extern EVP_PKEY *generate_key(const char *kt, const char *kl);

/** Generates a certificate.
 *
 * @param[in] pkey The EVP_PKEY structure containing the key.
 * @param[in] subj The subject name for the certificate.
 * @param[in] days The number of days the certificate is valid for.
 * @param[in] digest The digest algorithm to use.
 * @param[in] sign_pkey The EVP_PKEY structure containing the signing key.
 * @param[in] sign_cert The X509 structure containing the signing certificate.
 * @param[in] serial The serial number for the certificate.
 * @param[in] is_ca Flag indicating whether the certificate is a CA certificate.
 *
 * @return Pointer to the generated X509 structure.
 *
 * @note The caller is responsible for freeing the returned X509 structure.
 */
extern X509 *generate_certificate(EVP_PKEY *pkey, const char *subj, int days,
                                  const char *digest, EVP_PKEY *sign_pkey,
                                  X509 *sign_cert, unsigned long serial,
                                  int is_ca);

/** Formats the key, certificate, and subject names.
 *
 * @param[in] kt Key type.
 * @param[in] kl Key length.
 * @param[in] da Digest algorithm.
 * @param[in] key_type Type of the key.
 * @param[in] index Index of the key.
 * @param[in] is_ca Cert has CA flag. 
 * @param[out] key_name Output parameter for the formatted key name.
 * @param[out] crt_name Output parameter for the formatted certificate name.
 * @param[out] subj_name Output parameter for the formatted subject name.
 */
extern void format_key_cert_names(const char *kt, const char *kl,
                                  const char *da, const char *key_type,
                                  int index, int is_ca, char *key_name,
				  char *crt_name, char *subj_name);

/** Writes the PEM key and certificate to files.
 *
 * @param[in] pkey The EVP_PKEY structure containing the key.
 * @param[in] x509 The X509 structure containing the certificate.
 * @param[in] keyfile Path to the key file.
 * @param[in] certfile Path to the certificate file.
 * @param[in] pass The passphrase for encrypting the key.
 */
extern void write_key_and_cert(EVP_PKEY *pkey, X509 *x509, const char *keyfile,
                               const char *certfile, const char *pass);

/** Writes the key and certificate in DER format to files.
 *
 * @param[in] pkey The EVP_PKEY structure containing the key.
 * @param[in] x509 The X509 structure containing the certificate.
 * @param[in] keyfile Path to the key file.
 * @param[in] certfile Path to the certificate file.
 */
extern void write_der_key_and_cert(EVP_PKEY *pkey, X509 *x509,
                                   const char *keyfile, const char *certfile);

#endif /* __PKI_HELPER_H */
