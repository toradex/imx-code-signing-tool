// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

/*===========================================================================*/
/**
	@file   hab4_mac_dump.c

	@brief  Utility tool to dump the MAC data location and size from a HABv4
			csf binary data file.
 */

/*===========================================================================
				INCLUDE FILES
=============================================================================*/
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/*===========================================================================
				MACROS
=============================================================================*/
/* CSF filename is the only input parameter to the tool */
#define MIN_ARGS 2
#define MAX_ARGS 2

/* header */
#define HDR_TAG(x)((uint8_t)(x) & 0xff)
#define HDR_LEN(x)((uint16_t)((uint16_t)((x) & 0xff00)+(uint8_t)(((x)>>16) & 0xff)))

#define HAB_MAC_TAG 0xac

/* Debug out */
#ifdef DEBUG
#define DOUT printf
#else
#define DOUT(...) {}
#endif

/*===========================================================================
				Function Declarations
=============================================================================*/
void usage(void);

void usage(void)
{
	printf("\nUsage:\n");
	printf("\thab4_mac_dump <path to csf file>\n\n\n");
}

int main(int argc, char *argv[])
{
		int ret_val = 0;
		char *filename;
		FILE *fd_csf = NULL;
        long csf_file_size = 0;
        uint8_t *csf_data = NULL;

		/* Get filename */
		if (argc < MIN_ARGS || argc > MAX_ARGS) {
			usage();
			return -EINVAL;
		}

		filename = argv[1];

		/* Open file read only */
		fd_csf = fopen(filename, "rb");
		if (!fd_csf) {
            fprintf(stderr, "ERROR: Opening file %s\n", filename);
            return errno;
		}

		/* Get the file size */
        if (fseek(fd_csf, 0, SEEK_END) != 0)
        {
            fprintf(stderr, "Failed to seek to the end of the file");
            fclose(fd_csf);
            return errno;
        }

        csf_file_size = ftell(fd_csf);

        if (csf_file_size < 0)
        {
            fprintf(stderr, "Error: Failed to determine file size.\n");
            fclose(fd_csf);
            return errno;
        }

        rewind(fd_csf);

		/* Allocate csf data buffer */
		csf_data = (uint8_t *)malloc(csf_file_size);
		if (!csf_data)
			return -ENOMEM;

		do {
			uint32_t index = 0;
			uint32_t hdr = 0;

			/* Read csf file into buffer */
			if (fread(csf_data, 1, csf_file_size, fd_csf) != csf_file_size) {
				ret_val = -EIO;
				break;
			}

			while (index < csf_file_size) {
				uint8_t hdr_tag;
				uint16_t hdr_len = 0;

				hdr = *(uint32_t *)(csf_data+index);

				hdr_tag = HDR_TAG(hdr);
				hdr_len = HDR_LEN(hdr);

				DOUT("csf_index = %x\tdata = %x\n", index, hdr);
				DOUT("tag = %x\nlength = %x\n\n", hdr_tag, hdr_len);

				if (hdr_tag == HAB_MAC_TAG) {
					printf("MAC_TAG offset: 0x%x\n", index);
					printf("MAC_TAG length: 0x%x\n", hdr_len);
				}
				if (hdr_len % 4)
					hdr_len = (hdr_len & 0xfffc) + 0x4;

				index += hdr_len;
			}
		} while (0);

		if (csf_data)
			free(csf_data);

		if (fd_csf)
			fclose(fd_csf);

		return ret_val;
}
