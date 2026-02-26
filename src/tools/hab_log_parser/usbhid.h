/*
 * Copyright 2018, 2020 NXP
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef USBHIDAPI_H__
#define USBHIDAPI_H__

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include <hidapi/hidapi.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VENDOR_ID_FSL 0x15A2
#define VENDOR_ID_NXP 0x1FC9

#define CONSOLE 1
#define FILEOUTPUT 2
#define BUFFER  3

/* SDP COMMANDS */
#define SDP_COMMAND_TYPE_OFFSET     0
#define SDP_ADDRESS_OFFSET          2
#define SDP_FORMAT_OFFSET           6
#define SDP_DATA_COUNT_OFFSET       7
#define SDP_DATA_OFFSET             11
#define SDP_RESERVED_OFFSET         15

#define SDP_COMMAND_TYPE_SIZE   2
#define SDP_ADDRESS_SIZE        4
#define SDP_FORMAT_SIZE         1
#define SDP_DATA_COUNT_SIZE     4
#define SDP_DATA_SIZE           4
#define SDP_RESERVED_SIZE       1

#define REPORT_ID_1 0x1
#define REPORT_ID_2 0x2
#define REPORT_ID_3 0x3
#define REPORT_ID_4 0x4
#define REPORT_ID_5 0x5

#define FORMAT_8_BIT  0x08
#define FORMAT_16_BIT 0x10
#define FORMAT_32_BIT 0x20

/* ROM COMMAND TYPES */
#define READ_REGISTER   0x0101
#define WRITE_REGISTER  0x0202
#define WRITE_FILE      0x0404
#define ERROR_STATUS    0x0505
#define DCD_WRITE       0x0A0A
#define JUMP_ADDRESS    0x0B0B

#define MAX_STR 256
#define MAXBUFLEN 1024
#define ERROR_DEV_NOT_FOUND -1
#define ERROR_HID_SEND      -2
#define ERROR_HID_READ      -3
#define ERROR_HID_WRITE     -4
#define ERROR_WRITE_HAB     -5
#define ERROR_IO_OPEN       -6
#define ERROR_IO_WRITE -7
#define ERROR_MEMORY_ALLOCATION -8

    /**
 *  init_dev() - find a freescale HID device and initializes
 *               libraries and a handle for such device.
 *  @handle: a device handle using HIDAPI library
 *  @vid: Vendor ID
 *
 *  Initialize a device handle referenced by @handle
 *  Return: 0 on success or ERROR_STATUS
 **/
    int init_dev(hid_device **handle, uint16_t vid);

    /**
 *  jump_addr() - find a freescale HID device and initializes
 *  @handle: a device handle using HIDAPI library
 *  @addr: address to internal or external memory
 *  Return: 0 on success or ERROR_STATUS
 **/
    int jump_addr(hid_device **handle, uint32_t addr);

    /**
 *  error_status() - l return global error status that is updated
 *  after each SDP command
 *
 *  @handle: a device handle using HIDAPI library
 *
 *  Prints the status code
 *
 *  Return: 0 on success or ERROR_STATUS
 **/
    int error_status(hid_device **handle);

    /**
 *  read_register() - Reads a register of address in memory. If
 *    the size of the read data is bigger than 64 bytes, then
 *    multiple read commands are issued.
 *
 *  @handle: a device handle using HIDAPI library
 *  @addr: address to internal or external memory
 *  @format: Format of access, FORMAT_8_BIT, FORMAT_16_BIT, and
 *           FORMAT_32_BIT
 *  @size: Size of data to read
 *  @out: output pipe BUFFER,FILEOUTPUT, or CONSOLE
 *  @dst: if @out == BUFFER then this is a pointer to
 *        the buffer
 *        if @out == FILEOUTPUT this is the file path to the
 *        output file
 *
 *  Return: 0 on success or ERROR_STATUS
 */
    int read_register(hid_device **handle, uint32_t addr, uint8_t format,
                      uint32_t size, uint32_t out, char *dst);

    /**
 *  write_register() - find a freescale HID device and initializes
 *
 *  @handle: a device handle using HIDAPI library
 *  @addr:  address to internal or external memory
 *  @format: Format of access, FORMAT_8_BIT, FORMAT_16_BIT, and
 *           FORMAT_32_BIT
 *  @value: value being written to the register
 *
 *  Return: 0 on success or ERROR_STATUS
 **/
    int write_register(hid_device **handle, uint32_t addr, uint8_t format,
                       uint32_t value);

    /**
 *  write_file() - write a file into unprotected memory.
 *
 *  @handle: a device handle using HIDAPI library
 *  @addr: address to internal or external memory
 *  @file_path: path to the file being written
 *
 *  Return: 0 on success or ERROR_STATUS
 *
 *  Postcondition: On success the status report is COMPLETE.
 *  On failure to write the DCD the device will report HAB error
 *  status.
 *
 **/
    int write_file(hid_device **handle, uint32_t addr, char *file_path);

    /**
 *  dcd_write() - sends a DCD file to the device using multiple
 *  registers writes in one shot. The address is expect to be
 *  within an allowed range.
 *
 *  @handle: a device handle using HIDAPI library
 *  @addr: address to internal or external memory
 *  @file_path: path to the dcd file being written
 *  @ret: status report
 *
 *  Return: 0 on success or ERROR_STATUS
 *
 *  Postcondition: On success the status report is WRITE_COMPLETE.
 *  On failure to write the DCD the device will report HAB error
 *  status.
 **/

    int dcd_write(hid_device **handle, uint32_t addr, char *file_path,
                  int *ret);

    void handleSDPError(int);

#ifdef __cplusplus
}
#endif

#endif

