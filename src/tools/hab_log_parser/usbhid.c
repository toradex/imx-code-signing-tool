// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2018, 2020, 2024 NXP
 */

#include <math.h>
#include "usbhid.h"

struct hid_report{
    uint8_t  id ;
    uint16_t type;
    uint32_t addr;
    uint8_t  format;
    uint32_t data_cnt;
    uint32_t data;
    uint8_t  reserved;
}__attribute__((__packed__));

void handleSDPError(int err_no){
    printf("Error: (%d)\n",err_no);
    switch(err_no){
        case ERROR_DEV_NOT_FOUND:
            printf("Device not found\n");
            break;
        case ERROR_HID_SEND:
            printf("Error while sending report feature\n");
            break;
        case ERROR_HID_READ:
            printf("Error while reading report feature\n");
            break;
        case ERROR_HID_WRITE:
            printf("Error while writing report feature\n");
            break;
        case ERROR_WRITE_HAB:
            printf("Error HAB rejected address\n");
            break;
        case ERROR_IO_OPEN:
            printf("Error IO open\n");
            break;
        case ERROR_IO_WRITE:
            printf("Error IO write\n");
            break;
        case ERROR_MEMORY_ALLOCATION:
            printf("Error memory allocation\n");
            break;
    }
}

int jump_addr(hid_device **handle, uint32_t addr){
    int bytes = 0;
    struct hid_report sdp_command = {0};
    unsigned char buf[65] = {0};

    sdp_command.id = REPORT_ID_1;
    sdp_command.type = JUMP_ADDRESS;
    sdp_command.addr =  __builtin_bswap32(addr);
    sdp_command.format = 0x00;
    sdp_command.data_cnt =  0x00000000;
    sdp_command.data = 0x00000000;
    sdp_command.reserved = 0x00;

    bytes = hid_write(*handle, (unsigned char *)&sdp_command,  17);
    if(bytes == -1) return ERROR_HID_SEND;

    buf[0] = REPORT_ID_3;
    bytes = hid_read(*handle, buf, 5);
    if( bytes == -1 ) return ERROR_HID_READ;

#ifdef DEBUG
    printf("\n===========JUMP_ADDRESS Command==========\n");
    printf("Sec Conf: ");
    for (i = 1; i < 5; i++)
        printf("%02hhx ", buf[i]);
    printf("\n");
#endif

    buf[0] = REPORT_ID_4;
    bytes = hid_read(*handle, buf, 65);
    if( bytes == -1 ) return ERROR_HID_READ;

#ifdef DEBUG
    printf("Status: ");
    for (i = 0; i < 5; i++)
        printf("%02hhx ", buf[i]);
    printf("\n");
    printf("\n=========================================\n");
#endif

    return 0;
}

int error_status(hid_device **handle){
    int bytes = 0;
    struct hid_report sdp_command = {0};
    unsigned char buf[65] = {0};
    int i = 0;

    sdp_command.id = REPORT_ID_1;
    sdp_command.type = ERROR_STATUS;
    sdp_command.addr =  0x00000000;
    sdp_command.format = 0x00;
    sdp_command.data_cnt =  0x00000000;
    sdp_command.data = 0x00000000;
    sdp_command.reserved = 0x00;

    bytes = hid_write(*handle, (unsigned char *)&sdp_command,  17);
    if(bytes == -1) return ERROR_HID_SEND;

    buf[0] = REPORT_ID_3;
    bytes = hid_read(*handle, buf, 5);
    if( bytes == -1 ) return ERROR_HID_READ;

#ifdef DEBUG
    printf("\n===========Error Status Command==========\n");
    printf("Sec Conf: ");
    for (i = 1; i < 5; i++)
        printf("%02hhx ", buf[i]);
    printf("\n");
#endif

    buf[0] = REPORT_ID_4;
    /* Read a Feature Report from the device */
    bytes = hid_read(*handle, buf, 65);
    if( bytes == -1 ) return ERROR_HID_READ;

#ifdef DEBUG
    printf("Status: ");
    for (i = 0; i < 5; i++)
        printf("%02hhx ", buf[i]);
    printf("\n");
    printf("\n=========================================\n");
#endif

    return 0;
}

/* Read Memory */
int read_register(hid_device **handle, uint32_t addr, uint8_t format,
                  uint32_t size, uint32_t out_type, char *dst)
{
    int i = 0;
    int bytes = 0;
    unsigned char *buffer = NULL;
    FILE *fp = NULL;
    int n = 0;
    int idx = 0;
    int packets = 0;
    unsigned char buf[65] = {0};
    struct hid_report sdp_command = {0};
    int ret = 0;

    sdp_command.id = REPORT_ID_1;
    sdp_command.type = READ_REGISTER;
    sdp_command.addr = __builtin_bswap32(addr);
    sdp_command.format = format;
    sdp_command.data_cnt = __builtin_bswap32(size);
    sdp_command.data = 0x00000000;
    sdp_command.reserved = 0x00;

    bytes = hid_write(*handle, (unsigned char *) &sdp_command, 17);
    if (bytes == -1)
        return ERROR_HID_SEND;

    buf[0] = REPORT_ID_3;
    bytes = hid_read(*handle, buf, 5);
    if (bytes == -1)
        return ERROR_HID_READ;

#ifdef DEBUG
    printf("\n==========Read Register Command==========\n");
    printf("Sec Conf: ");
    for (i = 1; i < 5; i++)
    {
        printf("%02hhx ", buf[i]);
    }
    printf("\n");
#endif

    switch (out_type)
    {
        case BUFFER:
            buffer = (unsigned char *) malloc(sizeof(unsigned char) * size);
            if (!buffer)
                return ERROR_MEMORY_ALLOCATION;
            break;
        case FILEOUTPUT:
            fp = fopen(dst, "w+");
            if (!fp)
                return ERROR_IO_OPEN;
            break;
    }

    packets = ceil((double) size / 64.0);
    for (i = 0; i < packets; i++)
    {
        buf[0] = REPORT_ID_4;
        bytes = hid_read(*handle, buf, 65);
        if (bytes == -1)
        {
            ret = ERROR_HID_READ;
            goto cleanup;
        }

        if (i + 1 == packets)
        {
            if (size < packets * 64)
            {
                bytes = size - (size / 64) * 64;
                bytes++;
            }
        }

        switch (out_type)
        {
            case BUFFER:
                for (n = 1; n < bytes; n++)
                {
                    buffer[idx++] = buf[n];
                }
                break;
            case FILEOUTPUT:
                for (n = 1; n < bytes; n++)
                {
                    if (fprintf(fp, "%02hhx", buf[n]) < 0)
                    {
                        ret = ERROR_IO_WRITE;
                        goto cleanup;
                    }
                }
                break;
            case CONSOLE:
                for (n = 1; n < bytes; n++)
                {
                    printf("%02hhx", buf[n]);
                }
                break;
        }

#ifdef DEBUG
        for (n = 1; n < bytes; n++)
        {
            printf("%02hhx", buf[n]);
        }
        printf("\n");
#endif
    }

    if (out_type == BUFFER)
    {
        memcpy(dst, buffer,
               size); /* Copy data to `dst` before freeing `buffer` */
    }

cleanup:
    if (fp)
        fclose(fp);
    if (buffer)
        free(buffer);

#ifdef DEBUG
    printf("\n==========================================\n");
#endif

    return ret;
}

/* Write to Register */
int write_register(hid_device **handle, uint32_t addr, uint8_t format, uint32_t value){

    int bytes = 0;
    struct hid_report sdp_command = {0};
    unsigned char buf[65] = {0};

#ifdef DEBUG
    printf("\n==========Write Register Command==========\n");
#endif

    sdp_command.id = REPORT_ID_1;
    sdp_command.type = WRITE_REGISTER;
    sdp_command.addr =  __builtin_bswap32(addr);
    sdp_command.format = format;
    sdp_command.data_cnt =  __builtin_bswap32(format);
    sdp_command.data =  __builtin_bswap32(value);
    sdp_command.reserved = 0x00;

#ifdef DEBUG
    for(i = 0; i < 17; i++){
    printf("%02x",*((uint8_t*)&sdp_command + i*sizeof(uint8_t)));
    }
#endif

    bytes = hid_write(*handle, (unsigned char *)&sdp_command,  17);
    if( bytes == -1 ) return ERROR_HID_READ;

    buf[0] = REPORT_ID_3;
    bytes = hid_read(*handle, buf, 5);
    if( bytes == -1 ) return ERROR_HID_READ;

#ifdef DEBUG
    printf("Sec Conf: ");
    for (i = 1; i < 5; i++)
        printf("%02hhx ", buf[i]);
    printf("\n");
#endif

    buf[0] = REPORT_ID_4;
    bytes = hid_read(*handle, buf, 65);
    if( bytes == -1 ) return ERROR_HID_READ;

#ifdef DEBUG
    printf("Status: ");
    for (i = 0 ; i < 5; i++)
        printf("%02hhx ", buf[i]);
    printf("\n");
    printf("\n=========================================\n");
#endif
    return 0;
}

int write_file(hid_device **handle, uint32_t addr, char *file_path)
{
    int i = 0;
    int bytes = 0;
    FILE *fp = NULL;
    uint32_t size = 0;
    struct hid_report sdp_command = {0};
    int newLen = 0;
    unsigned char buf[MAXBUFLEN + 1] = {0};
    int packets = 0;
    uint32_t status = 0;

#ifdef DEBUG
    printf("\n============Write File Command===========\n");
#endif

    fp = fopen(file_path, "r");
    if (fp == NULL)
    {
#ifdef DEBUG
        perror("Error opening file");
#endif
        return ERROR_IO_OPEN;
    }

    if (fseek(fp, 0, SEEK_END) != 0)
    {
#ifdef DEBUG
        perror("Error seeking in file");
#endif
        fclose(fp);
        return ERROR_IO_OPEN;
    }

    size = (uint32_t) ftell(fp);
    if (size == (uint32_t) -1)
    {
#ifdef DEBUG
        perror("Error determining file size using ftell");
#endif
        fclose(fp);
        return ERROR_IO_OPEN;
    }

    rewind(fp);

    sdp_command.id = REPORT_ID_1;
    sdp_command.type = WRITE_FILE;
    sdp_command.addr = __builtin_bswap32(addr);
    sdp_command.format = 0x00;
    sdp_command.data_cnt = __builtin_bswap32(size);
    sdp_command.data = 0x00000000;
    sdp_command.reserved = 0x00;

#ifdef DEBUG
    for (i = 0; i < 17; i++)
    {
        printf("%02x", *((uint8_t *) &sdp_command + i * sizeof(uint8_t)));
    }
#endif

    bytes = hid_write(*handle, (unsigned char *) &sdp_command, 17);
    if (bytes == -1)
    {
        fclose(fp);
        return ERROR_HID_READ;
    }

    packets = ceil((double) size / MAXBUFLEN);

    for (i = 0; i < packets; i++)
    {
        buf[0] = REPORT_ID_2;
        newLen = fread(&buf[1], sizeof(unsigned char), MAXBUFLEN, fp);
        if (newLen == 0 && ferror(fp))
        {
#ifdef DEBUG
            perror("Error reading file");
#endif
            fclose(fp);
            return ERROR_IO_OPEN;
        }

        bytes = hid_write(*handle, buf, newLen + 1);
        if (bytes == -1)
        {
            fclose(fp);
            return ERROR_HID_READ;
        }
    }

    fclose(fp);

    buf[0] = REPORT_ID_3;
    bytes = hid_read(*handle, buf, 5);
    if (bytes == -1)
    {
        return ERROR_HID_READ;
    }

#ifdef DEBUG
    printf("Sec Conf: ");
    for (i = 1; i < 5; i++)
        printf("%02hhx ", buf[i]);
    printf("\n");
#endif

    buf[0] = REPORT_ID_4;
    bytes = hid_read(*handle, buf, 65);
    if (bytes == -1)
    {
        return ERROR_HID_READ;
    }

    status = 0x00000000;
    memcpy(&status, (unsigned int *) &buf[1], 4);
#ifdef DEBUG
    printf("Status: ");
    printf("Status: 0x%08x\n", status);
    printf("\n=========================================\n");
#endif

    return 0;
}

/* Load DCD to tempory addr */
int dcd_write(hid_device **handle, uint32_t addr, char *file_path, int *ret)
{

    FILE *fp = NULL;
    struct hid_report sdp_command = {0};
    int i = 0;
    int bytes = 0;
    uint32_t size = 0;
    int newLen = 0;
    unsigned char buf[MAXBUFLEN + 1] = {0};
    int packets = 0;
    uint32_t status = 0;

#ifdef DEBUG
    printf("\n=============DCD Write Command===========\n");
#endif

    fp = fopen(file_path, "r");
    if (fp == NULL)
    {
#ifdef DEBUG
        printf("Error reading file\n");
#endif
        return ERROR_IO_OPEN;
    }

    if (fseek(fp, 0, SEEK_END) != 0)
    {
#ifdef DEBUG
        printf("Error seeking in file\n");
#endif
        fclose(fp);
        return ERROR_IO_OPEN;
    }

    size = (uint32_t) ftell(fp);
    if (size == (uint32_t) -1)
    {
#ifdef DEBUG
        perror("Error determining file size using ftell");
#endif
        fclose(fp);
        return ERROR_IO_OPEN;
    }

    rewind(fp);

    sdp_command.id = REPORT_ID_1;
    sdp_command.type = DCD_WRITE;
    sdp_command.addr = __builtin_bswap32(addr);
    sdp_command.format = 0x00;
    sdp_command.data_cnt = __builtin_bswap32(size);
    sdp_command.data = 0x00000000;
    sdp_command.reserved = 0x00;

#ifdef DEBUG
    for (i = 0; i < 17; i++)
    {
        printf("%02x", *((uint8_t *) &sdp_command + i * sizeof(uint8_t)));
    }
#endif

    bytes = hid_write(*handle, (unsigned char *) &sdp_command, 17);
    if (bytes == -1)
    {
        fclose(fp);
        return ERROR_HID_READ;
    }

    if (error_status(handle) == ERROR_WRITE_HAB)
    {
        fclose(fp);
        return ERROR_WRITE_HAB;
    }

    packets = ceil((double) size / MAXBUFLEN);
    for (i = 0; i < packets; i++)
    {
        buf[0] = REPORT_ID_2;
        newLen = fread(&buf[1], sizeof(unsigned char), MAXBUFLEN, fp);
        if (newLen == 0 && ferror(fp))
        {
#ifdef DEBUG
            perror("Error reading file");
#endif
            fclose(fp);
            return ERROR_IO_OPEN;
        }

        bytes = hid_write(*handle, buf, newLen + 1);
        if (bytes == -1)
        {
            fclose(fp);
            return ERROR_HID_READ;
        }
    }

    fclose(fp);

    buf[0] = REPORT_ID_3;
    bytes = hid_read(*handle, buf, 5);
    if (bytes == -1)
    {
        return ERROR_HID_READ;
    }

#ifdef DEBUG
    printf("Sec Conf: ");
    for (i = 1; i < 5; i++)
    {
        printf("%02hhx ", buf[i]);
    }
    printf("\n");
#endif

    buf[0] = REPORT_ID_4;
    bytes = hid_read(*handle, buf, 65);
    if (bytes == -1)
    {
        return ERROR_HID_READ;
    }

    status = 0x00000000;
    memcpy(&status, (unsigned int *) &buf[1], 4);
    *ret = status;

#ifdef DEBUG
    printf("Status: ");
    printf("Status: 0x%08x\n", status);
    printf("\n=========================================\n");
#endif
    return 0;
}

int init_dev(hid_device **handle, uint16_t vid){
    /* Enumerate and print the HID devices on the system */
    struct hid_device_info *freescale_devs = NULL;
    struct hid_device_info *cur_dev = NULL;

#ifdef DEBUG
    printf("  Manufacturer: \n");
#endif

    freescale_devs = hid_enumerate(vid, 0x0);
    if(!freescale_devs){
        return ERROR_DEV_NOT_FOUND;
    }

    cur_dev = freescale_devs;

#ifdef DEBUG
    printf("Device Found\n  type: %04hx %04hx\n  path: %s\n  serial_number: %ls",
            cur_dev->vendor_id, cur_dev->product_id, cur_dev->path, cur_dev->serial_number);
    printf("\n");
    printf("  Manufacturer: %ls\n", cur_dev->manufacturer_string);
    printf("  Product:      %ls\n", cur_dev->product_string);
    printf("\n");
#endif

    /* Open the device using the VID, PID, and optionally the Serial number. */
    *handle = (hid_device *)hid_open(cur_dev->vendor_id, cur_dev->product_id, NULL);

    hid_free_enumeration(freescale_devs);

    return 0;
}
