/*
 * Copyright 2018, 2020, 2022, 2024 NXP
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

#include "hab_log_parser.h"
#include "usbhid.h"

/*----------------------------
  htoi
 ----------------------------*/
uint8_t htoi(char s[])
{
        uint8_t result = 0;
        int i = 0;

        //    printf("DBG %c \n", '\0');

        while(s[i]!='\0')
        {
                if (s[i] >= '0' && s[i] <='9')
                {
                        result = result * 16 + s[i] - '0';
                }
                else if (s[i]>='A' && s[i] <='F')
                {
                        result = result * 16 + s[i] - 'A' + 10;
                }
                else if (s[i]>='a' && s[i] <='f')
                {
                        result = result * 16 + s[i] - 'a' + 10;
                }
                else
                {
                        break;
                }

                i++;
        }

        //   printf("DBG %x \n", result);

        return result;
}

/*----------------------------
  tag_valid
 ----------------------------*/
bool tag_valid(uint32_t tag, int verbose)
{
    bool result = false;

    if ((tag == HAB_TAG_ANY)     ||
        (tag == HAB_TAG_KEY)     ||
        (tag == HAB_TAG_STATE)   ||
        (tag == HAB_TAG_ALG_DEF) ||
        (tag == HAB_TAG_ENG_DAT) ||
        (tag == HAB_TAG_BND_DAT) ||
        (tag == HAB_TAG_EVT_DEF) ||
        (tag == HAB_TAG_GENERIC) ||
        (tag == HAB_TAG_INIT)    ||
        (tag == HAB_TAG_UNLK)    ||
        (tag == HAB_KEY_PUBLIC)  ||
        (tag == HAB_KEY_MASTER)  ||
        (tag == HAB_TAG_EVT))
    {
        result = true;
    }
    else if (verbose != 0)
    {
        printf("Unknown tag - 0x%x\n", tag);
    }
    return result;
}

/** Maps status code to index of status description strings
 *
 * @param [in] sts status code
 *
 * @returns index into sts_str[] for the given status code
 */
static inline uint8_t get_sts_idx(uint8_t sts)
{
    uint8_t result;
    if (sts == HAB_SUCCESS) result = 0;
    else if (sts == HAB_FAILURE) result = 1;
    else if (sts == HAB_WARNING) result = 2;
    else result = 3;

    return result;
}

/** Maps reason code to index of reason description strings
 *
 * @param [in] rsn reason code
 *
 * @returns index into rsn_str[] for the given reason code
 */
static inline uint8_t get_rsn_idx(uint8_t rsn)
{
    uint8_t result;
    if (rsn == HAB_RSN_ANY) result = 0;
    else if (rsn == HAB_ENG_FAIL) result = 1;
    else if (rsn == HAB_INV_ADDRESS) result = 2;
    else if (rsn ==  HAB_INV_ASSERTION) result = 3;
    else if (rsn ==HAB_INV_CALL ) result = 4;
    else if (rsn == HAB_INV_CERTIFICATE) result = 5;
    else if (rsn == HAB_INV_COMMAND) result = 6;
    else if (rsn == HAB_INV_CSF) result = 7;
    else if (rsn == HAB_INV_DCD) result = 8;
    else if (rsn == HAB_INV_INDEX) result = 9;
    else if (rsn == HAB_INV_IVT) result = 10;
    else if (rsn == HAB_INV_KEY) result = 11;
    else if (rsn == HAB_INV_RETURN) result = 12;
    else if (rsn == HAB_INV_SIGNATURE) result = 13;
    else if (rsn == HAB_INV_SIZE) result = 14;
    else if (rsn == HAB_MEM_FAIL) result = 15;
    else if (rsn == HAB_OVR_COUNT) result = 16;
    else if (rsn == HAB_OVR_STORAGE) result = 17;
    else if (rsn == HAB_UNS_ALGORITHM) result = 18;
    else if (rsn == HAB_UNS_COMMAND) result = 19;
    else if (rsn == HAB_UNS_ENGINE) result = 20;
    else if (rsn == HAB_UNS_ITEM) result = 21;
    else if (rsn == HAB_UNS_KEY) result = 22;
    else if (rsn == HAB_UNS_PROTOCOL) result = 23;
    else if (rsn == HAB_UNS_STATE) result = 24;
    else result = 25;
    return result;
}

/** Maps context code to index of context description strings
 *
 * @param [in] ctx context code
 *
 * @returns index into ctx_str[] for the given context code
 */
static inline uint8_t get_ctx_idx(uint8_t ctx)
{
    uint8_t result;
    if (ctx == HAB_CTX_ANY) result = 0;
    else if (ctx == HAB_CTX_FAB) result = 1;
    else if (ctx == HAB_CTX_ENTRY) result = 2;
    else if (ctx == HAB_CTX_TARGET) result = 3;
    else if (ctx == HAB_CTX_AUTHENTICATE) result = 4;
    else if (ctx == HAB_CTX_DCD) result = 5;
    else if (ctx == HAB_CTX_CSF) result = 6;
    else if (ctx == HAB_CTX_COMMAND) result = 7;
    else if (ctx == HAB_CTX_AUT_DAT) result = 8;
    else if (ctx == HAB_CTX_ASSERT) result = 9;
    else if (ctx == HAB_CTX_EXIT) result = 10;
    else result = 11;
    return result;
}

/** Maps engine code to index of engine description strings
 *
 * @param [in] eng engine code
 *
 * @returns index into eng_str[] for the given engine code
 */
static inline uint8_t get_eng_idx(uint8_t eng)
{
    uint8_t result;
    if (eng == HAB_ENG_ANY) result = 0;
    else if (eng == HAB_ENG_SCC) result = 1;
    else if (eng == HAB_ENG_RTIC) result = 2;
    else if (eng == HAB_ENG_SAHARA) result = 3;
    else if (eng == HAB_ENG_CSU) result = 4;
    else if (eng == HAB_ENG_SRTC) result = 5;
    else if (eng == HAB_ENG_DCP) result = 6;
    else if (eng == HAB_ENG_RTL) result = 7;
    else if (eng == HAB_ENG_SW) result = 8;
    else if (eng == HAB_ENG_CAAM) result = 9;
    else if (eng == HAB_ENG_SNVS) result = 10;
    else result = 11;
    return result;
}

/*----------------------------
  print_data
 ----------------------------*/
void print_data(FILE *log_file, uint8_t *data_ptr, uint32_t bytes)
{
    uint32_t i;

    if (bytes > 0)
    {
        for (i = 0; i < bytes; i++)
        {
            if (i == 0)
            {
                fprintf(log_file, "%s  %02x", header,
                        data_ptr[i]);
            }
            else if ((i % 16) == 0)
            {
                fprintf(log_file, "\n%s  %02x", header,
                        data_ptr[i]);
            }
            else
            {
                fprintf(log_file, " %02x", data_ptr[i]);
            }
        }
        fprintf(log_file, "\n");
    }
}

/*----------------------------
  print_record_contents
 ----------------------------*/
void print_record_contents(FILE *output_fp, record_t *rec, char* record_type)
{
    fprintf(output_fp, "%s|0x%02x|0x%04x|0x%02x| Record Data (hex):\n",
            record_type, rec->tag, rec->len, rec->par);
    print_data(output_fp, &rec->contents[REC_HEADER_BYTES], rec->len - 4);

    return;
}

/*----------------------------q
  process_any_record
 ----------------------------*/
bool process_any_record(FILE *output_fp, record_t *rec)
{
    uint8_t  *data_ptr;
    uint8_t  *temp_ptr;
    uint32_t length = 0;
    uint8_t  *end_ptr  = rec->contents + rec->len;
    uint32_t count = 0;
    bool     result = false;

    if (rec->len >= REC_HEADER_BYTES)
    {
        do
        {
            data_ptr = &rec->contents[REC_HEADER_BYTES];
            BREAK_IF(data_ptr > end_ptr);

            fprintf(output_fp, "Event (ANY) |0x%02x|0x%04x|0x%02x| Record Data (hex):\n",
                    rec->tag, rec->len, rec->par);

            /* Check for end of record by finding 8 consecutive zero bytes */
            temp_ptr = data_ptr;
            while (temp_ptr < end_ptr)
            {
                if (*temp_ptr++ == 0) count++;
                else count = 0;

                length++;

                if (count == END_RECORD_COUNT)
                {
                    length = length - END_RECORD_COUNT;
                    break;
                }
            }

            print_data(output_fp, data_ptr, length);

            if (count != 8)
            {
                result = true;
            }
        } while (0);
    }

    return result;
}

/*----------------------------
  process_cmd
 ----------------------------*/
void display_pub_key_flags(FILE *output_fp, uint8_t flags)
{
    uint32_t i;

    fprintf(output_fp, "Flags: %02x\n", flags);

    if (flags == 0)
    {
        fprintf(output_fp, "%s        NO FLAGS DEFINED\n", header);
    }
    else
    {
        for (i = 0; i < sizeof(pkcs1_key_flags) / sizeof(pkcs1_key_flags[0]);
             i++)
        {
            if (flags & (1 << i))
            {
                fprintf(output_fp, "%s        %s", header, pkcs1_key_flags[i]);
            }
        }
    }
}

/*----------------------------
  process_cmd
 ----------------------------*/
bool process_public_key(FILE *output_fp, record_t *rec)
{
    uint8_t  *data_ptr = &rec->contents[REC_HEADER_BYTES]; /* Account for key record header */
    uint8_t  *end_ptr  = rec->contents + rec->len;
    uint32_t mod_bytes;
    uint32_t exp_bytes;
    bool     result = false;

    do
    {
        /* Skip unused bytes in flag word */
        data_ptr += 3;
        BREAK_IF(data_ptr >= end_ptr);
        display_pub_key_flags(output_fp, *data_ptr++);

        /* Length field */
        mod_bytes = EXTRACT_LENGTH(data_ptr);
        data_ptr+=2;
        fprintf(output_fp, "%s Mod. Bytes: 0x%04x\n", header, mod_bytes);

        exp_bytes = EXTRACT_LENGTH(data_ptr);
        data_ptr+=2;
        fprintf(output_fp, "%s Exp. Bytes: 0x%04x\n", header, exp_bytes);

        /* Display Modulus */
        BREAK_IF(data_ptr + mod_bytes > end_ptr);
        fprintf(output_fp, "%s Modulus (hex):\n", header);
        print_data(output_fp, data_ptr, mod_bytes);
        data_ptr += mod_bytes;

        BREAK_IF(data_ptr + exp_bytes > end_ptr);
        fprintf(output_fp, "%s Exponent (hex):\n", header);
        print_data(output_fp, data_ptr, exp_bytes);

        result = true;
    } while(0);
    return result;
}

/*----------------------------
  display_aut_dat_flags
 ----------------------------*/
void display_aut_dat_flags(FILE *output_fp, uint8_t flags)
{
    if (flags == HAB_CMD_AUT_DAT_CLR)
    {
        fprintf(output_fp, "%s                  FLAGS: %s", header,
                aut_dat_flags[HAB_CMD_AUT_DAT_CLR]);
    }
    else if (flags == HAB_CMD_AUT_DAT_ABS)
    {
        fprintf(output_fp, "%s                  FLAGS: %s", header,
                aut_dat_flags[HAB_CMD_AUT_DAT_ABS]);
    }
}


/*----------------------------
  display_aut_dat_pcl
 ----------------------------*/
void display_aut_dat_pcl(FILE *output_fp, uint8_t pcl)
{
    if (pcl == HAB_PCL_CMS)
    {
        fprintf(output_fp, "%s             PCL: HAB_PCL_CMS (0xC5)\n", header);
    }
    else if (pcl == HAB_PCL_SRK)
    {
        fprintf(output_fp, "%s             PCL: HAB_PCL_SRK (0x03)\n", header);
    }
    else
    {
        fprintf(output_fp, "%s                  FLAGS: Unknown protocol\n", header);
    }
}

/*----------------------------
  parse_aut_dat_cmd
 ----------------------------*/
bool parse_aut_dat_cmd(FILE *output_fp, uint8_t *start, uint8_t *end)
{
    bool     result = false;
    uint8_t  *data_ptr = start;
    uint32_t length;
    uint32_t word;

    do
    {
        data_ptr++; /* Skip TAG field */
        BREAK_IF(data_ptr > end);


        fprintf(output_fp, "%s             CMD: HAB_CMD_AUT_DAT (0xca)\n", header);

        length = EXTRACT_LENGTH(data_ptr);

        /* Update end pointer based on cmd length */
        end = start + length;
        data_ptr += LENGTH_BYTES;
        BREAK_IF(data_ptr > end);
        fprintf(output_fp, "%s             LEN: 0x%04x\n", header, length);
        fprintf(output_fp, "%s             FLG: 0x%02x\n", header, *data_ptr);


        /* Display Authenticate Data Flags */
        display_aut_dat_flags(output_fp, *data_ptr);
        data_ptr++;
        BREAK_IF(data_ptr + 4 > end);

        /* Sig. start address */
        fprintf(output_fp, "%s KPEC Field: 0x%08x\n", header,
                data_ptr[0] << 24 | data_ptr[1] << 16 | data_ptr[2] << 8 | data_ptr[3]);

        fprintf(output_fp, "%s             KEY: 0x%02x\n", header,
                *data_ptr++);

        display_aut_dat_pcl(output_fp, *data_ptr);
        data_ptr++;

        // TODO - parse AUT_DAT Engine and Config fields
        data_ptr++;
        data_ptr++;

        BREAK_IF(data_ptr + 4 > end);
        word = data_ptr[0] << 24 | data_ptr[1] << 16 | data_ptr[2] << 8 | data_ptr[3];
        data_ptr += 4;
        fprintf(output_fp, "%s Sig. Start: 0x%08x\n", header, word);

        if (data_ptr < end)
        {
            fprintf(output_fp, "%s Blk start/bytes:\n", header);
            print_data(output_fp, data_ptr, length - INS_KEY_FIXED_BYTES);
        }

        result = true;
    } while(0);

    return result;
}

/*----------------------------
  parse_ins_key_cmd
 ----------------------------*/
bool parse_ins_key_cmd(FILE *output_fp, uint8_t *start, uint8_t *end)
{
    bool     result = false;
    uint8_t  *data_ptr = start;
    uint32_t length;
//    uint8_t  flags;
//    uint8_t  bytes;
    uint32_t word;

    do {
        data_ptr++; /* Skip TAG field */
        BREAK_IF(data_ptr > end);

        fprintf(output_fp, "%s             CMD: HAB_CMD_INS_KEY (0xbe)\n", header);
        length = EXTRACT_LENGTH(data_ptr);

        /* Update end pointer based on cmd length */
        end = start + length;
        data_ptr += LENGTH_BYTES;
        BREAK_IF(data_ptr > end);
        fprintf(output_fp, "%s             LEN: 0x%04x\n", header, length);

        /* Display flags */
//        flags = (*data_ptr & 0xF8) >> 3;
//        bytes = (*data_ptr & 0x07);
        data_ptr++;
        BREAK_IF(data_ptr > end);
        fprintf(output_fp, "%s             FLG: 0x%02x\n", header, *data_ptr);

        fprintf(output_fp, "%s                  FLAGS: %s", header,
                ins_key_flags[0]);

        /* To Do - parse PAST field */
        word = BYTES_TO_WORD(data_ptr);
        data_ptr += 4;
        BREAK_IF(data_ptr > end);
        fprintf(output_fp, "%s PAST Field: 0x%08x\n", header, word);

        /* Cert Addr */
        word = BYTES_TO_WORD(data_ptr);
        data_ptr += 4;
        BREAK_IF(data_ptr > end);
        fprintf(output_fp, "%s Crt. addr:  0x%08x\n", header, word);

        /* Optional crt_hash field */
        if (data_ptr < end)
        {
            fprintf(output_fp, "%s Crt. hash:\n", header);
            print_data(output_fp, data_ptr, length - INS_KEY_FIXED_BYTES);
        }
        result = true;
    } while(0);

    return result;
}

/*----------------------------
  process_cmd
 ----------------------------*/
bool process_cmd(FILE *output_fp, uint8_t *start, uint32_t bytes)
{
    bool    result = false;
    uint8_t *data_ptr = start;
    uint8_t *end_ptr  = data_ptr + bytes - 1;
    uint8_t cmd;

    cmd = *data_ptr;

    if (VALID_CMD(cmd))
    {
        fprintf(output_fp, "%s Cmd Field:  0x%02x%02x%02x%02x\n", header, cmd,
                data_ptr[1], data_ptr[2], data_ptr[3]);
        switch (cmd)
        {
            case HAB_CMD_AUT_DAT:
                if (parse_aut_dat_cmd(output_fp, start, end_ptr) == false)
                {
                    fprintf(output_fp, "Error: Cannot parse Authenticate Data command\n");
                    exit(1);
                }
                break;

            case HAB_CMD_INS_KEY:
                if (parse_ins_key_cmd(output_fp, start, end_ptr) == false)
                {
                    fprintf(output_fp, "Error: Cannot parse Install Key command\n");
                    exit(1);
                }
                break;
            default:
                fprintf(output_fp, "Error: Unknown command\n");
                exit(1);
                break;
        }

        result = true;
    }

    return result;
}

/*----------------------------
  process_event_record
 ----------------------------*/
void process_event_record(FILE *log_file, record_t *rec)
{
    uint8_t *data_ptr = &rec->contents[4];
    uint32_t i = 0;
    uint32_t length = rec->len - REC_HEADER_BYTES;

    /* Display Status, Reason, Context and Engine fields */
    fprintf(log_file, "SRCE Field: %02x %02x %02x %02x\n", data_ptr[0],
            data_ptr[1], data_ptr[2], data_ptr[3]);

    for (i = 0; i < length; i++)
    {
        if (i == 0) fprintf(log_file, "%s", sts_str[get_sts_idx(data_ptr[i])]);
        else if (i == 1) fprintf(log_file, "%s", rsn_str[get_rsn_idx(data_ptr[i])]);
        else if (i == 2) fprintf(log_file, "%s", ctx_str[get_ctx_idx(data_ptr[i])]);
        else if (i == 3) fprintf(log_file, "%s", eng_str[get_eng_idx(data_ptr[i])]);
        else if (process_cmd(log_file, &data_ptr[i], rec->len - i) == true)
        {
            break;
        }
        /* Event data is not a recognized command */
        else
        {
            fprintf(log_file, "%s Evt Data (hex):\n", header);
            print_data(log_file, &data_ptr[i], rec->len - 8);
            break;
        }
    }
}

/*----------------------------
  read_record
 ----------------------------*/
int32_t extract_record(uint8_t *data_ptr, record_t *rec)
{
        uint32_t read_len = 0;

        do {
                /* Skip tag byte */
                data_ptr++;

                /* Determine record length - includes header word */
                rec->len = EXTRACT_LENGTH(data_ptr);
                data_ptr += 2;

                /* All records start on a word boundary */
                if ((rec->len % BYTES_IN_WORD) != 0)
                        read_len =  rec->len + (BYTES_IN_WORD - (rec->len % 4));
                else
                        read_len = rec->len;

                /* Parameter field */
                rec->par = *data_ptr;
                data_ptr++;

                /* Copy record contents for further processing later */
                if (rec->len == 0)
                {
                        /* Reached end of log */
                        read_len = 0;
                }
                else if ((rec->len) <= MAX_RECORD_BYTES)
                {
                        /* Copy record contents minus the header word */
                        memcpy(&rec->contents[REC_HEADER_BYTES], data_ptr, rec->len - REC_HEADER_BYTES);
                }
                else
                {
                        read_len = -1;
                }

        } while (0);
        return read_len;
}

/*----------------------------
  process_records
 ----------------------------*/
void process_records(FILE *log_file, uint8_t *data, int32_t bytes)
{
    uint8_t *data_ptr = NULL;
    int32_t rec_bytes = 0;
    record_t rec = {0};
    rec.any_rec_flag = false;

    if ((log_file == NULL) || (data == NULL) || (bytes <= 0))
    {
        fprintf(stderr, "Error: Invalid input to process_records\n");
        return;
    }

    data_ptr = data;

    fprintf(log_file, "\n------------+----+------+----+------------------------"
                      "-------------------------\n");
    fprintf(log_file, "Persistent  | T  |  L   | P  | Contents\n");
    fprintf(log_file, "Memory      | a  |  e   | a  |\n");
    fprintf(log_file, "Record      | g  |  n   | r  |\n");
    fprintf(log_file, "Type        |    |  g   |    |\n");
    fprintf(log_file, "            |    |  t   |    |\n");
    fprintf(log_file, "            |    |  h   |    |\n");
    fprintf(log_file, "------------+----+------+----+--------------------------"
                      "-----------------------\n");

    while (bytes > 0)
    {
        /* Read tag byte  */
        rec.tag = *data_ptr;

        /* Check if we need to fix for 64 bit */
        if ((g_64bit == 0) && (tag_valid(rec.tag, 0) == false))
        {
            if ((((uintptr_t) data_ptr) & 0x7) != 0)
            {
                uint8_t tmp_tag;
                int offset;

                offset = 8 - (((uintptr_t) data_ptr) & 0x7);
                tmp_tag = data_ptr[offset];
                if (tag_valid(tmp_tag, 0) == true)
                {
                    g_64bit = 1;
                    data_ptr += offset;
                    bytes -= offset;
                    rec.tag = *data_ptr;
                }
            }
        }

        if (tag_valid(rec.tag, 0) == true)
        {
            /* Send results to output file */
            rec_bytes = extract_record(data_ptr, &rec);
            if (rec_bytes <= 0)
                return;
            data_ptr += rec_bytes;
            if ((g_64bit != 0) && (rec_bytes & 0x7))
            {
                data_ptr += (8 - (rec_bytes & 0x7));
                bytes -= (8 - (rec_bytes & 0x7));
            }
            bytes -= rec_bytes;
            // file size less than total records
            if (bytes < 0)
                return;

            switch (rec.tag)
            {
                case HAB_TAG_ANY:
                    if (enable_verbose)
                        print_record_contents(log_file, &rec, "Free space  ");
                    break;
                case HAB_TAG_KEY:
                    if (enable_verbose)
                        print_record_contents(log_file, &rec, "Key Record  ");
                    break;
                case HAB_TAG_STATE:
                    if (enable_verbose)
                        print_record_contents(log_file, &rec, "State Record");
                    break;
                case HAB_TAG_ALG_DEF:
                    if (enable_verbose)
                        print_record_contents(log_file, &rec, "Default Alg ");
                    break;
                case HAB_TAG_ENG_DAT:
                    if (enable_verbose)
                        print_record_contents(log_file, &rec, "Engine Data ");
                    break;
                case HAB_TAG_BND_DAT:
                    if (enable_verbose)
                        print_record_contents(log_file, &rec, "Bind Data   ");
                    break;
                case HAB_TAG_EVT_DEF:
                    if (enable_verbose)
                        print_record_contents(log_file, &rec, "Default Evt ");
                    break;
                case HAB_TAG_GENERIC:
                    if (enable_verbose)
                        print_record_contents(log_file, &rec, "Generic     ");
                    break;
                case HAB_TAG_INIT:
                    if (enable_verbose)
                        print_record_contents(log_file, &rec, "Init        ");
                    break;
                case HAB_TAG_UNLK:
                    if (enable_verbose)
                        print_record_contents(log_file, &rec, "Unlock      ");
                    break;
                case HAB_KEY_PUBLIC:
                    if (enable_verbose)
                    {
                        fprintf(log_file, "%s|0x%02x|0x%04x|0x%02x| ",
                                "Public Key  ", rec.tag, rec.len, rec.par);
                        (void) process_public_key(log_file, &rec);
                    }
                    break;
                case HAB_KEY_MASTER:
                    if (enable_verbose)
                        print_record_contents(log_file, &rec, "Master Key  ");
                    break;
                case HAB_TAG_EVT:
                    fprintf(log_file, "%s|0x%02x|0x%04x|0x%02x| ",
                            "Event       ", rec.tag, rec.len, rec.par);
                    process_event_record(log_file, &rec);
                    fprintf(log_file,
                            "------------+----+------+----+--------------------"
                            "-----------------------------\n");

                    break;
                default:
                    /* Nothing yet */
                    break;
            }
            // fprintf(log_file, "------------+----+------+----+-------------------------------------------------\n");
        }
        /* Keep searching for a valid TAG */
        else
        {
            data_ptr++;
            bytes--;
        }
        }
}

/*
 * Description : This function reads the inputs file and returns size
 *
 * @Inputs  : fp         - Input file pointer
 *            input_file - Input file name
 *
 * @Outputs : return File size
 *
 */
static int get_file_size(FILE *fp)
{
        int ret = 0;

        /* Seek to the end of file to calculate size */
        if (fseek(fp , 0 , SEEK_END)) {
                errno = ENOENT;
                fprintf(stderr, "Error: Couldn't seek to end of file: error %s\n", strerror(errno));
                return -1;
        }

        /* Get size and go back to start of the file */
        ret = ftell(fp);
        rewind(fp);

        return ret;
}

/*----------------------------
  print_usage
 ----------------------------*/
void print_usage(void)
{
#ifndef NO_USB_SUPPORT
        int i = 0;
#endif
        printf("\nUsage:\n");
        printf("        hab_log_parser [input] [output]\n");
        printf("Input:\n");
        printf("        -s|--sdp <device_name>: SDP mode selected with Device name required\n");
#ifdef NO_USB_SUPPORT
        printf("                 *** SDP mode not supported for this platform ***\n");
#else
        printf("                 <device_name>:\n");
        for (i = 0; i < MAX_DEV; i++)
                printf("                        '-----%s\n", dev_info[i].dev);
#endif
        printf("        -b|--input-bin <input file>: Binary file containing a dump of HAB4 persistent memory contents\n");
        printf("        -a|--input-ascii <input file>: Ascii file containing a dump of HAB4 persistent memory contents\n");
        printf("Output (Optional):\n");
        printf("        -o|--output <output>: File of the parsed HAB4 persistent memory region\n");
        printf("                            : If output not provided output is sent to stdout\n");
        printf("Verbose (all records):\n");
        printf("        -v|--verbose : Print all records\n\n");
        printf("Examples:\n");
        printf("SDP:\n");
        printf("        ./hab_log_parser -s imx6s -o hab_log_parsed.txt\n");
        printf("Binary Input file:\n");
        printf("        ./hab_log_parser -b hab4_pers.bin -o hab_log_parsed.txt\n");
        printf("ASCII Input file:\n");
        printf("        ./hab_log_parser -a hab4_pers.ascii -o hab_log_parsed.txt\n\n");
        exit(EXIT_SUCCESS);
}

/*
 * Description : Handle each command line option
 *
 * @inputs     : Command line arguments
 */
void handle_cli(int argc, char **argv)
{
        int next_opt = 0;
        int mandatory_opt = 0;
        int i = 0;
        bool device_found = false;

        /* Check for minimum arguments */
        if (argc < 2 || argc > 6) {
                puts("Error: Incomplete options\n");
                print_usage();
                exit(EXIT_FAILURE);
        }

        /* Start from the first command-line option */
        optind = 0;

        /* Handle command line options*/
        do
        {
                next_opt = getopt_long(argc, argv, short_opt, long_opt, NULL);
                switch (next_opt)
                {
                /* SDP mode */
                case 's':
                        mandatory_opt += 1;
                        for (i = 0; i < sizeof(device)/sizeof(device[0]); i++) {
                                if (strncmp(optarg, device[i], MAX_DEV_NAME) == 0) {
                                        device_found = true;
                                }
                        }

                        if (!device_found) {
                                /* Device not found */
                                fprintf(stderr, "Error: Device %s is invalid\n", optarg);
                                print_usage();
                                exit(EXIT_FAILURE);
                        }
                        break;
                /* Binary Input */
                case 'b':
                /* ASCII Input */
                case 'a':
                        mandatory_opt += 1;
                        break;
                /* Verbose option */
                case 'v':
                        enable_verbose = true;
                        break;
                /* Display usage */
                case 'h':
                        print_usage();
                        exit(EXIT_SUCCESS);
                        break;
                case '?':
                        /* Input option with no parameter */
                        if ((optopt == 'b' || optopt == 'a' || optopt == 'o' || optopt == 's') && (optarg == NULL)) {
                                fprintf(stderr, "Error: Option -%c requires an operand\n", optopt);
                                print_usage();
                                exit(EXIT_FAILURE);
                        }
                        /* Unknown character returned */
                        print_usage();
                        exit(EXIT_FAILURE);
                        break;
                /* At the end check if mandatory options are present */
                default:
                        if (mandatory_opt != 1) {
                                puts("Error: Incorrect options\n");
                                print_usage();
                                exit(EXIT_FAILURE);
                        }
                        break;
                }
        } while (next_opt != -1);
}

/*
 * Description : build an array of devices and its details
 */
void build_device_info()
{
        int i;

        for (i = 0; i < MAX_DEV; i++)
        {
                strncpy(dev_info[i].dev, device[i], MAX_DEV_NAME);

                if(strncmp(device[i], "imx6sll", 7) == 0) {
                        dev_info[i].hab_pers_mem = IMX6_HAB_PERS_MEM;
                        dev_info[i].hab_pers_mem_size = MAX_PERS_SIZE_V1;
                        dev_info[i].vendor_id = VENDOR_ID_NXP;
                }
                else if (strncmp(device[i], "imx6", 4) == 0) {
                        dev_info[i].hab_pers_mem = IMX6_HAB_PERS_MEM;
                        dev_info[i].hab_pers_mem_size = MAX_PERS_SIZE_V1;
                        dev_info[i].vendor_id = VENDOR_ID_FSL;
                }
                else if ((strncmp(device[i], "imx7s", 5) == 0) ||
                         (strncmp(device[i], "imx7d", 5) == 0)) {
                        dev_info[i].hab_pers_mem = IMX7SD_HAB_PERS_MEM;
                        dev_info[i].hab_pers_mem_size = MAX_PERS_SIZE_V1;
                        dev_info[i].vendor_id = VENDOR_ID_FSL;
                }
                else if (strncmp(device[i], "imx7ulpa7", 9) == 0) {
                        dev_info[i].hab_pers_mem = IMX7ULPA7_HAB_PERS_MEM;
                        dev_info[i].hab_pers_mem_size = MAX_PERS_SIZE_V1;
                        dev_info[i].vendor_id = VENDOR_ID_NXP;
                }
                else if (strncmp(device[i], "imx7ulpm4", 9) == 0) {
                        dev_info[i].hab_pers_mem = IMX7ULPM4_HAB_PERS_MEM;
                        dev_info[i].hab_pers_mem_size = MAX_PERS_SIZE_V1;
                        dev_info[i].vendor_id = VENDOR_ID_NXP;
                }
                else if (strncmp(device[i], "imx8mq", 6) == 0) {
                        dev_info[i].hab_pers_mem = IMX8MQ_HAB_PERS_MEM;
                        dev_info[i].hab_pers_mem_size = MAX_PERS_SIZE_V2;
                        dev_info[i].vendor_id = VENDOR_ID_NXP;
                }
                else if (strncmp(device[i], "imx8mm", 6) == 0) {
                        dev_info[i].hab_pers_mem = IMX8MM_MN_HAB_PERS_MEM;
                        dev_info[i].hab_pers_mem_size = MAX_PERS_SIZE_V1;
                        dev_info[i].vendor_id = VENDOR_ID_NXP;
                }
                else if (strncmp(device[i], "imx8mn", 6) == 0) {
                        dev_info[i].hab_pers_mem = IMX8MM_MN_HAB_PERS_MEM;
                        dev_info[i].hab_pers_mem_size = MAX_PERS_SIZE_V2;
                        dev_info[i].vendor_id = VENDOR_ID_NXP;
                }
                else if (strncmp(device[i], "imx8mp", 6) == 0) {
                        dev_info[i].hab_pers_mem = IMX8MP_HAB_PERS_MEM;
                        dev_info[i].hab_pers_mem_size = MAX_PERS_SIZE_V2;
                        dev_info[i].vendor_id = VENDOR_ID_NXP;
                }
        }
}

int main(int argc, char **argv)
{
        FILE *fp_in = NULL;
        FILE *fp_out = NULL;
        FILE *fp_sdp = NULL;
        uint8_t *buf_in = NULL;
        int file_size = 0;
        int next_opt = 0;
        size_t result;
        int input;
        uint8_t c1, c2;
        char tmp_string[9];
        uint32_t bytes_read = 0;
        int ret = 0;
        hid_device *handle = NULL;
        uint32_t hab_addr = 0;
        uint32_t hab_pers_region_size = 0;
        int i = 0;
        uint16_t vid = 0;

        /* Build device related information like HAB persistent memory and vendor ID */
        build_device_info();

        /* Handle command line options */
        handle_cli(argc, argv);

        /* Start from the first command-line option */
        optind = 0;

        /* Perform actions according to command-line option */
        do
        {
                next_opt = getopt_long(argc, argv, short_opt, long_opt, NULL);
                switch (next_opt)
                {
                /* Binary input */
                case 'b':
                        /* Open file */
                        fp_in = fopen(optarg, "rb");
                        if (fp_in == NULL) {
                                fprintf(stderr, "Error: Couldn't open file %s; %s\n", optarg, strerror(errno));
                                return -1;
                        }

                        /* Read input file for reading log */
                        file_size = get_file_size(fp_in);
                        if (file_size < 0) {
                                fprintf(stderr, "Error: File read error; %s\n", strerror(errno));
                                goto err;
                        }

                        /* Allocate memory to the buf_infer */     
                        buf_in = malloc(file_size);
                        if (buf_in == NULL || buf_in == 0) {
                                fprintf(stderr, "Error: Error allocating memory; %s\n", strerror(errno));
                                goto err;
                        }

                        /* Copy the file into the buf_infer */
                        result = fread(buf_in, 1, file_size, fp_in);
                        if (result != file_size) {
                                fprintf(stderr, "Error: File read error; %s\n", strerror(errno));
                                goto err;
                        }

                        fclose(fp_in);
                        fp_in = NULL;
                        break;
                /* ASCII input */
                case 'a':
                        /* Open file */
                        fp_in = fopen(optarg, "r");
                        if (fp_in == NULL) {
                                fprintf(stderr, "Error: Couldn't open file %s; %s\n", optarg, strerror(errno));
                                return -1;
                        }

                        /* Read input file for reading log */
                        file_size = get_file_size(fp_in);
                        if (file_size < 0) {
                                fprintf(stderr, "Error: File read error; %s\n", strerror(errno));
                                goto err;
                        }

                        /* Allocate memory to the buf_infer */
                        buf_in = malloc(file_size);
                        if (buf_in == NULL || buf_in == 0) {
                                fprintf(stderr, "Error: Error allocating memory; %s\n", strerror(errno));
                                goto err;
                        }

                        /* Read file contents into input buffer */
                        while ( ((input = fgetc(fp_in)) != EOF) &&
                                (bytes_read < file_size) )
                        {
                                /* Initialize tmp_string to zero */
                                memset(tmp_string, 0, 9);

                                /* First character */
                                c1 = (uint8_t)input;

                                /* Skip invalid characters */
                                if (!VALID_CHAR(c1))
                                {
                                        continue;
                                }
                                else
                                {
                                        /* Read next character */
                                        if ((input = fgetc(fp_in)) != EOF)
                                        {
                                                c2 = (uint8_t)input;
                                                if (!VALID_CHAR(c2))
                                                {
                                                        continue;
                                                }

                                                /* Convert hex characters */
                                                tmp_string[0] = c1;
                                                tmp_string[1] = c2;
                                                buf_in[bytes_read++] = htoi(tmp_string);
                                        }
                                        else {
                                                break;
                                        }
                                }
                        }

                        fclose(fp_in);
                        fp_in = NULL;

                        break;
                /* SDP mode */
                case 's':
#ifdef NO_USB_SUPPORT
                        puts("SDP mode not supported\n");
#else
                        puts("SDP mode selected\n");

                        /* Find out HAB persistent memory address and vendor id based on the chip */
                        for (i = 0; i < MAX_DEV; i++) {
                                if (strncmp(optarg, dev_info[i].dev, sizeof(dev_info[i].dev)) == 0) {
                                        hab_addr = dev_info[i].hab_pers_mem;
                                        hab_pers_region_size = dev_info[i].hab_pers_mem_size;
                                        vid = dev_info[i].vendor_id;
                                        break;
                                }
                        }

                        if (!hab_addr && !vid) {
                                puts("Error: Device not found\n");
                                goto err;
                        }

                        ret = init_dev(&handle, vid);
                        if(ret) {
                                handleSDPError(ret);
                                exit(ret);
                        }

                        /* Open temporary file for writing */
                        fp_sdp = fopen(".log.tmp", "wb+");
                        if (fp_sdp == NULL) {
                                fprintf(stderr, "Error: Couldn't open file .log.tmp; %s\n", strerror(errno));
                                goto err;
                        }

                        ret = read_register(&handle, hab_addr, FORMAT_8_BIT, hab_pers_region_size, FILEOUTPUT, ".log.tmp");
                        if(ret){
                            if (remove(".log.tmp") != 0)
                            {
                                fprintf(stderr,
                                        "Warning: Failed to remove temporary "
                                        "file %s. errno: %d\n",
                                        ".log.tmp", errno);
                            }
                                handleSDPError(ret);
                                goto err;
                        }

                        /* Read file contents into input buffer */
                        buf_in = malloc(hab_pers_region_size);
                        if (buf_in == NULL || buf_in == 0) {
                                fprintf(stderr, "Error: Error allocating memory; %s\n", strerror(errno));
                                goto err;
                        }

                        while ( ((input = fgetc(fp_sdp)) != EOF) &&
                                (bytes_read < hab_pers_region_size) )
                        {
                                /* First character */
                                c1 = (uint8_t)input;

                                /* Skip invalid characters */
                                if (!VALID_CHAR(c1))
                                {
                                        continue;
                                }
                                else
                                {
                                        /* Read next character */
                                        if ((input = fgetc(fp_sdp)) != EOF)
                                        {
                                                c2 = (uint8_t)input;
                                                if (!VALID_CHAR(c2))
                                                {
                                                        continue;
                                                }

                                                /* Convert hex characters */
                                                tmp_string[0] = c1;
                                                tmp_string[1] = c2;
                                                buf_in[bytes_read++] = htoi(tmp_string);
                                        }
                                        else {
                                                break;
                                        }
                                }
                        }

                        fclose(fp_sdp);
                        fp_sdp = NULL;
#endif
                        break;
                case 'o':
                        /* Open output file for writing */
                        fp_out = fopen(optarg, "w+");
                        if (fp_out == NULL) {
                                fprintf(stderr, "Error: Couldn't open file %s; %s\n", optarg, strerror(errno));
                                puts("Output selected as Standard Output\n");
                                fp_out = stdout;
                        }
                        break;
                default:
                        /* If no output file provided, then choose stdout */
                        if (fp_out == NULL) {
                                puts("Output selected as Standard Output\n");
                                fp_out = stdout;
                        }
                        break;
                }
        } while (next_opt != -1);

        /* Process the input binary log */
        process_records(fp_out, buf_in, bytes_read);

        free(buf_in);
        if (fp_out != stdout)
        {
            fclose(fp_out);
            fp_out = NULL;
        }

        return EXIT_SUCCESS;

err:
        if (fp_in != NULL)
                fclose(fp_in);
        if (fp_sdp != NULL)
                fclose(fp_sdp);
        if (fp_out != stdout && fp_out != NULL)
                fclose(fp_out);
        if (buf_in)
                free(buf_in);
        return EXIT_FAILURE;
}
