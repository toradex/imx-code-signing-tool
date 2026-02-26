/*
 * Copyright 2018, 2020, 2022 NXP
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

/*===========================================================================
                                INCLUDE FILES
=============================================================================*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <getopt.h>
#include <errno.h>

/*===========================================================================
                               GLOBAL VARIABLES
=============================================================================*/
int g_64bit = 0;
bool enable_verbose = false;

/*
 * Devices supported
 * Increment MAX_DEV_NAME if new device description is more than 10 characters
 * Increment MAX_DEV if new device is added
 */
#define MAX_DEV_NAME 10
#define MAX_DEV 19

const char device[][MAX_DEV_NAME] = {
                {"imx6s"},
                {"imx6dl"},
                {"imx6q"},
                {"imx6d"},
                {"imx6qp"},
                {"imx6dp"},
                {"imx6sl"},
                {"imx6sll"},
                {"imx6sx"},
                {"imx6ul"},
                {"imx6ull"},
                {"imx7s"},
                {"imx7d"},
                {"imx7ulpa7"},
                {"imx7ulpm4"},
                {"imx8mq"},
                {"imx8mm"},
                {"imx8mn"},
                {"imx8mp"}
              };

/*===========================================================================
                        Command line arguments
=============================================================================*/
/* Valid short command line option letters. */
const char* const short_opt = "hvs:b:a:o:";

/* Valid long command line options. */
const struct option long_opt[] =
{
        {"sdp", required_argument, 0, 's'},
        {"input-bin", required_argument, 0, 'b'},
        {"input-ascii", required_argument, 0, 'a'},
        {"output", required_argument,  0, 'o'},
        {"help", no_argument, 0, 'h'},
        {"verbose", no_argument, 0, 'v'},
        {NULL, 0, NULL, 0}
};

/*===========================================================================
                               LOCAL CONSTANTS
=============================================================================*/
// #define MIN_NUM_CLI          3    /**< Minimum number of command line inputs */

#define HAB_TAG_ANY          0x00 /**< Wildcard - match any structure */
#define HAB_TAG_INVALID      0x01 /**< Invalid tag - breaks Hamming distance */
#define HAB_TAG_KEY          0x03 /**< Key record */
#define HAB_TAG_STATE        0x05 /**< State record */
#define HAB_TAG_ALG_DEF      0x06 /**< Algorithm defaults */
#define HAB_TAG_ENG_DAT      0x09 /**< Engine data */
#define HAB_TAG_BND_DAT      0x0a /**< Binding data */
#define HAB_TAG_EVT_DEF      0x0c /**< Event defaults */
#define HAB_TAG_GENERIC      0x0f /**< Generic data */
#define HAB_TAG_INIT         0x11 /**< Initialization record */
#define HAB_TAG_UNLK         0x12 /**< Unlock record */
#define HAB_TAG_EVT          0xdb /**< Event */
#define HAB_TAG_PLG          0xde /**< Plugin */
#define HAB_KEY_PUBLIC       0xe1 /**< Public key type: data present */
#define HAB_KEY_SECRET       0xe2 /**< Secret key type: data present */
#define HAB_KEY_MASTER       0xed /**< Master KEK type */

#define MAX_RECORD_BYTES     0xB80

#define REC_HEADER_BYTES     4    /* All record headers are 4 bytes long */
#define BITS_IN_BYTE         8
#define BYTES_IN_WORD        4
#define LENGTH_BYTES         2

#define INS_KEY_FIXED_BYTES  12
// #define SET_CMD_HDR_BYTES    4

#define END_RECORD_COUNT     8

#define MAX_PERS_SIZE_V1 0xB80
#define MAX_PERS_SIZE_V2 0x1200

#define IMX6_HAB_PERS_MEM       0x00904000
#define IMX7SD_HAB_PERS_MEM     0x009049C0
#define IMX7ULPA7_HAB_PERS_MEM  0x2F006840
#define IMX7ULPM4_HAB_PERS_MEM  0x20008040
#define IMX8MQ_HAB_PERS_MEM     0x009061C0
#define IMX8MM_MN_HAB_PERS_MEM  0x00908040
#define IMX8MP_HAB_PERS_MEM     0x0090D040

typedef enum hab_context {
    HAB_CTX_ANY = 0x00,         /**< Match any context in
                                 * hab_rvt.report_event()
                                 */
/** @cond rom */
    HAB_CTX_FAB = 0xff,         /**< @rom Event logged in hab_fab_test() */
/** @endcond */
    HAB_CTX_ENTRY = 0xe1,       /**< Event logged in hab_rvt.entry() */
    HAB_CTX_TARGET = 0x33,      /**< Event logged in hab_rvt.check_target() */
    HAB_CTX_AUTHENTICATE = 0x0a, /**< Event logged in
                                  *   hab_rvt.authenticate_image() 
                                  */
    HAB_CTX_DCD = 0xdd,         /**< Event logged in hab_rvt.run_dcd() */
    HAB_CTX_CSF = 0xcf,         /**< Event logged in hab_rvt.run_csf() */
    HAB_CTX_COMMAND = 0xc0,     /**< Event logged executing @ref csf or @ref
                                 *   dcd command
                                 */
    HAB_CTX_AUT_DAT = 0xdb,     /**< Authenticated data block */
    HAB_CTX_ASSERT = 0xa0,      /**< Event logged in hab_rvt.assert() */
    HAB_CTX_EXIT = 0xee,        /**< Event logged in hab_rvt.exit() */
    HAB_CTX_MAX
} hab_context_t;

typedef enum hab_reason {
    HAB_RSN_ANY = 0x00,         /**< Match any reason in
                                 * hab_rvt.report_event()
                                 */
    HAB_ENG_FAIL = 0x30,        /**< Engine failure. */
    HAB_INV_ADDRESS = 0x22,     /**< Invalid address: access denied. */
    HAB_INV_ASSERTION = 0x0c,   /**< Invalid assertion. */
    HAB_INV_CALL = 0x28,        /**< Function called out of sequence. */
    HAB_INV_CERTIFICATE = 0x21, /**< Invalid certificate. */
    HAB_INV_COMMAND = 0x06,     /**< Invalid command: command malformed. */
    HAB_INV_CSF = 0x11,         /**< Invalid @ref csf. */
    HAB_INV_DCD = 0x27,         /**< Invalid @ref dcd. */
    HAB_INV_INDEX = 0x0f,       /**< Invalid index: access denied. */
    HAB_INV_IVT = 0x05,         /**< Invalid @ref ivt. */
    HAB_INV_KEY = 0x1d,         /**< Invalid key. */
    HAB_INV_RETURN = 0x1e,      /**< Failed callback function. */
    HAB_INV_SIGNATURE = 0x18,   /**< Invalid signature. */
    HAB_INV_SIZE = 0x17,        /**< Invalid data size. */
    HAB_MEM_FAIL = 0x2e,        /**< Memory failure. */
    HAB_OVR_COUNT = 0x2b,       /**< Expired poll count. */
    HAB_OVR_STORAGE = 0x2d,     /**< Exhausted storage region. */
    HAB_UNS_ALGORITHM = 0x12,   /**< Unsupported algorithm. */
    HAB_UNS_COMMAND = 0x03,     /**< Unsupported command. */
    HAB_UNS_ENGINE = 0x0a,      /**< Unsupported engine. */
    HAB_UNS_ITEM = 0x24,        /**< Unsupported configuration item. */
    HAB_UNS_KEY = 0x1b,         /**< Unsupported key type or parameters. */
    HAB_UNS_PROTOCOL = 0x14,    /**< Unsupported protocol. */
    HAB_UNS_STATE = 0x09,       /**< Unsuitable state. */
    HAB_RSN_MAX
} hab_reason_t;

typedef enum hab_status {
    HAB_STS_ANY = 0x00,         /**< Match any status in
                                 * hab_rvt.report_event()
                                 */
    HAB_FAILURE = 0x33,         /**< Operation failed */
    HAB_WARNING = 0x69,         /**< Operation completed with warning */
    HAB_SUCCESS = 0xf0,         /**< Operation completed successfully */
    HAB_STS_MAX
} hab_status_t;

#define HAB_CMD_SET       0xb1  /**< Set */
#define HAB_CMD_INS_KEY   0xbe  /**< Install Key */
#define HAB_CMD_AUT_DAT   0xca  /**< Authenticate Data */
#define HAB_CMD_WRT_DAT   0xcc  /**< Write Data */
#define HAB_CMD_CHK_DAT   0xcf  /**< Check Data */
#define HAB_CMD_NOP       0xc0  /**< No Operation */
#define HAB_CMD_INIT      0xb4  /**< Initialise */
#define HAB_CMD_UNLK      0xb2  /**< Unlock */

typedef enum hab_cmd_aut_dat_flg
{
    HAB_CMD_AUT_DAT_CLR = 0,    /**< No flags set */
    HAB_CMD_AUT_DAT_ABS = 1     /**< Absolute signature address */
} hab_cmd_aut_dat_flg_t;

#define HAB_ENG_ANY      0x00   /**< First compatible engine will be */
#define HAB_ENG_SCC      0x03   /**< Security controller */
#define HAB_ENG_RTIC     0x05   /**< Run-time integrity checker */
#define HAB_ENG_SAHARA   0x06   /**< Crypto accelerator */
#define HAB_ENG_CSU      0x0a   /**< Central Security Unit */
#define HAB_ENG_SRTC     0x0c   /**< Secure clock */
#define HAB_ENG_DCP      0x1b   /**< Data Co-Processor */
#define HAB_ENG_CAAM     0x1d   /**< Cryptographic Acceleration and
                                     Assurance Module */
#define HAB_ENG_SNVS     0x1e   /**< Secure Non-Volatile Storage */
#define HAB_ENG_OCOTP    0x21   /**< Fuse controller */
#define HAB_ENG_DTCP     0x22   /**< DTCP co-processor */
#define HAB_ENG_HDMI     0x27   /**< HDMI firmware processing */
#define HAB_ENG_ROM      0x36   /**< Protected ROM area */
#define HAB_ENG_HDCP     0x24   /**< HDCP co-processor */
#define HAB_ENG_RTL      0x77   /**< @rom RTL simulation engine */
#define HAB_ENG_SW       0xff   /**< Software engine */

#define HAB_PCL_SRK      0x03   /**< SRK certificate format */
#define HAB_PCL_X509     0x09   /**< X.509v3 certificate format */
#define HAB_PCL_CMS      0xc5   /**< CMS/PKCS#7 signature format */
#define HAB_PCL_BLOB     0xbb   /**< SHW-specific wrapped key format */
#define HAB_PCL_AEAD     0xa3   /**< Proprietary AEAD MAC format */

/*===========================================================================
                                 LOCAL MACROS
=============================================================================*/
#define VALID_CHAR(c) \
    ((((c) >= '0') && ((c) <= '9')) || \
     (((c) >= 'A') && ((c) <= 'F')) || \
     (((c) >= 'a') && ((c) <= 'f')) || \
     (((c) == 'x') || ((c) == 'X')))

#define VALID_CMD(cmd) \
    (((cmd) == HAB_CMD_SET)     || ((cmd) == HAB_CMD_INS_KEY) || \
     ((cmd) == HAB_CMD_AUT_DAT) || ((cmd) == HAB_CMD_WRT_DAT) || \
     ((cmd) == HAB_CMD_CHK_DAT) || ((cmd) == HAB_CMD_NOP)     || \
     ((cmd) == HAB_CMD_INIT)    || ((cmd) == HAB_CMD_UNLK))

#define BYTES_TO_WORD(p) \
    ((p)[0] << 24 | (p)[1] << 16 | (p)[2] << 8 | (p)[3])

#define EXTRACT_LENGTH(p) \
    (((p)[0] << BITS_IN_BYTE) | (p)[1])

/** Break on condition
 *
 * @param [in] c   boolean condition
 *
 * @pre None.
 *
 * @post None.
 *
 * @remark This macro may be used only within a loop where a statement is
 * expected.
 */
#define BREAK_IF(c)                         \
    if (c) { break; }

/*===========================================================================
                  LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
=============================================================================*/
typedef struct record
{
        uint8_t  tag;                        /* Tag */
        uint32_t len;                        /* Length */
        uint8_t  par;                        /* Parameters/Version field */
        uint8_t  contents[MAX_RECORD_BYTES]; /* Record Data */
        bool     any_rec_flag;
} record_t;

char *header = "            |    |      |    |";

char *sts_str[] = {"            |    |      |    |             STS = HAB_SUCCESS (0xF0)\n",
                   "            |    |      |    |             STS = HAB_FAILURE (0x33)\n",
                   "            |    |      |    |             STS = HAB_WARNING (0x69)\n",
                   "            |    |      |    |             STS = INVALID\n"};

char *rsn_str[] = {"            |    |      |    |             RSN = HAB_RSN_ANY (0x00)\n",
                   "            |    |      |    |             RSN = HAB_ENG_FAIL (0x30)\n",
                   "            |    |      |    |             RSN = HAB_INV_ADDRESS (0x22)\n",
                   "            |    |      |    |             RSN = HAB_INV_ASSERTION (0x0C)\n",
                   "            |    |      |    |             RSN = HAB_INV_CALL (0x28)\n",
                   "            |    |      |    |             RSN = HAB_INV_CERTIFICATE (0x21)\n",
                   "            |    |      |    |             RSN = HAB_INV_COMMAND (0x06)\n",
                   "            |    |      |    |             RSN = HAB_INV_CSF (0x11)\n",
                   "            |    |      |    |             RSN = HAB_INV_DCD (0x27)\n",
                   "            |    |      |    |             RSN = HAB_INV_INDEX (0x0F)\n",
                   "            |    |      |    |             RSN = HAB_INV_IVT (0x05)\n",
                   "            |    |      |    |             RSN = HAB_INV_KEY (0x1D)\n",
                   "            |    |      |    |             RSN = HAB_INV_RETURN (0x1E)\n",
                   "            |    |      |    |             RSN = HAB_INV_SIGNATURE (0x18)\n",
                   "            |    |      |    |             RSN = HAB_INV_SIZE (0x17)\n",
                   "            |    |      |    |             RSN = HAB_MEM_FAIL (0x2E)\n",
                   "            |    |      |    |             RSN = HAB_OVR_COUNT (0x2B)\n",
                   "            |    |      |    |             RSN = HAB_OVR_STORAGE (0x2D)\n",
                   "            |    |      |    |             RSN = HAB_UNS_ALGORITHM (0x12)\n",
                   "            |    |      |    |             RSN = HAB_UNS_COMMAND (0x03)\n",
                   "            |    |      |    |             RSN = HAB_UNS_ENGINE (0x0A)\n",
                   "            |    |      |    |             RSN = HAB_UNS_ITEM (0x24)\n",
                   "            |    |      |    |             RSN = HAB_UNS_KEY (0x1B)\n",
                   "            |    |      |    |             RSN = HAB_UNS_PROTOCOL (0x14)\n",
                   "            |    |      |    |             RSN = HAB_UNS_STATE (0x09)\n",
                   "            |    |      |    |             RSN = INVALID\n"};

char *ctx_str[] = {"            |    |      |    |             CTX = HAB_CTX_ANY(0x00)\n",
                   "            |    |      |    |             CTX = HAB_CTX_FAB (0xFF)\n",
                   "            |    |      |    |             CTX = HAB_CTX_ENTRY (0xE1)\n",
                   "            |    |      |    |             CTX = HAB_CTX_TARGET (0x33)\n",
                   "            |    |      |    |             CTX = HAB_CTX_AUTHENTICATE (0x0A)\n",
                   "            |    |      |    |             CTX = HAB_CTX_DCD (0xDD)\n",
                   "            |    |      |    |             CTX = HAB_CTX_CSF (0xCF)\n",
                   "            |    |      |    |             CTX = HAB_CTX_COMMAND (0xC0)\n",
                   "            |    |      |    |             CTX = HAB_CTX_AUT_DAT (0xDB)\n",
                   "            |    |      |    |             CTX = HAB_CTX_ASSERT (0xA0)\n",
                   "            |    |      |    |             CTX = HAB_CTX_EXIT (0xEE)\n",
                   "            |    |      |    |             CTX = INVALID\n"};

char *eng_str[] = {"            |    |      |    |             ENG = HAB_ENG_ANY (0x00)\n",
                   "            |    |      |    |             ENG = HAB_ENG_SCC (0x03)\n",
                   "            |    |      |    |             ENG = HAB_ENG_RTIC (0x05)\n",
                   "            |    |      |    |             ENG = HAB_ENG_SAHARA (0x06)\n",
                   "            |    |      |    |             ENG = HAB_ENG_CSU (0x0A)\n",
                   "            |    |      |    |             ENG = HAB_ENG_SRTC (0x0C)\n",
                   "            |    |      |    |             ENG = HAB_ENG_DCP (0x1B)\n",
                   "            |    |      |    |             ENG = HAB_ENG_RTL (0x77)\n",
                   "            |    |      |    |             ENG = HAB_ENG_SW (0xFF)\n",
                   "            |    |      |    |             ENG = HAB_ENG_CAAM (0x1d)\n",
                   "            |    |      |    |             ENG = HAB_ENG_SNVS (0x1e)\n",
                   "            |    |      |    |             ENG = INVALID\n"};

#define NUM_PKCS1_KEY_FLAGS 9
char *pkcs1_key_flags[] = {"KEY_FLG_UNDEF (0x01)\n",
                           "KEY_FLG_UNDEF (0x02)\n",
                           "KEY_FLG_DAT   (0x04)\n",
                           "KEY_FLG_CFG   (0x08)\n",
                           "KEY_FLG_FID   (0x10)\n",
                           "KEY_FLG_MID   (0x20)\n",
                           "KEY_FLG_CID   (0x40)\n",
                           "KEY_FLG_CA    (0x80)\n"};

char *aut_dat_flags[] = {"AUT_DAT_CLR (0x00)\n",
                         "AUT_DAT_ABS (0x01)\n"};
                         
char *ins_key_flags[] = {"NOTHING YET\n"};


struct device_info
{
        char dev[MAX_DEV_NAME];           /* Device */
        uint32_t hab_pers_mem;  /* HAB persistent memory */
        uint32_t hab_pers_mem_size;
        uint16_t vendor_id;     /* Vendor ID */
} dev_info[MAX_DEV];
