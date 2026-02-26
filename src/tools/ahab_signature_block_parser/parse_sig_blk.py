#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright 2019-2023 NXP
#

import os
import shutil
from optparse   import OptionParser
from common     import *
from hashlib    import sha512, sha256

# Definitions

CONTAINER_HEADER_TAG      = 0x87
SIGNED_MESSAGE_HEADER_TAG = 0x89

ahab_cont_tags = {
    CONTAINER_HEADER_TAG      : "Image array",
    SIGNED_MESSAGE_HEADER_TAG : "Message"
}

HEADER_FLAGS_SRK_SET_NONE = 0x0
HEADER_FLAGS_SRK_SET_NXP  = 0x1
HEADER_FLAGS_SRK_SET_OEM  = 0x2

ahab_srk_sets = {
    HEADER_FLAGS_SRK_SET_NONE : "No authentication",
    HEADER_FLAGS_SRK_SET_NXP  : "NXP",
    HEADER_FLAGS_SRK_SET_OEM  : "OEM"
}

SRK_SHA256 = 0x0
SRK_SHA384 = 0x1
SRK_SHA512 = 0x2

ahab_hsh_algs = {
    SRK_SHA256 : STR_SHA256,
    SRK_SHA384 : STR_SHA384,
    SRK_SHA512 : STR_SHA512
}

SIGNATURE_BLOCK_TAG = 0x90

SRK_TABLE_TAG       = 0xD7
SRK_TABLE_VERSION   = 0x42

SRK_TAG             = 0xE1

SRK_RSA             = 0x21
SRK_RSA_PSS         = 0x22
SRK_ECDSA           = 0x27

ahab_sig_algs = {
    SRK_RSA     : "RSA",
    SRK_RSA_PSS : "RSA_PSS",
    SRK_ECDSA   : "ECDSA"
}

SRK_SECP256R1   = 0x1
SRK_SECP384R1   = 0x2
SRK_SECP521R1   = 0x3
SRK_RSA2048     = 0x5
SRK_RSA3072     = 0x6
SRK_RSA4096     = 0x7

ahab_key_types = {
    SRK_SECP256R1   : STR_SECP256R1,
    SRK_SECP384R1   : STR_SECP384R1,
    SRK_SECP521R1   : STR_SECP521R1,
    SRK_RSA2048     : "rsa2048",
    SRK_RSA3072     : "rsa3072",
    SRK_RSA4096     : "rsa4096"
}

CERTIFICATE_TAG     = 0xAF
CERTIFICATE_VERSION = 0

SIGNATURE_TAG     = 0xD8
SIGNATURE_VERSION = 0

# Function to decode RSA and ECC public keys

def decode_public_key(infile, offset):

    if SRK_TAG != bytes2int(get_bytes(infile, offset, 1)):
        error("invalid record tag")

    length = bytes2int(get_bytes(infile, offset + 1, 2))

    record = get_bytes(infile, offset, length)

    sig_alg = bytes2int(get_bytes(infile, offset + 3, 1))
    log_v("signature algo", sig_alg in ahab_sig_algs and ahab_sig_algs[sig_alg]
                            or error("invalid signature algorithm", sig_alg))

    hsh_alg = bytes2int(get_bytes(infile, offset + 4, 1))
    log_v("hash algorithm", hsh_alg in ahab_hsh_algs and ahab_hsh_algs[hsh_alg]
                            or error("invalid hash algorithm", hsh_alg))

    key_typ = bytes2int(get_bytes(infile, offset + 5, 1))
    log_v("key size/curve", key_typ in ahab_key_types
                            and ahab_key_types[key_typ]
                            or error("invalid key size/curve", key_typ))

    mod_x_len = bytes2int(get_bytes(infile, offset +  8, 2))
    exp_y_len = bytes2int(get_bytes(infile, offset + 10, 2))

    if (mod_x_len + exp_y_len + 12) != length:
        error("invalid lengths")

    if sig_alg == SRK_RSA:
        log_len("modulus len", mod_x_len)
        log_len("exponent len", exp_y_len)
    elif sig_alg == SRK_RSA_PSS:
        log_len("modulus len", mod_x_len)
        log_len("exponent len", exp_y_len)
    elif sig_alg == SRK_ECDSA:
        if mod_x_len != exp_y_len:
            error("invalid lengths")
        log_len("curve len", mod_x_len)
    else:
        pass

    return (length, sig_alg, hsh_alg, key_typ, mod_x_len, exp_y_len)

# Function to decode container and save relevant information

def decode_container(infile, offset, srk_hsh_alg):

    # Container header

    line_break()
    log("Container header:")
    tab()

    cont_tag = bytes2int(get_bytes(infile, offset + 3, 1))
    log_v("type", cont_tag in ahab_cont_tags and ahab_cont_tags[cont_tag]
	  or error("invalid container tag", cont_tag))

    cont_hdr_vers = bytes2int(get_bytes(infile, offset, 1))
    if cont_hdr_vers != 0: error("invalid container version", cont_hdr_vers)

    cont_hdr_len = bytes2int(get_bytes(infile, offset + 1, 2))
    log_len("length", cont_hdr_len)

    cont = get_bytes(infile, offset, cont_hdr_len)

    srk_set = bytes2int(get_bytes(infile, offset + 4, 1)) & 0x3
    log_v("srk set", srk_set in ahab_srk_sets and ahab_srk_sets[srk_set]
	  or error("invalid srk set", srk_set))

    srk_idx = (bytes2int(get_bytes(infile, offset + 4, 1)) & 0x30) >> 4
    log_v("srk source", srk_idx)

    srk_rvk = bytes2int(get_bytes(infile, offset + 6, 1))
    log_v("srk revocations", srk_rvk)

    if cont_tag == CONTAINER_HEADER_TAG:
        nb_imgs = bytes2int(get_bytes(infile, offset + 11, 1))
        log_v("number of images", nb_imgs)

    sig_blk_offset = bytes2int(get_bytes(infile, offset + 12, 2))

    if srk_set != HEADER_FLAGS_SRK_SET_NONE:

        # Parse signature block

        line_break()
        log("Signature block:")
        tab()

        sig_blk_offset += offset
        log_x("offset", sig_blk_offset)

        sig_blk_tag = bytes2int(get_bytes(infile, sig_blk_offset + 3, 1))
        if sig_blk_tag != SIGNATURE_BLOCK_TAG:
                error("invalid signature block tag", sig_blk_tag)

        sig_blk_len = bytes2int(get_bytes(infile, sig_blk_offset + 1, 2))
        log_len("length", sig_blk_len)

        sig_blk = get_bytes(infile, sig_blk_offset, sig_blk_len)

        sig_blk_vers = bytes2int(get_bytes(infile, sig_blk_offset, 1))
        if sig_blk_vers != 0:
                error("invalid signature block version", sig_blk_vers)

        cert_off = bytes2int(get_bytes(infile, sig_blk_offset + 4, 2))

        srktable_off = bytes2int(get_bytes(infile, sig_blk_offset + 6, 2))
        if srktable_off == 0:
                error("invalid srk table offset")

        sig_off = bytes2int(get_bytes(infile, sig_blk_offset + 8, 2))
        if sig_off == 0:
                error("invalid signature offset")

        blob_off = bytes2int(get_bytes(infile, sig_blk_offset + 10, 2))

        if 0 != blob_off:
            key_id = bytes2int(get_bytes(infile, sig_blk_offset + 12, 4))
            log_x("key identifier", key_id)

        # Parse SRK table

        log("SRK table:", new_line=True)
        tab()

        srk_table_offset = sig_blk_offset + srktable_off
        log_x("offset", srk_table_offset)

        if SRK_TABLE_TAG != bytes2int(get_bytes(infile, srk_table_offset, 1)):
            error("invalid SRK table tag")

        srk_table_len = bytes2int(get_bytes(infile, srk_table_offset + 1, 2))
        log_len("length", srk_table_len)

        srk_table = get_bytes(infile, srk_table_offset, srk_table_len)

        srk_table_vers = bytes2int(get_bytes(infile, srk_table_offset + 3, 1))

        if srk_table_vers != SRK_TABLE_VERSION:
            error("invalid srk table version", srk_table_vers)

        srk_table_offset += 4
        srk_table_len -= 4

        index = 0
        srk_info = []

        # Save SRK table in file

        try:
            srkTableFile = open("output/SRKTable.bin", "wb")
            srkTableFile.write(srk_table)
        except:
            parser.error("Failed to create SRK table binary dump")

        # Parse SRK record

        log("SRK Table records:")
        tab()
        (srk_len, srk_sig_alg, sig_hsh_alg, srk_type, mod_x_len,
         exp_y_len) = decode_public_key(infile, srk_table_offset)

        srk_info.append({
            "sig_alg" : srk_sig_alg,
            "hsh_alg" : ahab_hsh_algs[sig_hsh_alg],
            "key_typ" : ahab_key_types[srk_type],
            "mod_x"   : bytes2int(get_bytes(infile, srk_table_offset + 12,
                                            mod_x_len), "big"),
            "exp_y"   : bytes2int(get_bytes(infile, srk_table_offset + 12
                                             + mod_x_len, exp_y_len), "big")
        })

	# Calculate SRK records size and offset

        while srk_table_len != 0:

            log ("SRK {} record:".format(index + 1))
            tab()

            if srk_idx == index:
                        log ("** SRK record being used **")

            log_x("offset", srk_table_offset)

            if SRK_TAG != bytes2int(get_bytes(infile, srk_table_offset, 1)):
                        error("invalid record tag")

            length = bytes2int(get_bytes(infile, srk_table_offset + 1, 2))
            log_len("length", length)

            untab()

            if srk_len <= srk_table_len:
                srk_table_offset += srk_len
                srk_table_len -= srk_len
                index += 1
            else:
                error("invalid lengths")

        untab()
        log("SRK Hash fuses:")

        # Calculate SRK Hash and save in file

        try:
            srkHashFile = open("output/SRKHash.bin", "wb")
            if srk_hsh_alg == STR_SHA256:
                srkHashFile.write(sha256(srk_table).digest())
            else:
                srkHashFile.write(sha512(srk_table).digest())
        except:
            parser.error("Failed to create SRK hash binary dump")

        tab()
        if srk_hsh_alg == STR_SHA256:
            digest = sha256(srk_table).digest()
        else:
            digest = sha512(srk_table).digest()
        for i in range(0, len(digest), 4):
            log_x("fuse word {:2d}".format(int(i/4)),
                  bytes2int(digest[i:i+4]), int(32/4))
        untab()
        untab()

    # Check for SGK certificates

    if srk_set != HEADER_FLAGS_SRK_SET_NONE and cert_off != 0:

        log("Certificate:", new_line=True)
        tab()

        cert_offset = sig_blk_offset + cert_off
        log_x("offset", cert_offset)

        if CERTIFICATE_TAG != bytes2int(get_bytes(infile, cert_offset + 3, 1)):
            error("invalid Certificate tag")

        cert_len = bytes2int(get_bytes(infile, cert_offset + 1, 2))
        log_len("length", cert_len)

        cert = get_bytes(infile, cert_offset, cert_len)

        # Save SGK certificate in file

        try:
            sgkCertFile = open("output/SGK_cert.bin", "wb")
            sgkCertFile.write(cert)
        except:
            parser.error("Failed to create SGK certificate binary dump")

        cert_vers = bytes2int(get_bytes(infile, cert_offset, 1))

        if cert_vers != CERTIFICATE_VERSION:
            error("invalid Certificate version", cert_vers)

        cert_sig_off = bytes2int(get_bytes(infile, cert_offset + 4, 2))
        log_x("sig offset", cert_sig_off)

        cert_perm_inv = bytes2int(get_bytes(infile, cert_offset + 6, 1))
        cert_perm     = bytes2int(get_bytes(infile, cert_offset + 7, 1))

        if (cert_perm ^ cert_perm_inv) != 0xFF:
            error("incorrect permission encoding", cert_perm ^ cert_perm_inv)

        if "{:b}".format(cert_perm).count("1") != 1:
            error("multiple permissions", cert_perm)

        log_x("permission", cert_perm)

        log("public key")
        tab()

        (record_len, record_sig_alg, record_hsh_alg, recort_type, mod_x_len,
         exp_y_len) = decode_public_key(infile, cert_offset + 8)

        log_x("offset", cert_offset)

        if SRK_TAG != bytes2int(get_bytes(infile, cert_offset + 8, 1)):
            error("invalid record tag")
        length = bytes2int(get_bytes(infile, cert_offset + 8 + 1, 2))
        log_len("length", length)

        untab()

        log("Signature:")
        tab()

        log_x("offset",  cert_offset + cert_sig_off)

        if SIGNATURE_TAG != bytes2int(get_bytes(infile, cert_offset
                                      + cert_sig_off + 3, 1)):
            error("invalid signature tag")

        sig_len = bytes2int(get_bytes(infile, cert_offset + cert_sig_off + 1
                            , 2))
        log_len("length", sig_len)

        # Save SGK signature in file

        sgk_sig = get_bytes(infile, cert_offset + cert_sig_off,
                            sig_len)
        try:
            srkCertFile = open("output/SGK_sign.bin", "wb")
            srkCertFile.write(sgk_sig)
        except:
            parser.error("Failed to create SGK signature binary dump")

        untab()
        untab()

        cert_info = {
            "sig_alg" : record_sig_alg,
            "hsh_alg" : ahab_hsh_algs[record_hsh_alg],
            "key_typ" : ahab_key_types[recort_type],
            "mod_x"   : bytes2int(get_bytes(infile, cert_offset + 8 + 12,
                                            mod_x_len), "big"),
            "exp_y"   : bytes2int(get_bytes(infile,
                                            cert_offset + 8 + 12 + mod_x_len,
                                            exp_y_len), "big")
        }
    else:
        cert_info = None


    # Parse Header signature

    if srk_set != HEADER_FLAGS_SRK_SET_NONE:
        log("Signature:", new_line=True)
        tab()

        if cert_info != None:
            key = cert_info
        else:
            key = srk_info[srk_idx]

        log_x("offset",  sig_blk_offset + sig_off)

        if SIGNATURE_TAG != bytes2int(get_bytes(infile, sig_blk_offset
                                      + sig_off + 3, 1)):
            error("invalid signature tag")

        sig_len = bytes2int(get_bytes(infile, sig_blk_offset + sig_off + 1
                            , 2))

        log_len("length", sig_len)

        # Save Header/IMG signature in file

        img_sig = get_bytes(infile, sig_blk_offset + sig_off,
                            sig_len)
        try:
            imgSignFile = open("output/IMG_sign.bin", "wb")
            imgSignFile.write(img_sig)
        except:
            parser.error("Failed to create IMG certificate binary dump")

# main

if __name__ == "__main__":
    usage = \
"\n$ %prog <filepath> <offset>\n\
    filepath: Path for image container binary to be analyzed\n\
    offset:   Container header offset in binary\n\
    hash alg: Hash algorithm to generate SRK HASH\n\
              sha512 - For 8/8x devices\n\
              sha256 - For 8ULP\
"

    parser = OptionParser(usage=usage)
    (options, args) = parser.parse_args()

    if len(args) != 2 and len(args) != 3:
        parser.error("incorrect number of arguments")

    try:
        filepath = args[0]
        infile = open(filepath, "rb")
    except:
        parser.error("cannot open file {:}".format(filepath))

    try:
        offset = int(args[1], 0)
    except:
        parser.error("offset not a number")

    if len(args) == 3 and \
        (args[2].lower() == STR_SHA256 or \
        args[2].lower() == STR_SHA512):
            srk_hsh_alg = args[2].lower()
    else:
        srk_hsh_alg = STR_SHA512

    # Delete existing output directory if any

    if os.path.isdir("output"):
        try:
            shutil.rmtree("output")
        except:
            parser.error("Failed to delete output directory")

    # Create directory for output binaries

    try:
        os.mkdir("output")
    except:
        parser.error("Failed to create output directory")

    log_v("File", filepath)
    log_x("Offset", offset)

    decode_container(infile, offset, srk_hsh_alg)
