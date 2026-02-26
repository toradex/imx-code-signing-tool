#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright 2019, 2021-2023 NXP
#

# from cryptography.hazmat.backends              import default_backend
# from cryptography.hazmat.primitives.asymmetric import ec, utils, rsa, padding
# from cryptography.hazmat.primitives            import hashes

# Definitions

LINE_BREAK = "-" * 80
TAB        = " " * 4

STR_SECP256R1 = "secp256r1"
STR_SECP384R1 = "secp384r1"
STR_SECP521R1 = "secp521r1"

# curves = {
#     STR_SECP256R1 : ec.SECP256R1(),
#     STR_SECP384R1 : ec.SECP384R1(),
#     STR_SECP521R1 : ec.SECP521R1()
# }

STR_SHA256 = "sha256"
STR_SHA384 = "sha384"
STR_SHA512 = "sha512"

# hash_algos = {
#     STR_SHA256 : hashes.SHA256(),
#     STR_SHA384 : hashes.SHA384(),
#     STR_SHA512 : hashes.SHA512(),
# }

# Globals

tab_lvl = 0

# Error handling

def error(msg, inbytes=None, persist=False):
    import sys
    print("\n{:}: {:}: {:}".format(sys.argv[0], "ERROR", msg))
    if inbytes != None:
        print("{:#x}".format(inbytes))
    exit(-1)

# Get data from file

def get_bytes(infile, offset, size):
    try:
        infile.seek(offset)
        data = infile.read(size)
        if len(data) != size: raise Error
        return data
    except:
        error("cannot read {:} ({:#x}) bytes from offset {:#x}".format(size,
                                                                size, offset))

# Convert bytes to int

def bytes2int(bytes, order="little"):
    return int.from_bytes(bytes, byteorder=order)

# Tabs and breaks handling

def line_break():
    global tab_lvl
    tab_lvl = 0
    print(LINE_BREAK)

def tab():
    global tab_lvl
    tab_lvl += 1

def untab():
    global tab_lvl
    if tab_lvl > 0: tab_lvl -= 1

# Logs handling

def log(msg, new_line=False):
    global tab_lvl
    if new_line: print()
    print("{:}{:}".format(TAB * tab_lvl, msg))

def log_v(msg, val):
    global tab_lvl
    print("{:}{:.<16} {:}".format(TAB * tab_lvl, msg, val))

def log_x(msg, val, pad = 0):
    global tab_lvl
    print("{:}{:.<16} 0x{:0{pad}x}".format(TAB * tab_lvl, msg, val, pad = pad))

def log__x(msg, val, pad = 0):
    global tab_lvl
    print("{:}{:.<16} {:0{pad}x}".format(TAB * tab_lvl, msg, val, pad = pad))

def log_len(msg, val):
    global tab_lvl
    print("{:}{:.<16} {:} ({:#x})".format(TAB * tab_lvl, msg, val, val))

# Main

if __name__ == "__main__":
    print("This script cannot be called directly")
