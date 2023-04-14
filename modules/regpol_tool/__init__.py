import re
import sys
import struct

import click


class Entry:
    def __init__(self, key, value, regtype, size, data) -> None:
        self.key = key
        self.value = value
        self.regtype = regtype
        self.size = size
        self.data = data


magic_string = b'\x50\x52\x65\x67\x01\x00\x00\x00'

# from: https://github.com/wine-mirror/wine/blob/master/include/winnt.h
REG_NONE = 0  # /* no type */
REG_SZ = 1  # /* string type (ASCII) */
REG_EXPAND_SZ = 2  # /* string, includes %ENVVAR% (expanded by caller) (ASCII) */
REG_BINARY = 3  # /* binary format, callerspecific */
# /* YES, REG_DWORD == REG_DWORD_LITTLE_ENDIAN */
REG_DWORD = 4  # /* DWORD in little endian format */
REG_DWORD_LITTLE_ENDIAN = 4  # /* DWORD in little endian format */
REG_DWORD_BIG_ENDIAN = 5  # /* DWORD in big endian format  */
REG_LINK = 6  # /* symbolic link (UNICODE) */
REG_MULTI_SZ = 7  # /* multiple strings, delimited by \0, terminated by \0\0 (ASCII) */
REG_RESOURCE_LIST = 8  # /* resource list? huh? */
REG_FULL_RESOURCE_DESCRIPTOR = 9  # /* full resource descriptor? huh? */
REG_RESOURCE_REQUIREMENTS_LIST = 1  #
REG_QWORD = 1  # /* QWORD in little endian format */
REG_QWORD_LITTLE_ENDIAN = 1  # /* QWORD in little endian format */

reg_types = {
    REG_NONE: "REG_NONE",
    REG_SZ: "REG_SZ",
    REG_EXPAND_SZ: "REG_EXPAND_SZ",
    REG_BINARY: "REG_BINARY",
    # REG_DWORD: "REG_DWORD",
    REG_DWORD_LITTLE_ENDIAN: "REG_DWORD_LITTLE_ENDIAN",
    REG_DWORD_BIG_ENDIAN: "REG_DWORD_BIG_ENDIAN",
    REG_LINK: "REG_LINK",
    REG_MULTI_SZ: "REG_MULTI_SZ",
    REG_RESOURCE_LIST: "REG_RESOURCE_LIST",
    REG_FULL_RESOURCE_DESCRIPTOR: "REG_FULL_RESOURCE_DESCRIPTOR",
    # REG_RESOURCE_REQUIREMENTS_LIST: "REG_RESOURCE_REQUIREMENTS_LIST",
    # REG_QWORD: "REG_QWORD",
    # REG_QWORD_LITTLE_ENDIAN: "REG_QWORD_LITTLE_ENDIAN",
}


def parser_reg_pol(filename):
    """Print contents of Registry.pol file"""

    with open(filename, "rb") as f:
        file_data = f.read()
    if not file_data.startswith(magic_string):
        print("Missing Registry.pol magic string: {0}".format(magic_string), file=sys.stderr)

    body = file_data[len(magic_string):]

    entries = []

    while len(body) > 0:
        if body[0:2] != b'[\x00':
            print("Error: Entry does not start with \"[\"", file=sys.stderr)
            break
        body = body[2:]

        # key
        key, _, body = body.partition(b';\x00')
        # print(len(key))
        # print(key)
        key = decode_key(key)

        # value
        value, _, body = body.partition(b';\x00')
        # print(len(key))
        # print(key)
        value = decode_value(value)

        # type
        regtype = body[0:4]
        body = body[4 + 2:]  # len of field plus semicolon delimieter
        regtype = struct.unpack("<I", regtype)[0]

        # size
        size = body[0:4]
        body = body[4 + 2:]
        size = struct.unpack("<I", size)[0]

        # data
        data = body[0:size]
        body = body[size:]

        entry = Entry(key=key, value=value, regtype=regtype, size=size, data=data)
        entries.append(entry)

        if body[0:2] != b']\x00':
            print("Error: Entry does not end with \"]\"", file=sys.stderr)
            break
        body = body[2:]

    return {entry.key: entry.data for entry in entries}


def decode_key(regkey):
    # if regkey[-1:] != b'\x00':
    #     print("Warning: Key is not null-terminated: {0}".format(regkey), file=sys.stderr)
    # regkey = regkey[:-1]
    return regkey.decode('utf-16-le')


def decode_value(value):
    # if value[-1:] != b'\x00':
    #     print("Warning: Value is not null-terminated: {0}".format(value), file=sys.stderr)
    # value = value[:-1]
    return value.decode('utf-16-le')


def pprint_entries(entries):
    for entry in entries:
        print(entry.key)
        print("    value: {0}".format(entry.value))
        print("    type:  {0} {1}".format(entry.regtype, reg_types[entry.regtype]))
        print("    size:  {0}".format(entry.size))
        print("    data:  {0}".format(entry.data))
        print()


if __name__ == '__main__':
    print(parser_reg_pol("openRegistry.pol"))
