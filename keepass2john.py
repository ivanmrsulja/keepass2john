#!/usr/bin/env python3

import sys
import os
import struct
from binascii import hexlify


def stringify_hex(hex_bytes: bytes):
    return hexlify(hex_bytes).decode("utf-8")


def process_1x_database(data, database_name, max_inline_size=1024):
    index = 8
    algorithm = -1

    enc_flag = struct.unpack("<L", data[index:index+4])[0]
    index += 4
    if (enc_flag & 2 == 2):
        # AES
        algorithm = 0
    elif (enc_flag & 8):
        # Twofish
        algorithm = 1
    else:
        print("Unsupported file encryption!")
        return

    key_file_size = struct.unpack("<L", data[index:index+4])[0]
    index += 4
    keyfile = hexlify(data[index:index+key_file_size])
    index += key_file_size

    version = hexlify(data[index:index+4])
    index += 4

    final_random_seed = stringify_hex(data[index:index+16])
    index += 16

    iv_params = stringify_hex(data[index:index+16])
    index += 16

    num_groups = struct.unpack("<L", data[index:index+4])[0]
    index += 4
    num_entries = struct.unpack("<L", data[index:index+4])[0]
    index += 4

    contents_hash = stringify_hex(data[index:index+32])
    index += 32

    transform_random_seed = stringify_hex(data[index:index+32])
    index += 32

    key_transform_rounds = struct.unpack("<L", data[index:index+4])[0]

    filesize = len(data)
    datasize = filesize - 124

    if ((filesize + datasize) < max_inline_size):
        data_buffer = hexlify(data[124:])
        end = "*1*%ld*%s" % (datasize, stringify_hex(data_buffer))
    else:
        end = "0*%s" % database_name

    print("1x database properties:")
    print("Keyfile: %s\nVersion: %s\nNumber of groups: %s\nNumber of entries: %s\n" % (keyfile, version, num_groups, num_entries))

    return "%s<SHOULD_BE_REMOVED_INCLUDING_COLON>:$keepass$*1*%s*%s*%s*%s*%s*%s*%s" % (
        database_name, key_transform_rounds, algorithm,
        final_random_seed, transform_random_seed, iv_params, contents_hash, end
    )


def process_2x_database(data, database_name):
    index = 12
    end_reached = False
    master_seed = b''
    transform_seed = b''
    transform_rounds = 0
    iv_parameters = b''
    expected_start_bytes = b''

    while not end_reached:
        btFieldID = struct.unpack("B", data[index:index+1])[0]
        index += 1
        uSize = struct.unpack("H", data[index:index+2])[0]
        index += 2

        if btFieldID == 0:
            end_reached = True

        if btFieldID == 4:
            master_seed = stringify_hex(data[index:index+uSize])

        if btFieldID == 5:
            transform_seed = stringify_hex(data[index:index+uSize])

        if btFieldID == 6:
            transform_rounds = struct.unpack("Q", data[index:index+8])[0]

        if btFieldID == 7:
            iv_parameters = stringify_hex(data[index:index+uSize])

        if btFieldID == 9:
            expected_start_bytes = stringify_hex(data[index:index+uSize])

        index += uSize

    dataStartOffset = index
    firstEncryptedBytes = stringify_hex(data[index:index+32])

    return "%s<SHOULD_BE_REMOVED_INCLUDING_COLON>:$keepass$*2*%s*%s*%s*%s*%s*%s*%s" % (
        database_name, transform_rounds, dataStartOffset, master_seed,
        transform_seed, iv_parameters, expected_start_bytes,
        firstEncryptedBytes
    )


def parse_kdf_for_john(kdf_data, debug=False):
    """
    Extract Argon2/AES-KDF parameters for John/Hashcat.
    Returns dict with type and parameters.
    """
    info = {}
    if not kdf_data:
        return info

    try:
        index = 0
        version = struct.unpack("<H", kdf_data[index:index+2])[0]
        index += 2

        while index < len(kdf_data):
            value_type = struct.unpack("B", kdf_data[index:index+1])[0]
            index += 1
            if value_type == 0:
                break

            key_len = struct.unpack("<I", kdf_data[index:index+4])[0]
            index += 4
            key = kdf_data[index:index+key_len].decode("utf-8", errors="ignore")
            index += key_len

            val_len = struct.unpack("<I", kdf_data[index:index+4])[0]
            index += 4
            val = kdf_data[index:index+val_len]
            index += val_len

            if key == "$UUID":
                if val == bytes.fromhex("ef636ddf8c29444b91f7a9a403e30a0c"):
                    info["kdf"] = "argon2d"
                elif val == bytes.fromhex("9e298b1956db4773b23dfc3ec6f0a1e6"):
                    info["kdf"] = "argon2id"
                elif val == bytes.fromhex("c9d9f39a628a4460bf740d08c18a4fea"):
                    info["kdf"] = "aes-kdf"
            elif key == "I":
                info["iterations"] = struct.unpack("<Q", val)[0]
            elif key == "M":
                info["memory"] = struct.unpack("<Q", val)[0]
            elif key == "P":
                info["parallelism"] = struct.unpack("<I", val)[0]
            elif key == "S":
                info["salt"] = hexlify(val).decode()

        if debug:
            print("DEBUG: Parsed KDF info:", info)

    except Exception as e:
        if debug:
            print("ERROR parsing KDF parameters:", str(e))

    return info


def process_kdbx4_database(filename, debug=False):
    with open(filename, "rb") as f:
        sig1, sig2 = struct.unpack("<II", f.read(8))
        if sig1 != 0x9AA2D903 or sig2 != 0xB54BFB67:
            raise ValueError("Not a valid KDBX4 file")

        version = struct.unpack("<I", f.read(4))[0]
        if debug:
            print(f"DEBUG: KDBX4 version {version}")

        header_fields = {}
        while True:
            field_id = struct.unpack("B", f.read(1))[0]
            if field_id == 0:
                break
            length = struct.unpack("<I", f.read(4))[0]
            value = f.read(length)
            header_fields[field_id] = value

            if debug:
                print(f"DEBUG: Header field {field_id}, length {length}")

        master_seed = header_fields.get(4, b"")
        transform_seed = header_fields.get(7, b"")
        enc_iv = header_fields.get(6, b"")
        start_bytes = header_fields.get(8, b"")
        kdf_params = header_fields.get(11, b"")
        kdf_info = parse_kdf_for_john(kdf_params, debug)

        if debug:
            print("DEBUG: Master seed:", hexlify(master_seed))
            print("DEBUG: KDF info:", kdf_info)

        result = (
            f"$keepass$*4*{os.path.basename(filename)}*"
            f"{kdf_info.get('kdf','argon2id')}*"
            f"{kdf_info.get('parallelism',0)}*"
            f"{kdf_info.get('memory',0)}*"
            f"{kdf_info.get('iterations',0)}*"
            f"{kdf_info.get('salt','')}*"
            f"{hexlify(master_seed).decode()}*"
            f"{hexlify(transform_seed).decode()}*"
            f"{hexlify(enc_iv).decode()}*"
            f"{hexlify(start_bytes).decode()}"
        )
        return result


processing_mapping = {
    b'03d9a29a67fb4bb5': process_2x_database, # "2.X"
    b'03d9a29a66fb4bb5': process_2x_database, # "2.X pre release"
    b'03d9a29a65fb4bb5': process_1x_database  # "1.X"
}


def process_database(filename):
    with open(filename, 'rb') as f:
        data = f.read()

    base = os.path.basename(filename)
    database_name = os.path.splitext(base)[0]

    file_signature = hexlify(data[0:8])

    version = hexlify(data[8:12])

    try:
        if version == b'00000400':
            print(process_kdbx4_database(filename=filename, debug=False))
            return
        print(processing_mapping[file_signature](data, database_name))
    except KeyError:
        print("ERROR: KeePass signature unrecognized")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <kdb[x] file[s]>\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_database(sys.argv[i])
