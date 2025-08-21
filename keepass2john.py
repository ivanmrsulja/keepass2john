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


def parse_kdf_parameters(kdf_data):
    """Parse KDF parameters from VariantDictionary format"""
    params = {}
    index = 0
    
    if not kdf_data:
        return params
    
    # Read version (2 bytes)
    version = struct.unpack("<H", kdf_data[index:index+2])[0]
    index += 2
    
    while index < len(kdf_data):
        value_type = kdf_data[index]
        index += 1
        if value_type == 0:  # End marker
            break
            
        # Key length and key name
        key_len = struct.unpack("<I", kdf_data[index:index+4])[0]
        index += 4
        key_name = kdf_data[index:index+key_len].decode('utf-8', errors='ignore')
        index += key_len
        
        # Value length and value
        val_len = struct.unpack("<I", kdf_data[index:index+4])[0]
        index += 4
        
        if val_len > 0:
            value = kdf_data[index:index+val_len]
            index += val_len
            
            # Parse value based on type
            if value_type == 0x04:  # UInt32
                if val_len == 4:
                    params[key_name] = struct.unpack("<I", value)[0]
            elif value_type == 0x05:  # UInt64
                if val_len == 8:
                    params[key_name] = struct.unpack("<Q", value)[0]
            elif value_type == 0x08:  # Bool
                if val_len == 1:
                    params[key_name] = bool(value[0])
            elif value_type == 0x18:  # String
                params[key_name] = value.decode('utf-8', errors='ignore')
            elif value_type == 0x42:  # Byte array
                params[key_name] = value
                if key_name == "$UUID" and len(value) >= 16:
                    # Store UUID bytes for later conversion
                    params["$UUID_bytes"] = value
    
    return params


def process_kdbx4_database(filename):
    """Process KDBX4 database format with correct hash output"""
    with open(filename, "rb") as f:
        # Read signature and version
        sig1, sig2 = struct.unpack("<II", f.read(8))
        if sig1 != 0x9AA2D903 or sig2 != 0xB54BFB67:
            raise ValueError("Not a valid KDBX4 file")
        
        version = struct.unpack("<I", f.read(4))[0]
        
        # Store the complete header starting from signature
        f.seek(0)
        complete_header_data = f.read(12)  # Signature + version
        
        # Read header fields
        header_fields = {}
        header_start_pos = f.tell()
        
        while True:
            field_id_byte = f.read(1)
            if not field_id_byte:
                break
            field_id = struct.unpack("B", field_id_byte)[0]
            if field_id == 0:
                break
                
            field_size = struct.unpack("<I", f.read(4))[0]
            field_data = f.read(field_size)
            header_fields[field_id] = field_data
            # Add this field to the complete header data
            complete_header_data += field_id_byte + struct.pack("<I", field_size) + field_data
        
        # Add end marker to complete header
        header_end_pos = f.tell()
        
        # Read header hash and HMAC
        header_hash = f.read(8)
        complete_header_data += b'\x00' + header_hash
        f.read(32)
        header_hmac = f.read(32)
        
        # Extract required fields
        master_seed = header_fields.get(4, b"")  # MasterSeed
        kdf_params_data = header_fields.get(11, b"")  # KdfParameters
        
        # Parse KDF parameters
        kdf_params = parse_kdf_parameters(kdf_params_data)
        
        # Get KDF UUID and parameters
        kdf_uuid_bytes = kdf_params.get("$UUID", b"")
        if kdf_uuid_bytes and len(kdf_uuid_bytes) >= 4:
            # Convert UUID from little-endian to big-endian format
            # Need to reverse the byte order for the first 4 bytes
            uuid_le = struct.unpack("<I", kdf_uuid_bytes[:4])[0]
            # Convert to big-endian by reversing bytes
            uuid_be = struct.unpack(">I", struct.pack("<I", uuid_le))[0]
            kdf_uuid_str = f"{uuid_be:08x}"
        else:
            kdf_uuid_str = "00000000"
        
        iterations = kdf_params.get("I", kdf_params.get("R", 0))  # Iterations/Rounds
        memory = kdf_params.get("M", 0)  # Memory in KB
        parallelism = kdf_params.get("P", 0)  # Parallelism
        salt = kdf_params.get("S", b"")  # Salt
        v = kdf_params.get("V", 0)  
        # Get transform seed (from KDF parameters in KDBX4)
        transform_seed = salt
        
        # Format the hash output according to the expected pattern
        database_name = os.path.basename(filename)
        
        return "%s:$keepass$*4*%u*%s*%u*%u*%u*%s*%s*%s*%s" % (
            database_name,
            iterations,
            kdf_uuid_str,
            memory,
            v,
            parallelism,
            stringify_hex(master_seed),
            stringify_hex(transform_seed),
            stringify_hex(complete_header_data),
            stringify_hex(header_hmac)
        )


def process_3x_database(data, database_name):
    """Process KDBX3 database format that uses KDBX4-style KDF parameters"""
    index = 12
    end_reached = False
    master_seed = b''
    transform_seed = b''
    transform_rounds = 0
    iv_parameters = b''
    expected_start_bytes = b''
    algorithm = 0  # Default to AES
    kdf_params_data = b''

    while not end_reached:
        btFieldID = struct.unpack("B", data[index:index+1])[0]
        index += 1
        uSize = struct.unpack("<I", data[index:index+4])[0]  # 4-byte size in KDBX3
        index += 4

        if btFieldID == 0:
            end_reached = True
            continue

        if btFieldID == 2:  # CipherID
            cipher_id = data[index:index+uSize]
            if cipher_id.startswith(b'\x31\xc1\xf2\xe6'):
                algorithm = 0  # AES
            elif cipher_id.startswith(b'\xad\x68\xf2\x9f'):
                algorithm = 1  # TwoFish
            elif cipher_id.startswith(b'\xd6\x03\x8a\x2b'):
                algorithm = 2  # ChaCha20

        if btFieldID == 4:
            master_seed = data[index:index+uSize]

        if btFieldID == 5:
            transform_seed = data[index:index+uSize]

        if btFieldID == 6:
            transform_rounds = struct.unpack("<I", data[index:index+4])[0]

        if btFieldID == 7:
            iv_parameters = data[index:index+uSize]

        if btFieldID == 9:
            expected_start_bytes = data[index:index+uSize]

        if btFieldID == 11:  # KdfParameters (KDBX4 style in KDBX3)
            kdf_params_data = data[index:index+uSize]

        index += uSize

    # Read header hash (32 bytes) and HMAC (32 bytes) for KDBX3
    header_hash = data[index:index+32]
    index += 32
    header_hmac = data[index:index+32]
    index += 32

    # Read the first encrypted bytes (should be 32 bytes)
    first_encrypted_bytes = data[index:index+32]

    # Parse KDF parameters if available (KDBX4 style)
    if kdf_params_data:
        kdf_params = parse_kdf_parameters(kdf_params_data)
        
        # Get KDF UUID - convert from little-endian to big-endian
        kdf_uuid_bytes = kdf_params.get("$UUID_bytes", b"")
        if kdf_uuid_bytes and len(kdf_uuid_bytes) >= 4:
            uuid_le = struct.unpack("<I", kdf_uuid_bytes[:4])[0]
            kdf_uuid_str = f"{uuid_le:08x}"
            kdf_uuid_str = ''.join([kdf_uuid_str[i:i+2] for i in range(6, -1, -2)])
        else:
            kdf_uuid_str = "00000000"
        
        iterations = kdf_params.get("I", kdf_params.get("R", transform_rounds))
        memory = kdf_params.get("M", 0)
        parallelism = kdf_params.get("P", 0)
        salt = kdf_params.get("S", transform_seed)
        
        # Reconstruct the complete header
        f.seek(0)
        complete_header_data = f.read(index)  # Read up to the HMAC
        
        return "%s:$keepass$*4*%u*%s*%u*%u*%u*%s*%s*%s*%s" % (
            database_name,
            iterations,
            kdf_uuid_str,
            memory,
            parallelism,
            len(complete_header_data),
            stringify_hex(master_seed),
            stringify_hex(salt),
            stringify_hex(complete_header_data),
            stringify_hex(header_hmac)
        )
    else:
        # Traditional KDBX3 format
        return "%s:$keepass$*3*%s*%s*%s*%s*%s*%s*%s*%s*%s" % (
            database_name, transform_rounds, algorithm, 
            stringify_hex(master_seed),
            stringify_hex(transform_seed), 
            stringify_hex(iv_parameters), 
            stringify_hex(expected_start_bytes),
            stringify_hex(header_hash), 
            stringify_hex(header_hmac), 
            stringify_hex(first_encrypted_bytes)
        )


processing_mapping = {
    b'03d9a29a67fb4bb5': process_2x_database,  # KDBX2
    b'03d9a29a66fb4bb5': process_2x_database,  # KDBX2 pre-release
    b'03d9a29a65fb4bb5': process_1x_database   # KDBX1
}


def process_database(filename):
    with open(filename, 'rb') as f:
        data = f.read()

    base = os.path.basename(filename)
    database_name = os.path.splitext(base)[0]

    file_signature = hexlify(data[0:8])
    version = struct.unpack("<I", data[8:12])[0]

    try:
        # Check for KDBX4 first (version 0x00040000 or higher)
        if version >= 0x00040000:
            result = process_kdbx4_database(filename)
            print(result)
            return
        
        # Check for KDBX3 (version 0x00030001)
        if version == 0x00030001:
            result = process_3x_database(data, database_name)
            print(result)
            return
            
        # Handle KDBX1 and KDBX2
        result = processing_mapping[file_signature](data, database_name)
        print(result)
    except KeyError:
        print("ERROR: KeePass signature unrecognized")
    except Exception as e:
        print(f"ERROR processing {filename}: {str(e)}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <kdb[x] file[s]>\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_database(sys.argv[i])
