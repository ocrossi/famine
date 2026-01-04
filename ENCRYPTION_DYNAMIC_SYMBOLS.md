# Dynamic Symbol Resolution in Encryption

## Overview

The encryption program (`sources/encrypt.s`) now uses **dynamic symbol resolution** instead of hardcoded file offsets. This makes the encryption process resilient to code changes and linker variations.

## How It Works

### Previous Approach (Hardcoded)
The old implementation used hardcoded file offsets:
```assembly
; WRONG - Hardcoded offset
add rdi, 0x139b    ; Assumed encryption_key at fixed offset
```

This approach was fragile because:
- Symbol locations change when code is modified
- Linker may place symbols at different addresses
- Led to corruption and segfaults when offsets were wrong

### New Approach (Dynamic)
The new implementation:
1. **Parses the ELF file** to read the section headers
2. **Locates the symbol table** (.symtab) and string table (.strtab)
3. **Searches for required symbols** by name
4. **Calculates file offsets** from virtual addresses dynamically

```assembly
; CORRECT - Dynamic lookup
lea rdi, [rel sym_virus_start]
call find_symbol              ; Returns file offset
mov [rel addr_virus_start], rax
```

## Symbols Resolved Dynamically

The following symbols are now resolved at runtime:
- `virus_start` - Start of virus payload
- `encryption_key` - Location to write encryption key
- `encrypted_flag` - Flag indicating encryption status
- `encrypted_offset` - Offset to encrypted region
- `encrypted_size` - Size of encrypted region
- `decrypt_code.end` - End of decryption code
- `virus_end` - End of virus payload

## Benefits

1. **Robust to Code Changes**: Adding/removing code doesn't break encryption
2. **No Manual Offset Maintenance**: Offsets calculated automatically
3. **Prevents Corruption**: Symbols always point to correct locations
4. **Future-Proof**: Works with any binary layout

## Implementation Details

### ELF Parsing Function
The `find_symbol` function:
- Reads ELF header to locate section header table
- Iterates through sections to find `.symtab` and `.strtab`
- Reads symbol table into memory
- Searches for symbol by name comparison
- Converts virtual address to file offset

### File Offset Calculation
Virtual address to file offset conversion:
```
file_offset = virtual_address - 0x401000 + 0x1000
```

This assumes:
- `.text` section starts at virtual address `0x401000`
- `.text` section starts at file offset `0x1000`

## Testing

A comprehensive test suite (`tests/test_encryption.sh`) validates:
1. Encryption succeeds without errors
2. Encrypted binary is valid ELF
3. Encrypted binary runs without segfault
4. Encryption key written to correct location
5. Encrypted flag is set properly
6. Full obfuscation with strip works
7. Dynamic symbol resolution functions correctly

Run tests with:
```bash
./tests/test_encryption.sh
```

## Verification

To verify the encryption works correctly:
```bash
# Build and encrypt
make fclean && make obfuscate

# Run encrypted binary (should not segfault)
./Famine

# Check symbol locations
nm Famine | grep -E "(virus_start|encryption_key|encrypted_flag)"

# Verify encryption metadata in binary
hexdump -C Famine | grep -A 3 "00001380"
```

## Example Output

Successful encryption:
```
$ ./encrypt Famine
Encrypted successfully

$ ./Famine
(runs without segfault)
```

Symbol verification:
```
$ nm Famine | grep virus_start
0000000000401381 t virus_start

$ nm Famine | grep encryption_key
0000000000401389 t encryption_key
```

## Future Improvements

Potential enhancements:
- Cache symbol table for multiple lookups
- Support position-independent executables (PIE)
- Handle different section layouts
- Add error messages for missing symbols
