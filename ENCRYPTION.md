# Famine Binary Encryption

## Overview

The Famine binary is automatically encrypted when compiled. The encryption protects the virus payload code while still allowing the binary to execute normally through self-decryption at runtime.

## How It Works

### Build Process

1. **Compilation**: The source code is assembled with NASM and linked to create the initial binary
2. **Post-Build Encryption**: The `encrypt_binary.py` script automatically runs after linking to:
   - Encrypt the virus payload (from `encrypt_start` to `virus_end`) using XOR encryption
   - Generate a random 16-byte encryption key
   - Store the key in the `.data` section (`encryption_key_storage`)
   - Set the `encryption_flag` to 1 in the binary

### Runtime Decryption

When the encrypted Famine binary is executed:

1. **Entry Point**: Execution starts at `_start`
2. **Check Flag**: The code checks if `encryption_flag` is set to 1
3. **Make Writable**: Uses `mprotect` syscall to make the code segment writable (RWX)
4. **Decrypt**: The `decrypt_file` function XORs the encrypted region with the stored key
5. **Execute**: The decrypted code continues normal execution

## Technical Details

### Encryption Algorithm

- **Algorithm**: XOR cipher
- **Key Size**: 16 bytes (128 bits)
- **Key Generation**: Random bytes from `/dev/urandom`
- **Encrypted Region**: From `encrypt_start` symbol to `virus_end` symbol (~1.5 KB)

### Memory Protection

The code uses `mprotect` to temporarily make the `.text` segment writable:
```assembly
mprotect(page_aligned_addr, page_aligned_size, PROT_READ | PROT_WRITE | PROT_EXEC)
```

**Security Note**: This creates an RWX page which is typically a security risk. However, for a self-modifying virus, this is expected and necessary behavior.

### Key Storage

The encryption key is stored in the `.data` section at the `encryption_key_storage` symbol:
- **Location**: `.data` section (not `.bss`) so it exists in the file
- **Size**: 16 bytes
- **Usage**: Only used by the original Famine binary; infected binaries store keys differently

## Files Modified

- **`Makefile`**: Added post-build step to run `encrypt_binary.py`
- **`encrypt_binary.py`**: New Python script for encrypting the binary
- **`sources/main.s`**: 
  - Added `encryption_flag` and `encryption_key_storage`
  - Updated `_start` to call `mprotect` and `decrypt_file`
  - Modified `decrypt_file` to use different key locations for original vs infected binaries
- **`includes/include.s`**: Added `SYS_MPROTECT` and `PROT_EXEC` definitions

## Building

Simply run `make`:

```bash
make clean
make
```

The encryption happens automatically. The resulting `Famine` binary will be encrypted.

## Verification

To verify encryption is working:

```bash
# Check encryption flag (should be 01)
xxd -s 0x13ce -l 1 Famine

# Run the binary (it should work normally)
./Famine

# All tests should pass
make test
```

## Compatibility

- **Platform**: x86-64 Linux
- **Page Size**: Assumes 4KB pages (standard for x86-64 Linux)
- **Dependencies**: Python 3, NASM, binutils (readelf, nm)

## Limitations

1. The encryption is XOR-based, which is reversible and not cryptographically secure
2. The key is stored in the binary in plaintext
3. The decryption happens in-memory, so a memory dump could reveal the decrypted code
4. Creates an RWX memory page during decryption

These limitations are acceptable for an educational virus project but would not be suitable for real malware defense.
