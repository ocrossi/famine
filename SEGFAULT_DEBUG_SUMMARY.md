# Segfault Debug Summary

## ✅ FIXED

The segfault issue has been resolved by implementing dynamic symbol resolution.

## Original Problem
Running `make obfuscate` followed by `./Famine` resulted in an immediate segmentation fault.

## Root Cause (Original)
The `encrypt` program in `sources/encrypt.s` used **incorrect hardcoded file offsets** that were 18 bytes (0x12) too high. This caused it to write encryption metadata into executable code instead of the designated data fields.

## Solution Implemented

The issue has been **completely fixed** by replacing hardcoded offsets with **dynamic symbol resolution**:

### Changes Made (Commit 121d7cb)

1. **ELF Parsing**: Added `find_symbol()` function that:
   - Parses ELF section headers
   - Locates `.symtab` and `.strtab` sections
   - Searches for symbols by name
   - Converts virtual addresses to file offsets dynamically

2. **Dynamic Offset Calculation**: All symbols are now resolved at runtime:
   - `virus_start`
   - `encryption_key`
   - `encrypted_flag`
   - `encrypted_offset`
   - `encrypted_size`
   - `decrypt_code.end`
   - `virus_end`

3. **Test Suite**: Created `tests/test_encryption.sh` with 9 tests:
   - ✅ All encryption functionality tests pass
   - ✅ Encrypted binary runs without segfault
   - ✅ Full obfuscation with strip works correctly

### Verification
```bash
make fclean && make obfuscate
./Famine  # Runs successfully without segfault!
./tests/test_encryption.sh  # All 9 tests pass
```

## Technical Details (Historical Reference)

### Incorrect Assumptions in encrypt.s (OLD - FIXED)
- ~~Assumed `virus_start` at file offset **0x1393**~~
- Actually located at file offset **0x1381**
- Difference: **0x12 bytes (18 bytes)**

### Impact (RESOLVED)
The old encrypt program wrote:
1. ~~Encryption key at offset 0x139b (should be 0x1389)~~ ✅ Fixed
2. ~~Encrypted flag at offset 0x13ab (should be 0x1399)~~ ✅ Fixed
3. ~~Encrypted offset at 0x13ac (should be 0x139a)~~ ✅ Fixed
4. ~~Encrypted size at 0x13b4 (should be 0x13a2)~~ ✅ Fixed

This ~~overwrote~~ **used to overwrite** the `_start` function at entry point 0x4013aa with garbage data.

### Crash Sequence (NO LONGER OCCURS)
1. ~~Binary loads and jumps to entry point 0x4013aa~~
2. ~~Tries to execute corrupted instruction (0x6e = `outsb`)~~
3. ~~Invalid memory access → **SIGSEGFAULT**~~

**NOW**: Binary loads → Decrypts code correctly → Runs successfully ✅

## ~~Required Fixes~~ ✅ IMPLEMENTED

~~File: `sources/encrypt.s`~~

All fixes have been implemented using dynamic symbol resolution instead of manual offset corrections:

| ~~Line~~ | ~~Current Value~~ | ~~Correct Value~~ | Description | Status |
|------|--------------|---------------|-------------|--------|
| ~~156~~  | ~~0x139b~~       | ~~0x1389~~        | encryption_key file offset | ✅ **Dynamic** |
| ~~175~~  | ~~0x1dd~~        | ~~0x1d2~~         | encrypted_offset value | ✅ **Dynamic** |
| ~~179~~  | ~~0x637~~        | ~~0x68a~~         | encrypted_size value | ✅ **Dynamic** |
| ~~182~~  | ~~0x1570~~       | ~~0x1553~~        | encryption start offset | ✅ **Dynamic** |
| ~~184~~  | ~~0x637~~        | ~~0x68a~~         | size to encrypt | ✅ **Dynamic** |

**Better Solution**: Instead of fixing hardcoded values, all offsets are now calculated dynamically by parsing the ELF symbol table.

## Verification

See `debug_gdb.txt` for:
- Complete GDB session output
- Register dumps and disassembly
- Memory examination
- Hexdump verification
- Step-by-step crash analysis

## Symbol Addresses (from nm)
```
virus_start:      0x401381
_start:           0x4013aa  (entry point)
encryption_key:   0x401389
encrypted_flag:   0x401399
decrypt_code.end: 0x401553
virus_end:        0x401bdd
```

## How to Reproduce (Historical - Issue Fixed)
```bash
# OLD ISSUE (no longer occurs):
make clean && make all
make obfuscate
./Famine  # Used to segfault - NOW WORKS!
```

## Current Behavior (After Fix)
```bash
make fclean && make obfuscate
./Famine  # ✅ Runs successfully!

# Run test suite
./tests/test_encryption.sh  # ✅ All 9 tests pass
```

## Investigation Command (Historical Reference)
```bash
gdb ./Famine
# Note: ptrace anti-debug will cause clean exit, but crash is visible without debugger
# This was used to identify the root cause - see debug_gdb.txt
```

For complete analysis, see:
- **debug_gdb.txt** (400 lines, 15KB) - Original debug session
- **ENCRYPTION_DYNAMIC_SYMBOLS.md** - New implementation details
- **tests/test_encryption.sh** - Test suite validating the fix
