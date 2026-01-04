# Segfault Debug Summary

## Problem
Running `make obfuscate` followed by `./Famine` results in an immediate segmentation fault.

## Root Cause
The `encrypt` program in `sources/encrypt.s` uses **incorrect hardcoded file offsets** that are 18 bytes (0x12) too high. This causes it to write encryption metadata into executable code instead of the designated data fields.

## Technical Details

### Incorrect Assumptions in encrypt.s
- Assumes `virus_start` is at file offset **0x1393**
- Actually located at file offset **0x1381**
- Difference: **0x12 bytes (18 bytes)**

### Impact
The encrypt program writes:
1. Encryption key at offset 0x139b (should be 0x1389) ❌
2. Encrypted flag at offset 0x13ab (should be 0x1399) ❌  
3. Encrypted offset at 0x13ac (should be 0x139a) ❌
4. Encrypted size at 0x13b4 (should be 0x13a2) ❌

This **overwrites the `_start` function** at entry point 0x4013aa with garbage data.

### Crash Sequence
1. Binary loads and jumps to entry point 0x4013aa
2. Tries to execute corrupted instruction (0x6e = `outsb`)
3. Invalid memory access → **SIGSEGFAULT**

## Required Fixes

File: `sources/encrypt.s`

| Line | Current Value | Correct Value | Description |
|------|--------------|---------------|-------------|
| 156  | 0x139b       | 0x1389        | encryption_key file offset |
| 175  | 0x1dd        | 0x1d2         | encrypted_offset value |
| 179  | 0x637        | 0x68a         | encrypted_size value |
| 182  | 0x1570       | 0x1553        | encryption start offset |
| 184  | 0x637        | 0x68a         | size to encrypt |

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

## How to Reproduce
```bash
make clean && make all
make obfuscate
./Famine  # Segmentation fault (core dumped)
```

## Investigation Command
```bash
gdb ./Famine
# Note: ptrace anti-debug will cause clean exit, but crash is visible without debugger
```

For complete analysis, see **debug_gdb.txt** (400 lines, 15KB).
