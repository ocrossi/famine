# Before and After: Visual Comparison

## Source Code Changes

### Before (Absolute Addressing)
```assembly
; Line 122
mov rsi, firstDir           ; source = /tmp/test

; Line 134  
mov rsi, secondDir          ; source = /tmp/test2
```

### After (RIP-Relative Addressing)
```assembly
; Line 122
lea rsi, [rel firstDir]     ; source = /tmp/test

; Line 134
lea rsi, [rel secondDir]    ; source = /tmp/test2
```

## Generated Assembly

### Before (Broken)

```assembly
0x401497:  48 be 1a 10 40 00 00 00 00 00    movabs $0x40101a,%rsi
           │  │  └────────┬────────────┘
           │  │           └─ Absolute address: 0x40101a
           │  └─ Opcode for movabs to rsi
           └─ REX.W prefix (64-bit)
           
           Size: 10 bytes
           Position-independent: NO ❌
```

### After (Fixed)

```assembly
0x401497:  48 8d 35 7c fb ff ff    lea -0x484(%rip),%rsi  # 40101a <firstDir>
           │  │  │  └────┬────┘
           │  │  │       └─ Offset: -0x484 (signed 32-bit)
           │  │  └─ ModR/M: register=rsi, mode=RIP-relative
           │  └─ Opcode for LEA
           └─ REX.W prefix (64-bit)
           
           Size: 7 bytes  
           Position-independent: YES ✅
```

## Address Calculation Examples

### Scenario: Original Famine Binary

**Before (Absolute):**
```
Instruction address:  0x401497
Encoded instruction:  movabs $0x40101a,%rsi
Target address:       0x40101a (hard-coded)
Result:               Points to firstDir ✓
```

**After (RIP-Relative):**
```
Instruction address:  0x401497
RIP after instruction: 0x40149e
Offset:               -0x484
Target address:       0x40149e + (-0x484) = 0x40101a
Result:               Points to firstDir ✓
```

### Scenario: Infected Binary (Virus at 0x5000000)

**Before (Absolute) - BROKEN:**
```
Instruction address:  0x5000497
Encoded instruction:  movabs $0x40101a,%rsi  ← Still the same!
Target address:       0x40101a (hard-coded)
Actual firstDir at:   0x500001a
Result:               Points to WRONG ADDRESS ❌
                      → SEGMENTATION FAULT
```

**After (RIP-Relative) - WORKS:**
```
Instruction address:  0x5000497
RIP after instruction: 0x500049e
Offset:               -0x484  ← Still the same!
Target address:       0x500049e + (-0x484) = 0x500001a
Actual firstDir at:   0x500001a
Result:               Points to CORRECT ADDRESS ✅
                      → No segfault!
```

## Key Insight

The **offset** (-0x484) stays the same because the relative distance between the instruction and the data doesn't change when the code is copied. Only the base address changes.

With **absolute addressing**, the address is hard-coded and breaks when relocated.

With **RIP-relative addressing**, the offset adjusts automatically based on the current instruction pointer, making the code position-independent.

## Benefits of the Fix

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Instruction size | 10 bytes | 7 bytes | -30% |
| Position-independent | No | Yes | ✓ |
| Works in infected binaries | No | Yes | ✓ |
| Segfaults | Yes | No | ✓ |

The fix makes the code smaller, faster, and correct!
