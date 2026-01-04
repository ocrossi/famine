# Complete Analysis: Segfault Issue with Absolute Addressing

## Executive Summary

The last commit introduced data sections (in `include.s` and `main.s`) that broke the position-independent virus code. The virus uses **absolute addressing** to reference data labels `firstDir` and `secondDir`, which causes **segmentation faults** when the virus code is injected into other binaries at different memory addresses.

**Root Cause:** Lines 122 and 134 in `sources/virus.s` used `mov rsi, label` instead of `lea rsi, [rel label]`

**Fix:** Changed to RIP-relative addressing which maintains correct references regardless of code location.

## The Problematic Assembly Instructions

### Before Fix (Absolute Addressing)

**Source code (virus.s:122, 134):**
```assembly
mov rsi, firstDir           ; Generates absolute address
mov rsi, secondDir          ; Generates absolute address
```

**Generated machine code:**
```assembly
0x401497:  48 be 1a 10 40 00 00 00 00 00    movabs $0x40101a,%rsi
0x4014a1:  ...
0x4014b5:  48 be 24 10 40 00 00 00 00 00    movabs $0x401024,%rsi
```

**Instruction breakdown:**
- Opcode: `48 be` (REX.W prefix + movabs)
- Operand: `1a 10 40 00 00 00 00 00` (little-endian 64-bit absolute address `0x40101a`)
- **Total length: 10 bytes**
- **Hard-coded address that breaks when code is relocated!**

### After Fix (RIP-Relative Addressing)

**Source code (virus.s:122, 134):**
```assembly
lea rsi, [rel firstDir]     ; Generates RIP-relative address
lea rsi, [rel secondDir]    ; Generates RIP-relative address
```

**Generated machine code:**
```assembly
0x401497:  48 8d 35 7c fb ff ff    lea -0x484(%rip),%rsi
0x40149e:  ...
0x4014af:  48 8d 35 6e fb ff ff    lea -0x492(%rip),%rsi
```

**Instruction breakdown:**
- Opcode: `48 8d 35` (REX.W + LEA with RIP-relative addressing)
- Operand: `7c fb ff ff` (little-endian 32-bit signed offset `-0x484`)
- **Total length: 7 bytes**
- **Offset-based addressing that works regardless of location!**

## Why Data in include.s and main.s Breaks Relative Addressing

### Data Section Layout

The `include.s` file defines data in the `.text` section:

```assembly
procdir: db "/proc/", 0                                          ; @ 0x401000
proc_status: db "/status", 0                                      ; @ 0x401007
firstDir: db "/tmp/test", 0                                       ; @ 0x40101a
secondDir: db "/tmp/test2", 0                                     ; @ 0x401024
signature: db "Famine version 1.0 (c)oded by <ocrossi>...", 0   ; @ 0x40102f
```

These data labels become part of the virus payload (`virus_start` to `virus_end`).

### The Virus Injection Process

1. **Original Famine binary:**
   - Virus code at: `0x401000 - 0x402108`
   - `firstDir` at: `0x40101a`
   - Instruction at `0x401497`: `movabs $0x40101a,%rsi`

2. **Infected binary (virus injected at new address):**
   - Virus code at: `0x5000000 - 0x5001108` (example)
   - `firstDir` at: `0x500001a` (relocated with the virus)
   - **Problematic:** Instruction at `0x5000497` still contains `movabs $0x40101a,%rsi`
   - **Result:** Tries to access old address `0x40101a` which is:
     - Either unmapped memory → SIGSEGV (segmentation fault)
     - Or belongs to the infected binary's original code/data → wrong data

## GDB Analysis of the Segfault

### Scenario: Infected Binary Crashes

When debugging an infected binary that crashes:

```gdb
(gdb) run
Starting program: /tmp/test/infected_binary

Program received signal SIGSEGV, Segmentation fault.
0x0000000005000497 in ?? ()

(gdb) x/i $rip
=> 0x5000497:  movabs $0x40101a,%rsi    ← Problematic instruction!

(gdb) info registers rip rsi
rip            0x5000497
rsi            0x0

(gdb) x/s 0x40101a
0x40101a: <error: Cannot access memory at address 0x40101a>
                                                    ↑ SEGFAULT HERE!

(gdb) x/s 0x500001a
0x500001a: "/tmp/test"    ← This is where firstDir actually is now!
```

### Calculating What Should Have Happened

```
Virus base (original):    0x401000
Virus base (infected):    0x5000000
Offset difference:        +0x4bff000

firstDir (original):      0x40101a
firstDir (infected):      0x40101a + 0x4bff000 = 0x500001a ✓

Instruction (original):   0x401497: movabs $0x40101a,%rsi
Instruction (infected):   0x5000497: movabs $0x40101a,%rsi  ← Still points to wrong address!
```

With RIP-relative addressing:
```
Instruction (original):   0x401497: lea -0x484(%rip),%rsi
RIP after instruction:    0x40149e
Target: 0x40149e + (-0x484) = 0x40101a ✓

Instruction (infected):   0x5000497: lea -0x484(%rip),%rsi  ← Offset unchanged!
RIP after instruction:    0x500049e
Target: 0x500049e + (-0x484) = 0x500001a ✓  ← Automatically correct!
```

## How to Identify the Problem in Disassembly

### Red Flags in objdump Output

**❌ BAD - Absolute addressing:**
```assembly
movabs $0x40101a,%rsi    # Hard-coded address
movabs $0x401024,%rsi    # Hard-coded address
mov    $0x403000,%rax    # Hard-coded address
```

**✅ GOOD - Position-independent addressing:**
```assembly
lea    -0x484(%rip),%rsi      # RIP-relative
lea    0x1be3(%rip),%rdi      # RIP-relative
mov    0x102bf1(%rip),%rax    # RIP-relative
```

### Quick Test: Is My Code Position-Independent?

Run objdump and check for absolute addresses in the virus code section:

```bash
objdump -d Famine | grep -E "(movabs|mov.*\$0x[4-7][0-9a-f]{5})"
```

If you see addresses in the range `0x400000-0x7fffff` being moved directly into registers, you likely have position-dependent code!

## The Fix Applied

**File:** `sources/virus.s`

**Lines changed:**
- Line 122: `mov rsi, firstDir` → `lea rsi, [rel firstDir]`
- Line 134: `mov rsi, secondDir` → `lea rsi, [rel secondDir]`

**Effect:**
- Code is now fully position-independent
- Virus can execute correctly in infected binaries at any address
- No more segmentation faults from invalid memory access

## Technical Notes

### Why LEA with [rel] Instead of MOV?

In x86-64 assembly:

- `mov rsi, label` - NASM interprets `label` as an **immediate value** (the address)
  - Generates: `movabs $address,%rsi`
  - 10 bytes, absolute addressing

- `lea rsi, [label]` - NASM may still use absolute addressing
  - Need to be explicit!

- `lea rsi, [rel label]` - Forces RIP-relative addressing
  - Generates: `lea offset(%rip),%rsi`
  - 7 bytes, position-independent

The `[rel]` directive is crucial - it explicitly tells NASM to use RIP-relative addressing mode, which is the default mode for 64-bit position-independent code.

### Instruction Encoding Details

**Absolute addressing (movabs):**
```
Bytes: 48 be 1a 10 40 00 00 00 00 00
       ^^    ^^^^^^^^^^^^^^^^^^^^^^^^
       |     └─ 64-bit absolute address
       └─ REX.W prefix for 64-bit operand
```

**RIP-relative addressing (lea):**
```
Bytes: 48 8d 35 7c fb ff ff
       ^^ ^^ ^^ ^^^^^^^^^^^^
       |  |  |  └─ 32-bit signed offset
       |  |  └─ ModR/M byte (rsi, RIP-relative)
       |  └─ Opcode (LEA)
       └─ REX.W prefix
```

The RIP-relative version is:
- **3 bytes shorter** (7 vs 10 bytes)
- **Position-independent** (works at any address)
- **More efficient** (no 64-bit immediate to load)

## Conclusion

The segfault was caused by using absolute addressing (`mov reg, label`) instead of RIP-relative addressing (`lea reg, [rel label]`) when accessing data labels that are part of the virus payload. When the virus code is copied to infected binaries at different addresses, absolute addresses become invalid, causing segmentation faults. The fix ensures all data references use RIP-relative addressing, making the code fully position-independent.
