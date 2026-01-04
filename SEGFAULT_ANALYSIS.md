# Segfault Analysis: Absolute vs. RIP-Relative Addressing

## Problem Summary

The last commit caused a segfault in the Famine virus when injected code runs in infected binaries. The root cause was using absolute addressing instead of RIP-relative addressing for data references in the virus payload code.

## Technical Analysis

### The Problematic Instructions

**Before the fix (lines 122 and 134 in `sources/virus.s`):**
```assembly
mov rsi, firstDir           ; source = /tmp/test
...
mov rsi, secondDir          ; source = /tmp/test2
```

These instructions were assembled as:
```assembly
0x401497:  movabs $0x40101a,%rsi    # Absolute address
```

### Why This Causes a Segfault

#### 1. How the Virus Works
The Famine virus works by:
1. Reading its own code from `virus_start` to `virus_end`
2. Copying this code into infected binaries as a new PT_LOAD segment
3. When the infected binary runs, it executes the virus code at a **different memory address**

#### 2. The Address Problem

**In the original Famine binary:**
- `firstDir` is located at address `0x40101a` (in the `.text` section)
- The instruction `movabs $0x40101a,%rsi` correctly points to this address

**In an infected binary:**
- The virus code is copied to a new location (e.g., at address `0x5000000`)
- The `firstDir` data is also copied and is now at `0x5000000 + offset`
- But the instruction still contains `movabs $0x40101a,%rsi` (absolute address)
- **This points to the WRONG location!**

When the infected binary tries to access address `0x40101a`, it either:
- Accesses invalid memory → **SEGFAULT**
- Accesses some random data from the infected binary
- Accesses unmapped memory → **SEGFAULT**

#### 3. The GDB Investigation

Using GDB on an infected binary would show:

```
(gdb) x/i $rip
=> 0x5000497:  movabs $0x40101a,%rsi

(gdb) x/s 0x40101a
0x40101a: <invalid memory or garbage>

(gdb) x/s 0x5000000 + (0x40101a - 0x401000)
0x500001a: "/tmp/test"  ← This is where firstDir actually is!
```

The problematic instruction would be at an offset from the new base address (e.g., `0x5000497` instead of `0x401497`), but it still references the old absolute address `0x40101a`.

### The Fix

**After the fix:**
```assembly
lea rsi, [rel firstDir]     ; source = /tmp/test
...
lea rsi, [rel secondDir]    ; source = /tmp/test2
```

These instructions assemble as:
```assembly
0x401497:  lea -0x484(%rip),%rsi    # RIP-relative addressing
```

#### Why RIP-Relative Addressing Works

**RIP-relative addressing** calculates the address relative to the current instruction pointer:
```
target_address = RIP + offset
```

**In the original Famine binary:**
```
RIP = 0x401497 (after the instruction)
offset = -0x484
target = 0x401497 + (-0x484) = 0x40101a ✓
```

**In an infected binary (virus at 0x5000000):**
```
RIP = 0x5000497 (after the instruction)  ← Different!
offset = -0x484                          ← Same!
target = 0x5000497 + (-0x484) = 0x500001a ✓
```

The **offset stays the same** because the relative distance between the code and data doesn't change. Only the base address changes, and RIP-relative addressing automatically adjusts for it!

### Data Placement in include.s and main.s

The data sections in `include.s` contain:
```assembly
procdir: db "/proc/", 0
proc_status: db "/status", 0
firstDir: db "/tmp/test", 0
secondDir: db "/tmp/test2", 0
signature: db "Famine version 1.0 (c)oded by <ocrossi>-<elaignel>", 0
```

These are placed in the `.text` section and become part of the virus payload. When using **absolute addressing**, these become "hard-coded" addresses that break when the code is relocated. With **RIP-relative addressing**, the references remain valid regardless of where the code is loaded.

## Summary

| Addressing Mode | Instruction | Position-Independent? | Works in Infected Binary? |
|----------------|-------------|----------------------|--------------------------|
| Absolute | `movabs $addr,%reg` | ❌ No | ❌ No - SEGFAULT |
| RIP-Relative | `lea offset(%rip),%reg` | ✅ Yes | ✅ Yes |

**The fix:** Changed from `mov rsi, label` (absolute) to `lea rsi, [rel label]` (RIP-relative) in `sources/virus.s` lines 122 and 134.

This ensures the virus code remains position-independent and can execute correctly when injected into other binaries at different memory addresses.
