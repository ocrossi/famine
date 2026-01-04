# Segfault Fix: Documentation Index

This directory contains comprehensive documentation explaining and fixing a segmentation fault issue in the Famine virus code.

## Quick Start

**Problem:** Virus code segfaults when injected into other binaries.

**Root Cause:** Using absolute addressing instead of RIP-relative addressing.

**Fix:** Changed 2 lines in `sources/virus.s` to use `lea reg, [rel label]` instead of `mov reg, label`.

## Documentation Files

### 1. [FIX_SUMMARY.md](FIX_SUMMARY.md) - **Start Here!**
Executive summary of the issue and fix. Best for quick understanding.
- What was the problem
- What was the fix
- How to verify it

### 2. [BEFORE_AFTER_COMPARISON.md](BEFORE_AFTER_COMPARISON.md)
Visual side-by-side comparison showing:
- Source code before/after
- Assembly instructions before/after  
- Address calculations in both scenarios
- Benefits of the fix

### 3. [SEGFAULT_ANALYSIS.md](SEGFAULT_ANALYSIS.md)
Explanation of how the virus works and why absolute addressing breaks it:
- How virus injection works
- Address calculation examples
- Why RIP-relative addressing solves the problem

### 4. [DETAILED_ANALYSIS.md](DETAILED_ANALYSIS.md) - **Most Comprehensive**
Complete technical deep-dive including:
- Instruction encoding details
- GDB debugging session examples
- How to identify the problem in disassembly
- x86-64 addressing mode explanations

## The Problem

When using `mov rsi, firstDir` in the virus code, NASM generates:
```assembly
movabs $0x40101a,%rsi    # 10 bytes, absolute address
```

This hard-codes the address `0x40101a` into the instruction. When the virus is copied to an infected binary at a different address (e.g., `0x5000000`), the instruction still tries to access `0x40101a` which is now invalid → **SEGFAULT**.

## The Solution

Using `lea rsi, [rel firstDir]` generates:
```assembly
lea -0x484(%rip),%rsi    # 7 bytes, RIP-relative offset
```

This uses an offset relative to the current instruction pointer. When the code is copied to `0x5000000`, the offset `-0x484` stays the same, but RIP changes to `0x500049e`, so the calculation becomes:
```
0x500049e + (-0x484) = 0x500001a  ✓ Correct!
```

## Code Changes

**File:** `sources/virus.s`

**Line 122:**
```diff
-    mov rsi, firstDir           ; source = /tmp/test
+    lea rsi, [rel firstDir]     ; source = /tmp/test
```

**Line 134:**
```diff
-    mov rsi, secondDir          ; source = /tmp/test2
+    lea rsi, [rel secondDir]    ; source = /tmp/test2
```

## Verification

Check the disassembly to verify the fix:
```bash
objdump -d Famine | grep "401497:"
```

**Before:** `movabs $0x40101a,%rsi` ❌

**After:** `lea -0x484(%rip),%rsi` ✅

## Key Takeaway

In x86-64 position-independent code:
- **Don't use:** `mov reg, label` → absolute addressing
- **Do use:** `lea reg, [rel label]` → RIP-relative addressing

The `[rel]` directive in NASM is essential for creating code that can run at any address.
