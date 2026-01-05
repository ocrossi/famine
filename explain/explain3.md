# Famine Virus - Comprehensive Algorithm Explanation with Difficulty Ratings

## Syscalls Used in Famine Virus

| Syscall Number | Name | Purpose |
|----------------|------|---------|
| 0 | SYS_READ | Read file content into buffer |
| 1 | SYS_WRITE | Write data to file/stdout |
| 3 | SYS_CLOSE | Close file descriptor |
| 8 | SYS_LSEEK | Seek to position within file |
| 60 | SYS_EXIT | Exit program |
| 101 | SYS_PTRACE | Process tracing (anti-debugging) |
| 217 | SYS_GETDENTS64 | Read directory entries |
| 257 | SYS_OPENAT | Open file or directory |

---

## Phase 1: Entry Point and Setup

### 1. Stack Frame Initialization
**Difficulty: ⭐☆☆☆☆ (Basic)**

The program starts at `_start` and sets up the stack frame by saving registers. This involves pushing `rbp`, setting `rbp` to `rsp`, and pushing all callee-saved registers (`rbx`, `r12`, `r13`, `r14`, `r15`) to preserve their values across function calls following the x86-64 calling convention.

**Syscalls:** None

### 2. Anti-Debugging Check
**Difficulty: ⭐⭐⭐☆☆ (Intermediate)**

The program performs an anti-debugging check using the `ptrace` system call (syscall number 101). It calls `ptrace(PTRACE_TRACEME, 0, 0, 0)` which returns -1 if the process is already being traced by a debugger, allowing the virus to detect debugging attempts and potentially exit or modify its behavior.

**Syscalls:** SYS_PTRACE (101)

### 3. Encryption Check
**Difficulty: ⭐⭐⭐⭐☆ (Advanced)**

The program checks if the code is encrypted by reading the `encrypted_flag` byte relative to the virus base address. If the flag is non-zero, it would decrypt the code using XOR operations; otherwise, it skips decryption and continues with normal execution. Encryption serves to defeat static analysis and evade signature-based detection.

**Syscalls:** None

### 4. Position-Independent Base Address Calculation
**Difficulty: ⭐⭐⭐⭐⭐ (Expert)**

The program calculates its base address in memory using the call/pop technique: it calls a label, pops the return address from the stack (which is the address of that label), and subtracts the offset to find `virus_start`. This enables position-independent code execution at any memory address. This is critical because when the virus code is injected into another binary, it will be loaded at a different virtual address than it was assembled for.

**Syscalls:** None

### 5. Binary Type Detection
**Difficulty: ⭐⭐⭐⭐☆ (Advanced)**

The program checks the `original_entry_storage` value to determine execution mode. If zero, it's the original Famine binary and should scan/infect files. If non-zero, it's running as injected virus code in an infected binary and should spread infection before jumping to the original entry point. This dual-mode operation is critical for stealth.

**Syscalls:** None

---

## Phase 2: Directory Scanning (Original Binary)

### 6. File Counter Initialization
**Difficulty: ⭐☆☆☆☆ (Basic)**

The program initializes the file counter to zero using `mov qword [rel file_count], 0`, preparing to track how many files are discovered during directory traversal. The `[rel file_count]` syntax uses RIP-relative addressing for position independence.

**Syscalls:** None

### 7. Path Buffer Setup
**Difficulty: ⭐⭐☆☆☆ (Easy)**

The program copies the target directory path "/tmp/test" to a buffer using the `str_copy` utility function, which performs a byte-by-byte copy until it encounters a null terminator. This is necessary because the path buffer will be modified during directory traversal.

**Syscalls:** None

### 8. Recursive Directory Traversal Initiation
**Difficulty: ⭐⭐⭐☆☆ (Intermediate)**

The program calls `list_files_recursive` with the path buffer address, initiating a depth-first traversal of the directory tree to discover all files and subdirectories. The depth-first approach is simpler to implement than breadth-first and uses less memory.

**Syscalls:** None (calls function that uses syscalls)

### 9. Directory Opening
**Difficulty: ⭐⭐⭐☆☆ (Intermediate)**

The function opens the directory using `openat` (syscall 257) with flags `O_RDONLY | O_DIRECTORY` (0x10000) and `AT_FDCWD` (-100) as the directory file descriptor, which means relative to the current working directory. This returns a file descriptor for reading directory contents.

**Syscalls:** SYS_OPENAT (257)

### 10. Directory Entry Reading
**Difficulty: ⭐⭐⭐⭐☆ (Advanced)**

The function reads directory entries using `getdents64` (syscall 217), which fills a buffer with multiple `linux_dirent64` structures containing inode numbers, offsets, record lengths, file types, and filenames for each entry in the directory. This is much more efficient than making a syscall per file.

**Syscalls:** SYS_GETDENTS64 (217)

### 11. Entry Filtering
**Difficulty: ⭐⭐⭐☆☆ (Intermediate)**

The function processes each entry in the buffer, extracting the `d_type` field (byte 18) to determine file type and the `d_name` field (starting at byte 19) for the filename. It explicitly skips "." and ".." entries to prevent infinite recursion.

**Syscalls:** None

### 12. Path Construction
**Difficulty: ⭐⭐⭐☆☆ (Intermediate)**

The function builds the full path for each file by checking if the current path ends with '/', appending '/' if needed, and then calling `str_copy` to concatenate the filename to the path buffer. The path length is saved and restored to enable path reuse without allocating new buffers.

**Syscalls:** None

### 13. Regular File Handling
**Difficulty: ⭐⭐☆☆☆ (Easy)**

For regular files (`d_type == DT_REG` which equals 8), the program prints the file path to stdout using the `write` syscall (syscall 1) with file descriptor `STDOUT` (1), allowing users to see which files are being processed.

**Syscalls:** SYS_WRITE (1)

### 14. Subdirectory Recursion
**Difficulty: ⭐⭐⭐⭐☆ (Advanced)**

For subdirectories (`d_type == DT_DIR` which equals 4), the program recursively calls `list_files_recursive` with the updated path. This recursion creates a call stack that grows with the depth of the directory tree, implementing depth-first traversal.

**Syscalls:** None (recursive call)

### 15. Directory Cleanup
**Difficulty: ⭐⭐☆☆☆ (Easy)**

The program closes the directory file descriptor using the `close` syscall (syscall 3) after reading all entries, freeing system resources and ensuring proper cleanup. This is essential to avoid running out of file descriptors.

**Syscalls:** SYS_CLOSE (3)

---

## Phase 3: ELF Validation and Infection

### 16. File List Iteration
**Difficulty: ⭐⭐☆☆☆ (Easy)**

The program iterates through the collected file list by setting up a loop counter and processing each file path sequentially. This separates the discovery phase from the infection phase for clearer code organization.

**Syscalls:** None

### 17. ELF Header Reading
**Difficulty: ⭐⭐⭐☆☆ (Intermediate)**

For each file, the program opens it using `openat` with `O_RDWR` flags (read-write mode) and reads the first 64 bytes using the `read` syscall (syscall 0), which contains the complete ELF header structure.

**Syscalls:** SYS_OPENAT (257), SYS_READ (0)

### 18. Magic Number Validation
**Difficulty: ⭐⭐☆☆☆ (Easy)**

The program validates the ELF magic number by comparing the first four bytes to `0x7F`, 'E', 'L', 'F'. This is the quickest way to filter out non-ELF files without parsing the entire header structure.

**Syscalls:** None

### 19. Class Verification
**Difficulty: ⭐⭐☆☆☆ (Easy)**

The program checks byte 4 (EI_CLASS field) to verify the file is 64-bit ELF by comparing it to `ELFCLASS64` (value 2). The virus is designed specifically for 64-bit binaries and cannot infect 32-bit executables.

**Syscalls:** None

### 20. Executable Type Check
**Difficulty: ⭐⭐⭐☆☆ (Intermediate)**

The program checks the `e_type` field at offset 16 to verify it's either `ET_EXEC` (value 2, traditional executable) or `ET_DYN` (value 3, position-independent executable/PIE). Both types can be infected because both can be executed.

**Syscalls:** None

### 21. Signature Search
**Difficulty: ⭐⭐⭐⭐☆ (Advanced)**

The program searches the entire file for the virus signature string "Famine version 1.0 (c)oded by <ocrossi>-<elaignel>" using a substring search algorithm. It reads the file in chunks and performs byte-by-byte comparison. If found, the file is already infected and must be skipped to prevent reinfection.

**Syscalls:** SYS_LSEEK (8), SYS_READ (0)

### 22. Program Header Extraction
**Difficulty: ⭐⭐⭐⭐☆ (Advanced)**

The program reads all program headers by extracting metadata from the ELF header (`e_phoff`, `e_phnum`, `e_phentsize`), seeking to the program header table using `lseek`, and reading all headers in one syscall. Each program header is a 56-byte structure describing memory segments.

**Syscalls:** SYS_LSEEK (8), SYS_READ (0)

### 23. PT_NOTE Segment Search
**Difficulty: ⭐⭐⭐☆☆ (Intermediate)**

The program searches for a PT_NOTE segment by iterating through the program headers and checking if `p_type` equals `PT_NOTE` (value 4). PT_NOTE segments contain auxiliary information that is not essential for program execution, making them ideal targets for conversion.

**Syscalls:** None

### 24. Maximum Virtual Address Discovery
**Difficulty: ⭐⭐⭐⭐☆ (Advanced)**

The program finds the maximum virtual address used by existing PT_LOAD segments by iterating through all program headers, checking for `p_type == PT_LOAD`, and tracking the highest value of `p_vaddr + p_memsz`. This determines where new code can be safely placed in the virtual address space.

**Syscalls:** None

### 25. New Virtual Address Calculation
**Difficulty: ⭐⭐⭐⭐⭐ (Expert)**

The program calculates a new virtual address using a complex alignment algorithm: `page_offset = file_size % 0x1000`, `aligned_vaddr = (max_vaddr + 0xfff) & ~0xfff`, `new_vaddr = aligned_vaddr + page_offset`. This ensures the ELF loader's congruency requirement: `vaddr % 4096 == offset % 4096`. Incorrect calculations will result in the infected binary failing to load.

**Syscalls:** None

### 26. PT_NOTE to PT_LOAD Conversion
**Difficulty: ⭐⭐⭐⭐☆ (Advanced)**

The program converts the PT_NOTE segment to PT_LOAD type by changing `p_type` from 4 to 1. This allows code injection without expanding the program header table, avoiding the complexity of shifting the entire file contents and recalculating all offsets.

**Syscalls:** None

### 27. End-of-File Segment Configuration
**Difficulty: ⭐⭐⭐⭐☆ (Advanced)**

The program configures the converted segment by setting `p_offset` to the file size, `p_filesz` to the virus code size, and `p_memsz` to the same value. This tells the loader to read the virus code from the end of the file and map it into memory at the specified virtual address.

**Syscalls:** None

### 28. Permission Configuration
**Difficulty: ⭐⭐⭐☆☆ (Intermediate)**

The program updates the segment permissions by setting `p_flags` to `PF_R | PF_W | PF_X` (value 7), granting read, write, and execute permissions. RWX mappings are necessary for the virus to run and potentially self-modify, though they may be flagged by W^X security policies.

**Syscalls:** None

### 29. Original Entry Point Storage
**Difficulty: ⭐⭐⭐☆☆ (Intermediate)**

The program saves the original entry point address from `e_entry` (offset 24) to calculate the offset needed for the virus to return control to the legitimate program after executing its payload.

**Syscalls:** None

### 30. Entry Point Hijacking
**Difficulty: ⭐⭐⭐⭐☆ (Advanced)**

The program updates the entry point by setting `e_entry` to `new_vaddr + (_start - virus_start)`. When the kernel loads the infected binary, it reads `e_entry` and jumps to the virus code instead of the original program's entry point.

**Syscalls:** None

### 31. Program Header Update
**Difficulty: ⭐⭐⭐☆☆ (Intermediate)**

The program writes the modified program headers back to the file by seeking to `e_phoff` and using the `write` syscall. This makes the PT_NOTE→PT_LOAD conversion permanent.

**Syscalls:** SYS_LSEEK (8), SYS_WRITE (1)

### 32. ELF Header Update
**Difficulty: ⭐⭐☆☆☆ (Easy)**

The program writes the modified ELF header back to the file by seeking to offset 0 and writing 64 bytes. This persists the entry point change.

**Syscalls:** SYS_LSEEK (8), SYS_WRITE (1)

### 33. Virus Code Buffer Preparation
**Difficulty: ⭐⭐⭐☆☆ (Intermediate)**

The program copies the virus code from `virus_start` to `virus_end` to a temporary buffer. Creating a working copy is necessary because the code needs to be patched with the original entry point offset before being written to the file.

**Syscalls:** None

### 34. Entry Point Offset Patching
**Difficulty: ⭐⭐⭐⭐⭐ (Expert)**

The program patches the virus code copy by calculating `offset = original_entry - new_entry` and writing it to the `original_entry_storage` location. This allows the virus to calculate the original entry point at runtime using position-independent techniques, regardless of where the code is loaded.

**Syscalls:** None

### 35. File Position Seeking
**Difficulty: ⭐☆☆☆☆ (Basic)**

The program seeks to the end of the file using `lseek` with `SEEK_END`, positioning the file pointer exactly where the virus code should be appended.

**Syscalls:** SYS_LSEEK (8)

### 36. Virus Code Appending
**Difficulty: ⭐⭐⭐☆☆ (Intermediate)**

The program appends the virus code to the file using the `write` syscall, writing the entire patched virus payload (typically several kilobytes) to the end of the ELF binary. This is the final step that embeds the virus code.

**Syscalls:** SYS_WRITE (1)

### 37. File Closure
**Difficulty: ⭐☆☆☆☆ (Basic)**

The program closes the infected file using the `close` syscall, flushing buffers, updating file metadata, and releasing the file descriptor. This ensures changes are committed to persistent storage.

**Syscalls:** SYS_CLOSE (3)

---

## Phase 4: Second Directory Scan

### 38. Repeated Infection Process
**Difficulty: ⭐⭐☆☆☆ (Easy)**

The program repeats the entire scanning and infection process for the "/tmp/test2" directory, effectively doubling the potential spread of the virus.

**Syscalls:** Same as Phases 2-3

---

## Phase 5: Virus Execution (Infected Binary)

### 39. Virus Entry Point Execution
**Difficulty: ⭐⭐⭐☆☆ (Intermediate)**

When an infected binary is executed, the kernel's ELF loader reads `e_entry` and jumps to the virus code, giving the virus complete control before the legitimate program runs.

**Syscalls:** None (kernel operation)

### 40. Original Entry Point Calculation
**Difficulty: ⭐⭐⭐⭐☆ (Advanced)**

The virus calculates the absolute address of the original entry point using the call/pop method to get its current execution address, then adding the stored offset from `original_entry_storage`. This demonstrates advanced position-independent code techniques.

**Syscalls:** None

### 41. Stack Space Allocation
**Difficulty: ⭐⭐⭐☆☆ (Intermediate)**

The virus allocates stack space (typically 16KB) for its operations by subtracting from `rsp` and aligning to 16-byte boundaries. This provides buffer space for path strings, file lists, and local variables.

**Syscalls:** None

### 42. First Directory Infection
**Difficulty: ⭐⭐⭐⭐☆ (Advanced)**

The virus recursively scans and infects files in "/tmp/test" by calling `virus_list_and_infect`, which performs directory traversal, validates ELF files, and infects suitable targets. This happens transparently while the user thinks they're running the original program.

**Syscalls:** SYS_OPENAT (257), SYS_GETDENTS64 (217), SYS_READ (0), SYS_WRITE (1), SYS_LSEEK (8), SYS_CLOSE (3)

### 43. Second Directory Infection
**Difficulty: ⭐⭐⭐☆☆ (Intermediate)**

The virus repeats the infection process for "/tmp/test2", increasing the chances of spreading to other systems and ensuring persistence.

**Syscalls:** Same as step 42

### 44. Stack Restoration
**Difficulty: ⭐⭐☆☆☆ (Easy)**

The virus restores the original stack state by setting `rsp` back to `rbp` and popping the saved frame pointer, erasing evidence of virus stack usage.

**Syscalls:** None

### 45. Register Sanitization
**Difficulty: ⭐⭐☆☆☆ (Easy)**

The virus clears all modified registers by XORing them with themselves, removing traces of its operation and preventing information leakage to the original program.

**Syscalls:** None

### 46. Control Transfer
**Difficulty: ⭐⭐⭐☆☆ (Intermediate)**

The virus jumps to the original program entry point using `jmp rax`, seamlessly transferring execution to the legitimate program as if nothing happened.

**Syscalls:** None

### 47. Transparent Execution
**Difficulty: ⭐⭐⭐⭐☆ (Advanced)**

The original program executes normally without knowing it was infected. The virus has cleaned up all evidence, making the infection invisible to both the user and the program itself.

**Syscalls:** None

---

## Key Techniques

### 48. Position-Independent Code (PIC)
**Difficulty: ⭐⭐⭐⭐⭐ (Expert)**

Position-independent code uses RIP-relative addressing (`lea reg, [rel label]`) instead of absolute addressing. The address is calculated as `rip + offset` where the offset is encoded in the instruction. This allows the code to work correctly at any memory location, which is critical for virus code that will be injected at different addresses.

**Syscalls:** None

### 49. PT_NOTE Segment Hijacking
**Difficulty: ⭐⭐⭐⭐⭐ (Expert)**

The PT_NOTE to PT_LOAD conversion hijacks unused segments for code injection by changing the segment type field. This technique requires minimal modifications, doesn't expand the file structure, and is relatively stealthy. It requires deep understanding of ELF format, Linux loader implementation, and memory mapping semantics.

**Syscalls:** None

### 50. Signature-Based Infection Prevention
**Difficulty: ⭐⭐⭐☆☆ (Intermediate)**

Signature checking prevents infinite reinfection by embedding a unique string in the virus code and searching for it before infecting. This prevents corrupting file structure, wasting disk space, and making detection trivial through exponentially growing file sizes.

**Syscalls:** SYS_READ (0), SYS_LSEEK (8)

---

## Summary Statistics

**Difficulty Distribution:**
- ⭐☆☆☆☆ (Basic): 5 steps
- ⭐⭐☆☆☆ (Easy): 8 steps
- ⭐⭐⭐☆☆ (Intermediate): 16 steps
- ⭐⭐⭐⭐☆ (Advanced): 15 steps
- ⭐⭐⭐⭐⭐ (Expert): 6 steps

**Total Steps:** 50

**Unique Syscalls:** 8 (SYS_READ, SYS_WRITE, SYS_CLOSE, SYS_LSEEK, SYS_EXIT, SYS_PTRACE, SYS_GETDENTS64, SYS_OPENAT)
