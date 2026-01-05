Famine Virus - Detailed Algorithm Explanation
Phase 1: Entry Point and Setup
1. Stack Frame Initialization

The program starts at _start and sets up the stack frame by saving registers. This involves pushing rbp, setting rbp to rsp, and pushing all callee-saved registers (rbx, r12, r13, r14, r15) to preserve their values across function calls following the x86-64 calling convention.
2. Anti-Debugging Check

The program performs an anti-debugging check using the ptrace system call (syscall number 101). It calls ptrace(PTRACE_TRACEME, 0, 0, 0) which returns -1 if the process is already being traced by a debugger, allowing the virus to detect debugging attempts and potentially exit or modify its behavior.
3. Encryption Check

The program checks if the code is encrypted by reading the encrypted_flag byte relative to the virus base address. If the flag is non-zero, it would decrypt the code using XOR operations; otherwise, it skips decryption and continues with normal execution.
4. Position-Independent Base Address Calculation

The program calculates its base address in memory using the call/pop technique: it calls a label, pops the return address from the stack (which is the address of that label), and subtracts the offset to find virus_start. This enables position-independent code execution at any memory address.
5. Binary Type Detection

The program checks the original_entry_storage value to determine execution mode. If zero, it's the original Famine binary and should scan/infect files. If non-zero, it's running as injected virus code in an infected binary and should spread infection before jumping to the original entry point.
Phase 2: Directory Scanning (Original Binary)
6. File Counter Initialization

The program initializes the file counter to zero using mov qword [rel file_count], 0, preparing to track how many files are discovered during directory traversal.
7. Path Buffer Setup

The program copies the target directory path "/tmp/test" to a buffer using the str_copy utility function, which performs a byte-by-byte copy until it encounters a null terminator.
8. Recursive Directory Traversal Initiation

The program calls list_files_recursive with the path buffer address, initiating a depth-first traversal of the directory tree to discover all files and subdirectories.
9. Directory Opening

The function opens the directory using openat (syscall 257) with flags O_RDONLY | O_DIRECTORY (0x10000) and AT_FDCWD (-100) as the directory file descriptor, which means relative to the current working directory. This returns a file descriptor for reading directory contents.
10. Directory Entry Reading

The function reads directory entries using getdents64 (syscall 217), which fills a buffer with multiple linux_dirent64 structures containing inode numbers, offsets, record lengths, file types, and filenames for each entry in the directory.
11. Entry Filtering

The function processes each entry in the buffer, extracting the d_type field (byte 18) to determine file type and the d_name field (starting at byte 19) for the filename. It explicitly skips "." and ".." entries by comparing the first characters and checking for null terminators.
12. Path Construction

The function builds the full path for each file by checking if the current path ends with '/', appending '/' if needed, and then calling str_copy to concatenate the filename to the path buffer, creating absolute paths for all discovered files.
13. Regular File Handling

For regular files (d_type == DT_REG which equals 8), the program prints the file path to stdout using the write syscall (syscall 1) with file descriptor STDOUT (1), allowing users to see which files are being processed.
14. Subdirectory Recursion

For subdirectories (d_type == DT_DIR which equals 4), the program recursively calls list_files_recursive with the new path, implementing depth-first traversal to explore all subdirectories and their contents.
15. Directory Cleanup

The program closes the directory file descriptor using the close syscall (syscall 3) after reading all entries, freeing system resources and ensuring proper cleanup before returning from the function.
Phase 3: ELF Validation and Infection
16. File List Iteration

The program iterates through the collected file list, processing each file path to determine if it's a valid target for infection.
17. ELF Header Reading

For each file, it opens the file using openat with O_RDWR flags (read-write mode) and reads the first 64 bytes using the read syscall (syscall 0), which contains the complete ELF header structure.
18. Magic Number Validation

The program validates the ELF magic number by comparing the first four bytes to 0x7F, 'E', 'L', 'F', ensuring the file is actually an ELF binary and not some other file type.
19. Class Verification

The program checks byte 4 (EI_CLASS) to verify it's 64-bit ELF by comparing it to ELFCLASS64 (value 2), as the virus is designed specifically for 64-bit binaries and cannot infect 32-bit executables.
20. Executable Type Check

The program checks the e_type field at offset 16 to verify it's either ET_EXEC (value 2, traditional executable) or ET_DYN (value 3, position-independent executable/PIE), as these are the executable types that can be infected.
21. Signature Search

The program searches the entire file for the virus signature string "Famine version 1.0 (c)oded by <ocrossi>-<elaignel>" using the search_substring utility, which performs a byte-by-byte comparison throughout the file. If found, the file is already infected and should be skipped to avoid reinfection.
22. Program Header Extraction

The program reads all program headers from the ELF file by seeking to the offset specified in e_phoff (offset 32) using lseek (syscall 8), then reading e_phnum * e_phentsize bytes (typically 56 bytes per header), loading all segment descriptors into memory.
23. PT_NOTE Segment Search

The program searches for a PT_NOTE segment by iterating through the program headers and checking if p_type equals PT_NOTE (value 4). PT_NOTE segments contain auxiliary information and are often non-essential, making them ideal targets for conversion to code segments.
24. Maximum Virtual Address Discovery

The program finds the maximum virtual address used by existing PT_LOAD segments by iterating through all program headers, checking for p_type == PT_LOAD (value 1), and tracking the highest value of p_vaddr + p_memsz to determine where new code can be safely placed.
25. New Virtual Address Calculation

The program calculates a new virtual address for the virus code by taking the file size modulo 0x1000 (page size 4KB) to get the page offset, aligning the maximum virtual address up to the next page boundary, and adding the page offset to maintain proper alignment with the file offset.
26. PT_NOTE to PT_LOAD Conversion

The program converts the PT_NOTE segment to PT_LOAD type by setting p_type to 1, effectively hijacking the segment descriptor to create a new loadable code segment without adding new entries to the program header table.
27. End-of-File Segment Configuration

The program sets the segment to point to the end of the file by setting p_offset to the current file size and p_filesz to the virus code size (virus_end - virus_start), ensuring the virus code will be mapped when the binary is loaded.
28. Permission Configuration

The program updates the segment permissions by setting p_flags to PF_R | PF_W | PF_X (value 7), granting read, write, and execute permissions necessary for the virus code to run and potentially modify itself.
29. Original Entry Point Storage

The program saves the original entry point address from e_entry (offset 24) to calculate the offset needed for the virus to return control to the legitimate program after executing its payload.
30. Entry Point Hijacking

The program updates the entry point by setting e_entry to the new virtual address plus the offset from virus_start to _start, ensuring the virus code executes first when the infected binary is loaded by the kernel's ELF loader.
31. Program Header Update

The program writes the modified program headers back to the file by seeking to e_phoff using lseek and using the write syscall to overwrite the original segment descriptors with the modified version containing the new PT_LOAD segment.
32. ELF Header Update

The program writes the modified ELF header back to the file by seeking to offset 0 and writing 64 bytes, updating the entry point and ensuring the binary will load and execute correctly with the modifications.
33. Virus Code Buffer Preparation

The program copies the virus code from virus_start to virus_end to a temporary buffer, creating a working copy that can be patched without modifying the original virus code in the Famine binary itself.
34. Entry Point Offset Patching

The program patches the virus code copy by calculating the offset from the new entry point to the original entry point and writing this value to the original_entry_storage location in the buffer, enabling the virus to find and jump to the legitimate program.
35. File Position Seeking

The program seeks to the end of the file using lseek with SEEK_END (value 2), positioning the file offset at the exact location where the virus code should be appended.
36. Virus Code Appending

The program appends the virus code to the file using the write syscall, writing the entire patched virus payload (typically several kilobytes) to the end of the ELF binary, permanently embedding the infection.
37. File Closure

The program closes the infected file using the close syscall, flushing all buffers, committing changes to disk, and releasing the file descriptor for reuse.
Phase 4: Second Directory Scan
38. Repeated Infection Process

The program repeats the entire scanning and infection process for "/tmp/test2" directory by copying the path, calling list_files_recursive, validating ELF files, and infecting suitable targets, effectively doubling the potential spread of the virus.
Phase 5: Virus Execution (Infected Binary)
39. Virus Entry Point Execution

When an infected binary runs, the kernel's ELF loader reads e_entry and jumps to the virus entry point instead of the original program entry, giving the virus complete control before the legitimate program executes.
40. Original Entry Point Calculation

The virus calculates the original entry point by getting its current execution address using the call/pop technique, adding the original_entry_storage offset (which was patched during infection), and determining the absolute address of the legitimate program's entry point.
41. Stack Space Allocation

The virus allocates stack space for its operations using sub rsp, VIRUS_STACK_SIZE (typically 16KB), providing buffer space for path strings, file lists, and local variables needed during the infection process, and aligns the stack to 16-byte boundaries.
42. First Directory Infection

The virus recursively scans and infects files in "/tmp/test" by calling virus_list_and_infect, which performs directory traversal with openat and getdents64, validates ELF files, and calls virus_infect_elf for each suitable target, spreading the infection.
43. Second Directory Infection

The virus recursively scans and infects files in "/tmp/test2" using the same virus_list_and_infect function, potentially infecting additional binaries and increasing the virus's presence on the system.
44. Stack Restoration

The virus restores the original stack state by setting rsp back to rbp and popping the saved frame pointer, ensuring the stack appears exactly as it did when the binary was loaded, hiding evidence of virus execution.
45. Register Sanitization

The virus clears all modified registers by XORing them with themselves (xor rdi, rdi, xor rsi, rsi, etc.), removing any traces of its operation and preventing information leakage that might reveal the infection to the legitimate program.
46. Control Transfer

The virus jumps to the original program entry point using jmp rax (where rax contains the calculated original entry address), seamlessly transferring execution to the legitimate program as if nothing happened.
47. Transparent Execution

The original program executes normally without knowing it was infected, as the virus has cleaned up all evidence, restored the stack, and transferred control cleanly, making the infection invisible to the user and the program itself.
Key Techniques
48. Position-Independent Code (PIC)

Position-independent code uses RIP-relative addressing (lea reg, [rel label]) instead of absolute addressing (mov reg, address), allowing the code to work correctly at any memory location by calculating offsets from the instruction pointer rather than using fixed addresses.
49. PT_NOTE Segment Hijacking

The PT_NOTE to PT_LOAD conversion hijacks unused segments for code injection by changing the segment type field in the program header, avoiding the need to expand the program header table or shift existing segments, which would be much more complex and detectable.
50. Signature-Based Infection Prevention

Signature checking prevents infinite reinfection of the same file by searching for a unique string that only exists in infected binaries, ensuring each file is infected only once and preventing the virus from growing exponentially or corrupting already-infected files.
