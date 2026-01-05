Famine Virus - Simple Algorithm Explanation
Phase 1: Entry Point and Setup

    The program starts at _start and sets up the stack frame by saving registers.
    The program performs an anti-debugging check using the ptrace system call.
    The program checks if the code is encrypted and skips decryption if not.
    The program calculates its base address in memory for position-independent execution.
    The program checks if it's running as the original binary or as injected virus code.

Phase 2: Directory Scanning (Original Binary)

    The program initializes the file counter to zero.
    The program copies the target directory path "/tmp/test" to a buffer.
    The program calls list_files_recursive to scan the directory.
    The function opens the directory using the openat system call.
    The function reads directory entries using getdents64 system call.
    The function processes each entry, skipping "." and ".." entries.
    The function builds the full path for each file by concatenating directory and filename.
    For regular files, the program stores them in a file list.
    For subdirectories, the program recursively calls itself to scan them.
    The program closes the directory after scanning all entries.

Phase 3: ELF Validation and Infection

    The program iterates through the collected file list.
    For each file, it opens the file and reads the ELF header (64 bytes).
    The program validates the ELF magic number (0x7F 'E' 'L' 'F').
    The program checks if the file is 64-bit ELF (ELFCLASS64).
    The program checks if it's an executable type (ET_EXEC or ET_DYN).
    The program searches the file for the virus signature to avoid reinfection.
    The program reads all program headers from the ELF file.
    The program searches for a PT_NOTE segment to hijack.
    The program finds the maximum virtual address used by existing segments.
    The program calculates a new virtual address for the virus code.
    The program converts the PT_NOTE segment to PT_LOAD type.
    The program sets the new segment to point to the end of the file.
    The program updates the segment with appropriate permissions (RWX).
    The program saves the original entry point address.
    The program updates the entry point to jump to the virus code.
    The program writes the modified program headers back to the file.
    The program writes the modified ELF header back to the file.
    The program copies the virus code to a temporary buffer.
    The program patches the virus code with the offset to the original entry point.
    The program seeks to the end of the file.
    The program appends the virus code to the file.
    The program closes the infected file.

Phase 4: Second Directory Scan

    The program repeats the scanning and infection process for "/tmp/test2".

Phase 5: Virus Execution (Infected Binary)

    When an infected binary runs, it starts at the virus entry point.
    The virus calculates where the original entry point is located.
    The virus allocates stack space for its operations.
    The virus recursively scans and infects files in "/tmp/test".
    The virus recursively scans and infects files in "/tmp/test2".
    The virus restores the original stack state.
    The virus clears all modified registers.
    The virus jumps to the original program entry point.
    The original program executes normally without knowing it was infected.

Key Techniques

    Position-independent code uses RIP-relative addressing to work at any memory location.
    The PT_NOTE to PT_LOAD conversion hijacks unused segments for code injection.
    Signature checking prevents infinite reinfection of the same file.

