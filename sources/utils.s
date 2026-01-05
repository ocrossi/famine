; ============================================
; print_string(char *str)
; rdi = pointer to null-terminated string
; ============================================
print_string:
    push rdi
    push rsi
    push rdx

    ; Get string length
    mov rsi, rdi                ; save string pointer
    call str_len                ; rax = length

    ; Write to stdout
    mov rdx, rax                ; length
    mov rdi, STDOUT             ; fd = stdout
    mov eax, SYS_WRITE
    ; rsi already contains string pointer
    syscall

    pop rdx
    pop rsi
    pop rdi
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
; search_substring(char *haystack, size_t haystack_len, char *needle, size_t needle_len)
; rdi = haystack (buffer to search in)
; rsi = haystack_len (length of buffer)
; rdx = needle (string to search for)
; rcx = needle_len (length of needle)
; Returns: rax = 1 if found, 0 if not found
; ============================================
search_substring:
    push rbp
    mov rbp, rsp
    push r12                    ; haystack
    push r13                    ; haystack_len
    push r14                    ; needle
    push r15                    ; needle_len
    push rbx                    ; current position

    mov r12, rdi                ; r12 = haystack
    mov r13, rsi                ; r13 = haystack_len
    mov r14, rdx                ; r14 = needle
    mov r15, rcx                ; r15 = needle_len

    ; If needle is longer than haystack, not found
    cmp r15, r13
    ja .search_not_found

    xor rbx, rbx                ; rbx = current position in haystack

.search_loop:
    ; Check if we have enough bytes left
    mov rax, r13
    sub rax, rbx                ; bytes remaining
    cmp rax, r15
    jb .search_not_found        ; not enough bytes left

    ; Compare needle with current position in haystack
    lea rdi, [r12 + rbx]        ; current position in haystack
    mov rsi, r14                ; needle
    mov rcx, r15                ; needle_len
    
    ; Byte-by-byte comparison
    xor rax, rax                ; match counter
.compare_loop:
    cmp rax, r15
    jge .search_found           ; all bytes matched

    mov r8b, [rdi + rax]        ; byte from haystack
    mov r9b, [rsi + rax]        ; byte from needle
    cmp r8b, r9b
    jne .search_next            ; mismatch, try next position

    inc rax
    jmp .compare_loop

.search_next:
    inc rbx                     ; move to next position
    jmp .search_loop

.search_found:
    mov rax, 1
    jmp .search_done

.search_not_found:
    xor rax, rax

.search_done:
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    mov rsp, rbp
    pop rbp
    ret

; ============================================
; check_process_running()
; Checks if a process named "test" is running
; Returns: rax = 1 if "test" process is running, 0 otherwise
; ============================================
check_process_running:
    push rbp
    mov rbp, rsp
    push r12                    ; proc fd
    push r13                    ; status fd
    push r14                    ; bytes read
    push r15                    ; process found flag
    push rbx                    ; current position

    xor r15, r15                ; process found flag = 0

    ; Open /proc directory
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    lea rsi, [rel procdir]
    mov edx, O_RDONLY | O_DIRECTORY
    xor r10d, r10d
    syscall

    test rax, rax
    js .check_proc_done         ; Failed to open /proc

    mov r12, rax                ; Save /proc fd

.check_proc_read_loop:
    ; Read directory entries into BSS buffer
    mov eax, SYS_GETDENTS64
    mov edi, r12d
    lea rsi, [rel proc_dirent_buf]
    mov edx, 512
    syscall

    test rax, rax
    jle .check_proc_close       ; EOF or error

    mov r14, rax                ; Save bytes read
    xor rbx, rbx                ; pos = 0

.check_proc_process_entry:
    cmp rbx, r14
    jge .check_proc_read_loop

    lea rdi, [rel proc_dirent_buf]
    add rdi, rbx                ; dirent pointer

    ; Get d_reclen
    movzx ecx, word [rdi + 16]
    push rcx                    ; Save d_reclen

    ; Get d_name
    lea rsi, [rdi + 19]

    ; Check if d_name is numeric (process directory)
    movzx eax, byte [rsi]
    cmp al, '0'
    jb .check_proc_next_entry_pop
    cmp al, '9'
    ja .check_proc_next_entry_pop

    ; Build path: /proc/[pid]/status in BSS buffer
    lea rdi, [rel proc_path_buf]
    lea rsi, [rel procdir]
    call str_copy               ; Copy "/proc/"
    
    lea rdi, [rel proc_path_buf]
    mov rax, 6                  ; length of "/proc/"
    add rdi, rax
    lea rsi, [rel proc_dirent_buf]
    add rsi, rbx
    add rsi, 19                 ; d_name
    call str_copy               ; Copy pid
    
    ; Append "/status"
    lea rdi, [rel proc_path_buf]
    call str_len
    lea rdi, [rel proc_path_buf]
    add rdi, rax
    lea rsi, [rel proc_status]
    call str_copy

    ; Open status file
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    lea rsi, [rel proc_path_buf]
    xor edx, edx                ; O_RDONLY
    xor r10d, r10d
    syscall

    test rax, rax
    js .check_proc_next_entry_pop   ; Failed to open status file

    mov r13, rax                ; Save status fd

    ; Read status file into BSS buffer
    mov eax, SYS_READ
    mov edi, r13d
    lea rsi, [rel proc_status_buf]
    mov edx, 128
    syscall

    push rax                    ; Save bytes read

    ; Close status file
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

    pop rsi                     ; Restore bytes read
    test rsi, rsi
    jle .check_proc_next_entry_pop

    ; Search for "Name:\ttest\n" in status buffer
    lea rdi, [rel proc_status_buf]
    lea rdx, [rel proc_test.string]
    mov rcx, proc_test.len
    call search_substring

    test rax, rax
    jz .check_proc_next_entry_pop

    ; Found "test" process!
    mov r15, 1
    pop rcx                     ; Clean up d_reclen
    jmp .check_proc_close

.check_proc_next_entry_pop:
    pop rcx                     ; d_reclen
    add rbx, rcx
    jmp .check_proc_process_entry

.check_proc_close:
    mov eax, SYS_CLOSE
    mov edi, r12d
    syscall

.check_proc_done:
    mov rax, r15                ; Return process found flag

    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    mov rsp, rbp
    pop rbp
    ret

; ============================================
; generate_random_suffix()
; Generates 8 random alphanumeric characters
; Stores result in random_suffix buffer in .bss section
; Uses SYS_GETRANDOM syscall
; ============================================
generate_random_suffix:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    push rdx

    ; Get random bytes
    mov eax, SYS_GETRANDOM
    lea rdi, [rel random_suffix]
    mov esi, RANDOM_SUFFIX_LEN
    xor edx, edx                ; flags = 0 (default)
    syscall

    ; Convert each byte to alphanumeric character
    xor rcx, rcx
.convert_loop:
    cmp rcx, RANDOM_SUFFIX_LEN
    jge .done

    lea rsi, [rel random_suffix]
    movzx eax, byte [rsi + rcx] ; Get random byte
    xor rdx, rdx
    mov ebx, 62                 ; 62 possible chars (0-9, A-Z, a-z)
    div ebx                     ; rdx = eax % 62

    ; Convert to character: 0-9 (0-9), 10-35 (A-Z), 36-61 (a-z)
    cmp edx, 10
    jl .digit
    cmp edx, 36
    jl .upper
    ; lowercase
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
    jmp .convert_loop

.done:
    pop rdx
    pop rcx
    pop rbx
    pop rbp
    ret


