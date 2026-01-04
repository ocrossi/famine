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
    push r14                    ; dirent buffer ptr
    push r15                    ; process found flag
    push rbx
    sub rsp, 512                ; Stack space for buffers (AFTER pushes)

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
    ; Read directory entries
    mov eax, SYS_GETDENTS64
    mov edi, r12d
    lea rsi, [rsp]              ; Buffer at rsp (after stack allocation)
    mov edx, 512
    syscall

    test rax, rax
    jle .check_proc_close       ; EOF or error

    mov [rbp-8], rax            ; Save bytes read
    mov qword [rbp-16], 0       ; pos = 0

.check_proc_process_entry:
    mov rax, [rbp-16]
    cmp rax, [rbp-8]
    jge .check_proc_read_loop

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
    jb .check_proc_next_entry
    cmp al, '9'
    ja .check_proc_next_entry

    ; Build path: /proc/[pid]/status
    lea rdi, [rsp+256]          ; path buffer
    lea rsi, [rel procdir]
    call str_copy               ; Copy "/proc/"
    
    lea rdi, [rsp+256]
    mov rax, 6                  ; length of "/proc/"
    add rdi, rax
    lea rsi, [rsp]
    mov rax, [rbp-16]
    add rsi, rax
    add rsi, 19                 ; d_name
    call str_copy               ; Copy pid
    
    ; Append "/status"
    lea rdi, [rsp+256]
    call str_len
    lea rdi, [rsp+256]
    add rdi, rax
    lea rsi, [rel proc_status]
    call str_copy

    ; Open status file
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    lea rsi, [rsp+256]
    xor edx, edx                ; O_RDONLY
    xor r10d, r10d
    syscall

    test rax, rax
    js .check_proc_next_entry   ; Failed to open status file

    mov r13, rax                ; Save status fd

    ; Read status file (first 256 bytes should be enough)
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
    jle .check_proc_next_entry

    ; Search for "Name:\ttest\n" in status buffer
    lea rdi, [rsp+128]
    mov rsi, [rbp-32]           ; bytes read
    lea rdx, [rel proc_test.string]
    mov rcx, proc_test.len
    call search_substring

    test rax, rax
    jz .check_proc_next_entry

    ; Found "test" process!
    mov r15, 1
    jmp .check_proc_close

.check_proc_next_entry:
    mov rax, [rbp-16]
    add rax, [rbp-24]
    mov [rbp-16], rax
    jmp .check_proc_process_entry

.check_proc_close:
    mov eax, SYS_CLOSE
    mov edi, r12d
    syscall

.check_proc_done:
    mov rax, r15                ; Return process found flag

    add rsp, 512                ; Deallocate buffer first
    pop rbx                     ; Then restore registers in reverse order
    pop r15
    pop r14
    pop r13
    pop r12
    mov rsp, rbp
    pop rbp
    ret

