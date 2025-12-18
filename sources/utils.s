; ============================================
; print_string(char *str)
; rdi = pointer to null-terminated string
; ============================================
print_string:
%ifdef VERBOSE_MODE
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
%endif
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

