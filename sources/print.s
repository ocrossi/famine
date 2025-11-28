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
