; ============================================
; UTILITY FUNCTIONS
; These functions have been moved into virus.s to be part of the virus payload
; This allows both original Famine and virus code to use the same functions
; reducing code duplication
; ============================================

; str_len, str_copy, and search_substring are now defined in virus.s
; They are position-independent and work in both contexts

; print_string is still here as it's only used by main code in verbose mode
%ifdef VERBOSE_MODE
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
    call str_len                ; rax = length (calls virus.s version)

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
%endif

