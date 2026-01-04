; ============================================
; UTILITY FUNCTIONS
; 
; Core utility functions (str_len, str_copy, search_substring) have been
; moved into virus.s to be part of the virus payload. This allows both
; the original Famine binary and the virus code running in infected binaries
; to use the same function implementations, eliminating code duplication.
; 
; Benefits:
; - Single source of truth for core utilities
; - No duplicate virus_* versions needed
; - Both execution contexts use identical code
; - Improved maintainability
; 
; Tradeoff:
; - Utility functions are now included in the virus payload (adds ~87 lines)
; - But eliminates need for duplicate versions (saves ~84 lines)
; - Net impact: minimal size increase, significant structural improvement
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
%endif

