%include "include.s"

  
global _start

_start:
    ; syscall write 
    mov eax, 4
    mov ebx, 1
    mov ecx, signature 
    mov edx, signature_len
    int 0x80 

    ; exit syscall 
    mov eax, 1
    xor ebx, ebx 
    int 0x80
