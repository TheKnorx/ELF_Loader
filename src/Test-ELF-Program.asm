; nasm -f elf64 Test-ELF-Program.asm
; gcc -no-pie Test-ELF-Program.o -o Test-ELF-Program

section .bss
section .data
    MSG: db "Hello World!", 0x0A, 0x00
section .text

extern printf

global main

main: 
    xor     rax, rax
    mov     rdi, MSG
    call    printf
exit: 
    ret


