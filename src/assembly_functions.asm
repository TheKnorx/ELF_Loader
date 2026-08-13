section .bss
    ENTRY_POINT_ADDR:   resq 1  ; reservate 1 quad word of space for the entry pointer address
section .data
section .text

; prologe - macro for setting up the stack
%macro ENTER 0
    push    rbp
    mov     rbp, rsp
    and     rsp, -16        ; align the stack to multiple of 16
%endmacro
; epiloge - macro for tearing down the stack
%macro LEAVE 0
    mov     rsp, rbp
    pop     rbp
    ret
%endmacro

; This function works just like memcpy, but it copies stuff until it reaches a NULL-terminator
; and returns the amount of chars copied
; original signature:   void *memcpy(void dest[restrict .n], const void src[restrict .n]);
; current signature:    ssize_t memcpy(void* dest, const void* src);
global memcpy_n
memcpy_n:
    ; no prolog or epilog needed

    ; rdi - parameter dest[restrict .n] - rdi already contains destination memory address
    ; rsi - parameter src[restrict .n] - rsi already contains the source memory address
    mov     rcx, rdx    ; move parameter n into counter register
    xor     rdx, rdx,   ; clear rdx - use it as a counter for how many chars we copied
    cld                 ; clear direction flag so that we overwrite upwards from the base memory address
    .cpy:
        movsb           ; overwrite whole allocated memory with char in al
        inc     rdx     ; increment char counter
        cmp     byte [rsi], 0   ; check if rsi is zero or not
        jne     .cpy    ; continue copying if rsi is not zero/null-terminator, else fall through
    .endcpy:
    movsb               ; finally copy the null terminator into memory
    inc     rdx,        ; increment char counter for the null terminator
    mov     rax, rdx    ; move r9/s[.n] into rax for returning
    ret

; This function is just a custom memset implementation in assembly - it works just like memset
; signature:    void *memset(void s[n], int c, size_t n);
global memset_
memset_:
    ; no prolog or epilog needed

    ; rdi - parameter s[n] - rdi already contains destination memory address
    mov     r9, rdi     ; save s[n] into r9 for later use
    mov     rcx, rdx    ; move parameter n into counter register
    mov     al, sil     ; move parameter c into al
    cld                 ; clear direction flag so that we overwrite upwards from the base memory address
    rep stosb           ; overwrite whole allocated memory with char in al

    mov     rax, r9     ; move r9/s[n] into rax for returning
    ret

; this function follows the ABI convention
; we expect the following parameters in the following order: entry_point, address to set rsp to
; we return the following: -
global transfer_control
transfer_control:
    ENTER

    mov     rsp, rsi    ; set stack pointer to point to stack begin
    mov     qword [rel ENTRY_POINT_ADDR], rdi   ; preserve the address of the entry point

    ; zero out all segment registers
    xor     ax, ax
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax

    ; zero out all general purpose registers
    xor     rax, rax
    xor     rbx, rbx
    xor     rcx, rcx
    xor     rdx, rdx
    xor     rbp, rbp
    xor     rsi, rsi
    xor     rdi, rdi
    xor     r8, r8
    xor     r9, r9
    xor     r10, r10
    xor     r11, r11
    xor     r12, r12
    xor     r13, r13
    xor     r14, r14
    xor     r15, r15

    jmp     [rel ENTRY_POINT_ADDR]  ; jmp to _start of ELF binary

    LEAVE

