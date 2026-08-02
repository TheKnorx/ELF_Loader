section .bss
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
    mov     r9, rdi     ; save s[.n] into r9 for later use
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
    mov     rax, r9     ; move r9/s[.n] into rax for returning
    ret

; function for creating the initial user stack
; we expect the following parameters in the following order: stack_addr, argc, argv,
create_initial_user_stack:


; this function follows the ABI convention
; we expect the following parameters in the following order: entry_point, -
; we return the following: -
global transfer_control
transfer_control:
    ENTER

    call rdi

    LEAVE

