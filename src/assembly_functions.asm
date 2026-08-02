section .bss
section .data
section .text

global transfer_control

; this function follows the ABI convention
; we expect the following parameters in the following order: entry_point, -
; we return the following: -
transfer_control:
    push    rbp
    mov     rbp, rsp
    and     rsp, -16        ; align the stack to multiple of 16

    call rdi

    .exit:
        mov     rsp, rbp
        pop     rbp
        ret
