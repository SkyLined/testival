BITS 64

SECTION .text

%define register_size 8

%define flag_ID   (21)
%define flag_VIP  (20)
%define flag_VIF  (19)
%define flag_AC   (18)
%define flag_VM   (17)
%define flag_RF   (16)
%define flag_NT   (14)
%define flag_IOPL (12) ; and 13
%define flag_OF   (11)
%define flag_DF   (10)
%define flag_IF   (9)
%define flag_TF   (8)
%define flag_SF   (7)
%define flag_ZF   (6)
%define flag_AF   (4)
%define flag_PF   (2)
%define flag_CF   (0)

%define arg1 RCX
%define arg2 RDX
%define arg3 R8
%define arg4 R9
%define arg5 QWORD [RSP + 5 * register_size] ; RET address and 4 * 8 "Register Parameter Stack"
%define return RAX
; struct registers = { RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, RIP }
%define registers arg1
%define register(x) [registers + x * register_size]
%define register_rsp register(0x04)
%define register_rip register(0x10)
%define do_int3 arg2
%define do_ret  arg3
%define set_rsp arg4
%define set_rip arg5
%define temp_rip [GS:0x800]             ; Use unused bytes in the PEB to temporarily store RIP

global asm_SetRegisters
asm_SetRegisters:
    CMP     set_rsp, 0
    JNE     no_get_rsp
    MOV     register_rsp, RSP
no_get_rsp:
    ; Setup RFLAGS such that CF = do_int3, PF = do_ret, ZF = set_rip
    PUSHFQ
    POP     RAX
    BTR     RAX, flag_CF
    CMP     do_int3, 0
    JE      CF_0
    BTS     RAX, flag_CF
CF_0:
    BTR     RAX, flag_PF
    CMP     do_ret, 0
    JE      PF_0
    BTS     RAX, flag_PF
PF_0:
    BTR     RAX, flag_ZF
    CMP     set_rip, 0
    JE      ZF_0
    BTS     RAX, flag_ZF
ZF_0:
    PUSH    RAX
    POPFQ
    ; Save RIP for later use (it is used after we set all other registers and lose the pointer to the registers structure
    PUSH    QWORD register_rip
    POP     QWORD temp_rip
    MOV     RSP, registers              ; RSP = struct registers
    POP     RAX                         ; RAX = registers.RAX
    POP     RCX                         ; RCX = registers.RCX
    POP     RDX                         ; RDX = registers.RDX
    POP     RBX                         ; RBX = registers.RBX
    POP     R15                         ; R15 = registers.RSP
    POP     RBP                         ; RBP = registers.RBP
    POP     RSI                         ; RSI = registers.RSI
    POP     RDI                         ; RDI = registers.RDI

    POP     R8                          ; R8  = registers.R8
    POP     R9                          ; R9  = registers.R9
    POP     R10                         ; R10 = registers.R10
    POP     R11                         ; R11 = registers.R11
    POP     R12                         ; R12 = registers.R12
    POP     R13                         ; R13 = registers.R13
    POP     R14                         ; R14 = registers.R14
    XCHG    R15, [RSP]                  ; R15 = registers.R15, [registers.R15] = registers.RSP
    POP     RSP                         ; RSP = registers.R15 == registers.RSP

    JP      use_ret

use_jmp:
    JNC     no_int3_jmp
    INT3
no_int3_jmp:
    JMP     temp_rip                    ; RIP = temp_eip

use_ret:
    JNZ     no_set_rip
    PUSH    QWORD temp_rip              ; [RSP] = temp_eip
no_set_rip:
    JNC     no_int3_ret
    INT3
no_int3_ret:
    RET                                 ; RIP = [RSP]
