BITS 32

SECTION .text

%define arg1 DWORD [ESP+0x04]
%define arg2 DWORD [ESP+0x08]
%define arg3 DWORD [ESP+0x0C]
%define arg4 DWORD [ESP+0x10]
%define arg5 DWORD [ESP+0x14]
%define return EAX

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

; struct registers = { EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI, EIP }
%define registers arg1
%define register_size 4
%define register(x) [registers + x * register_size]
%define register_esp register(4)
%define register_eip register(8)
%define do_int3 arg2
%define do_ret  arg3
%define set_esp arg4
%define set_eip arg5
%define temp_eip [FS:0x800]             ; Use unused bytes in the TEB to temporarily store EIP

global _asm_SetRegisters
_asm_SetRegisters:
    MOV     ECX, registers
%define registers ECX
    CMP     set_esp, 0
    JNE     no_get_esp
    MOV     register_esp, ESP
no_get_esp:
    ; Setup RFLAGS such that CF = do_int3, PF = do_ret, ZF = set_eip
    PUSHFD
    POP     EAX
    BTR     EAX, flag_CF
    CMP     do_int3, 0
    JE      CF_0
    BTS     EAX, flag_CF
CF_0:
    BTR     EAX, flag_PF
    CMP     do_ret, 0
    JE      PF_0
    BTS     EAX, flag_PF
PF_0:
    BTR     EAX, flag_ZF
    CMP     set_eip, 0
    JE      ZF_0
    BTS     EAX, flag_ZF
ZF_0:
    PUSH    EAX
    POPFD
    ; Save RIP for later use (it is used after we set all other registers and lose the pointer to the registers structure
    PUSH    DWORD register_eip
    POP     DWORD temp_eip
    MOV     ESP, registers              ; ESP = struct registers
    POP     EAX                         ; EAX = registers.EAX
    POP     ECX                         ; ECX = registers.ECX
    POP     EDX                         ; EDX = registers.EDX
    POP     EBX                         ; EBX = registers.EBX
    POP     EDI                         ; EDI = registers.ESP
    POP     EBP                         ; EBP = registers.EBP
    POP     ESI                         ; ESI = registers.ESI
    XCHG    EDI, [ESP]                  ; EDI = registers.EDI, [registers.EDI] = registers.ESP
    POP     ESP                         ; ESP = registers.EDI == registers.ESP

    JP      use_ret

use_jmp:
    JNC     no_int3_jmp
    INT3
no_int3_jmp:
    JMP     temp_eip                    ; RIP = temp_eip

use_ret:
    JNZ     no_set_rip
    PUSH    DWORD temp_eip              ; [RSP] = temp_eip
no_set_rip:
    JNC     no_int3_ret
    INT3
no_int3_ret:
    RET                                 ; EIP = [RSP]
