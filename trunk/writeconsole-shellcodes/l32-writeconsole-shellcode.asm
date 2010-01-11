BITS 32
SECTION .text

%define message `Hello, world!\n`
%strlen sizeof_message message

global shellcode
shellcode:
global _shellcode
_shellcode:
%ifdef STACK_ALIGN
    AND     SP, 0xFFFC
%endif

    PUSH    BYTE 0x4                    ;
    POP     EAX                         ; EAX = 0x4 (write)
    PUSH    BYTE 0x1                    ;
    POP     EBX                         ; EBX = 0x1 (stdout)
    JMP     SHORT PUSH_pmessage         ;
pmessage_PUSHED:                        ;
    POP     ECX                         ; ECX = &message
    PUSH    BYTE sizeof_message         ;
    POP     EDX                         ; EDX = strlen(message)
    INT     0x80                        ; write(stdout, &message, strlen(message))

    PUSH    BYTE 0x1                    ;
    POP     EAX                         ; EAX = 0x1 (exit)
    INT     0x80                        ; exit([random exit code])
    
PUSH_pmessage:
    CALL pmessage_PUSHED
    db message
