; Copyright (c) 2006-2010, Berend-Jan "SkyLined" Wever <berendjanwever@gmail.com>
; Project homepage: http://code.google.com/p/testival/
; All rights reserved. See COPYRIGHT.txt for details.
BITS 64
SECTION .text

; Windows x64 null-free shellcode that writes "Hello, world!" to stdout.
; Works in any console application for Windows 5.1-7.0 all service packs.
; (See http://skypher.com/wiki/index.php/Hacking/Shellcode).
; This version uses 16-bit hashes.

%define message `Hello, world!\r\n`
%strlen sizeof_message message

%include "w64-writeconsole-shellcode-hash-list.asm"

%define B2W(b1,b2)                      (((b2) << 8) + (b1))
%define W2DW(w1,w2)                     (((w2) << 16) + (w1))
%define W2QW(w1,w2,w3,w4)               (((w4) << 48) + ((w3) << 32) + ((w2) << 16) + (w1))
%define B2DW(b1,b2,b3,b4)               (((b4) << 24) + ((b3) << 16) + ((b2) << 8) + (b1))
%define B2DQ(b1,b2,b3,b4,b5,b6,b7,b8)   (((b8) << 56) + ((b7) << 48) + ((b6) << 40) + ((b5) << 32) + ((b4) << 24) + ((b3) << 16) + ((b2) << 8) + (b1))
%define DW2QW(dw1,dw2)                  (((dw2) << 32) + (dw1))

%macro PUSHDW 1
  %if %1 > 0x7FFFFFFF
    PUSH    -(0x100000000 - %1)
  %else
    PUSH    %1
  %endif
%endmacro

global shellcode
shellcode:
global _shellcode
_shellcode:
    MOV     R12, W2QW(hash_kernel32_GetStdHandle, hash_kernel32_WriteFile, hash_kernel32_FlushFileBuffers, hash_ntdll_RtlExitUserProcess);
    MOV     RSI, RSP
    PUSH    BYTE -11                    ; GetStdHandle(nStdHandle) = STD_OUTPUT_HANDLE
    POP     R13                         ; R13 = argument1 == STD_OUTPUT_HANDLE
    PUSH    RAX                         ; argument2 == garbage
next_hash:
    PUSH    BYTE 0x60                   ; [ESP] = 0x60
    POP     RAX                         ; RCX = 0x60
; Find base address of kernel32.dll. This code should work on Windows 5.1-7.0
; Base on http://milw0rm.com/shellcode/2126 by Kevin Devine <wyse101@gmail.com>
    MOV     R11, [GS:RAX]               ; R11 = &(PEB) ([GS:0x60])
    MOV     R11, [R11+0x18]             ; R11 = ntdll!PebLdr
    MOV     R11, [R11+0x30]             ; R11 = ntdll!PebLdr.InInitOrder (first module)
next_module:
    MOV     RBP, [R11 + 0x10]           ; RBP = InInitOrder[X].base_address
    MOV     R11, [R11]                  ; R11 = InInitOrder[X].flink == InInitOrder[X+1]

get_proc_address_loop:
; Find the PE header and export and names tables of the module:
    MOV     EAX, [RBP + 0x3C]           ; RAX = offset PE header
    ADD     EAX, BYTE 0x10              ; export table is at offset 0x88, which does not fit an unsigned byte.
    MOV     EAX, [RBP + RAX + 0x78]     ; RAX = offset(export table)
%define extra_offset 0x18
    LEA     RBX, [RBP + RAX + extra_offset] ; RBX = &(export table) + extra_offset (Avoid NULL)
; Hash each function name and check it against the requested hash:
    MOV     EAX, [RBX - extra_offset + 0x18] ; ECX = number of name pointers
    MOV     RCX, RAX                    ; RCX = number of exported functions
next_function_loop:
; Get the next function name:
    MOV     EAX, [RBX - extra_offset + 0x20] ; RAX = offset(names table)
    LEA     RDI, [RBP + RAX - 4]        ; RDI = &(names table) - 4 (Avoid NULL)
    MOV     EAX, [RDI + RCX * 4]        ; RAX = offset(function name)
    ADD     RAX, RBP                    ; RAX = &(function name)
    XOR     RDI, RDI                    ; RDI = 0
    XCHG    RAX, RDI                    ; RAX = 0, RDI = &(function name)
    CQO                                 ; RDX = 0
hash_loop:
    XOR     DL, [RDI]                   ; DX ^= name byte
    ROR     DX, hash_ror_value          ; Rotate DX for hash function
    SCASB                               ; [RDI++] == 0 ?
    JNE     hash_loop                   ; Not 0, more chars in string...
    CMP     DX, R12W                    ; hash == target hash ?
    LOOPNE  next_function_loop          ; No, try next function if there is one.
    JNE     next_module                 ; Try next module
; Find the address of the requested function:
    MOV     EAX, [RBX - extra_offset + 0x24] ; RAX = offset ordinals table
    LEA     RDX, [RBP + RAX + extra_offset] ; RDX = &oridinals table + extra_offset (Avoid NULL)
    MOVZX   RDX, WORD [RDX - extra_offset + 2 * RCX] ; RCX = ordinal number of function
    MOV     EAX, [RBX - extra_offset + 0x1C]    ; RAX = offset address table
    LEA     RCX, [RBP + RAX + extra_offset] ; RCX = &address table + extra_offset (Avoid NULL)
    MOV     EAX, [RCX - extra_offset + 4 * RDX] ; RAX = offset function in DLL
    ADD     RAX, RBP                    ; RAX = &(function)
    ; Second argument (Garbage, &message, &message)
    POP     RDX                         ; __in         LPCVOID lpBuffer = message
    ; First argument: (STD_OUTPUT_HANDLE, GetStdHandle(STD_OUTPUT_HANDLE), WriteFile(...) (!= 0))
    MOV     RCX, R13
    ; GetStdHandle(): __in  DWORD nStdHandle = STD_OUTPUT_HANDLE
    ; WriteConsole(): __in  HANDLE hFile = GetStdHandle(STD_OUTPUT_HANDLE)
    ; ExitProcess():  __in  UINT uExitCode = WriteFile(...) (!= 0)
    PUSH    BYTE sizeof_message         ; __in         DWORD nNumberOfBytesToWrite = strlen(message)
    POP     R8
    MOV     R9,RSP                      ; __out_opt    LPDWORD lpNumberOfBytesWritten = Stack
    XOR     R10,R10                     ; 
;   PUSH    R10                         ; Stack align to 16 bytes (does not seem to be required
    PUSH    R10                         ; __inout_opt  LPOVERLAPPED lpOverlapped = NULL
    SUB     RSP, BYTE 0x20              ; 4 * 8 "Register Parameter Stack"
    CALL    RAX
    CMP     R12W, hash_kernel32_GetStdHandle ;
    JNE     do_not_save_handle
    MOV     R13, RAX
do_not_save_handle:
    SHR     R12, BYTE 0x10              ; Next hash
    CALL    next_hash
    db      message
