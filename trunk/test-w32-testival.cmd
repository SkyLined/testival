@ECHO OFF

ECHO     + Testing w32-testival.exe:

IF NOT EXIST "writeconsole-shellcode\w32-writeconsole-shellcode.bin" (
  ECHO       * Cannot find w32-writeconsole-shellcode.bin for testing.
  EXIT /B 0
)

ECHO       + JMP to EIP
w32-testival.exe [$]=ascii:writeconsole-shellcode\w32-writeconsole-shellcode.bin eip=$ --EH 2>&1 | match_output "Hello, world![\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + RET to EIP
w32-testival.exe [$]=ascii:writeconsole-shellcode\w32-writeconsole-shellcode.bin eip=$ --ret --EH 2>&1 | match_output "Hello, world![\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + Set ESP and ret-into-libc
w32-testival.exe [$+800]=value:$+804 [$+804]=ascii:writeconsole-shellcode\w32-writeconsole-shellcode.bin esp=$+800 --ret --EH 2>&1 | match_output "Hello, world![\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + Set ESP and JMP to RIP
w32-testival.exe [$+800]=ascii:writeconsole-shellcode\w32-writeconsole-shellcode.bin esp=$+800 eip=$+800 --EH 2>&1 | match_output "Hello, world![\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + Detect NULL pointer execution AV
w32-testival.exe eip=0 --EH 2>&1 | match_output "Second chance access violation while executing \[0+\]: no memory allocated\.[\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + Load DLL with writeconsole shellcode
w32-testival.exe --loadlibrary writeconsole-shellcode\w32-writeconsole-shellcode.dll 2>&1 | match_output "Hello, world![\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

EXIT /B %ERRORLEVEL%

:FAILED
  ECHO     * Test failed!
  EXIT /B %ERRORLEVEL%