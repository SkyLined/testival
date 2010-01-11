@ECHO OFF

ECHO     + Testing w64-testival.exe:

IF "%PROCESSOR_ARCHITECTURE%"=="x86" (
  ECHO       * Cannot test w64-testival.exe on x86 platform.
  EXIT /B 0
) ELSE IF NOT EXIST "writeconsole-shellcode\w64-writeconsole-shellcode.bin" (
  ECHO       * Cannot find w64-writeconsole-shellcode.bin for testing...
  EXIT /B 0
)

ECHO       + JMP to RIP
w64-testival.exe [$]=ascii:writeconsole-shellcode\w64-writeconsole-shellcode.bin rip=$ --EH 2>&1 | match_output "Hello, world![\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + RET to RIP
w64-testival.exe [$]=ascii:writeconsole-shellcode\w64-writeconsole-shellcode.bin rip=$ --ret --EH 2>&1 | match_output "Hello, world![\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + Set RSP and ret-into-libc
w64-testival.exe [$+800]=value:$+808 [$+808]=ascii:writeconsole-shellcode\w64-writeconsole-shellcode.bin rsp=$+800 --ret --EH 2>&1 | match_output "Hello, world![\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + Set RSP and JMP to RIP
w64-testival.exe [$+800]=ascii:writeconsole-shellcode\w64-writeconsole-shellcode.bin rsp=$+800 rip=$+800 --EH 2>&1 | match_output "Hello, world![\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + Detect NULL pointer execution AV
w64-testival.exe rip=0 --EH 2>&1 | match_output "Second chance access violation while executing \[0+\]: no memory allocated\.[\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + Load DLL with writeconsole shellcode
w64-testival.exe --loadlibrary writeconsole-shellcode\w64-writeconsole-shellcode.dll 2>&1 | match_output "Hello, world![\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

EXIT /B %ERRORLEVEL%

:FAILED
  ECHO     * Test failed!
  EXIT /B %ERRORLEVEL%