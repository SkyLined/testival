@ECHO OFF

ECHO     + Testing w64-testival.exe:

w64-testival.exe >nul
IF ERRORLEVEL 1 (
  ECHO       * Cannot test w64-testival.exe on x86 platform.
  EXIT /B 0
) ELSE IF NOT EXIST "%CD%\writeconsole-shellcodes\w64-writeconsole-shellcode.bin" (
  ECHO       * Cannot find w64-writeconsole-shellcode.bin for testing...
  EXIT /B 0
)

ECHO       + JMP to RIP
w64-testival.exe a[$]="%CD%\writeconsole-shellcodes\w64-writeconsole-shellcode.bin" rip=$ --EH 2>&1 | CALL match_output.cmd "Hello, world![\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + RET to RIP
w64-testival.exe a[$]="%CD%\writeconsole-shellcodes\w64-writeconsole-shellcode.bin" rip=$ --ret --EH 2>&1 | CALL match_output.cmd "Hello, world![\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + Set RSP and ret-into-libc
w64-testival.exe [$+2000]=$+2008 a[$+2008]="%CD%\writeconsole-shellcodes\w64-writeconsole-shellcode.bin" rsp=$+2000 --ret --EH --mem:size=4000 2>&1 | CALL match_output.cmd "Hello, world![\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + Set RSP and JMP to RIP
w64-testival.exe a[$+2008]="%CD%\writeconsole-shellcodes\w64-writeconsole-shellcode.bin" rsp=$+2000 rip=$+2008 --EH --mem:size=4000 2>&1 | CALL match_output.cmd "Hello, world![\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + Detect NULL pointer execution AV
w64-testival.exe rip=0 --EH 2>&1 | CALL match_output.cmd "Second chance access violation while executing \[0x0000000000000000\]: no memory allocated\.[\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + Load DLL with writeconsole shellcode
w64-testival.exe --loadlibrary "%CD%\writeconsole-shellcodes\w64-writeconsole-shellcode.dll" 2>&1 | CALL match_output.cmd "Hello, world![\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

EXIT /B %ERRORLEVEL%

:FAILED
  ECHO     * Test failed!
  EXIT /B %ERRORLEVEL%