@ECHO OFF

ECHO     + Testing w32-testival.exe:
IF NOT EXIST "%CD%\writeconsole-shellcodes\w32-writeconsole-shellcode.bin" (
  ECHO       * Cannot find w32-writeconsole-shellcode.bin for testing.
  EXIT /B 0
)

ECHO       + JMP to EIP
"%~dp0buildexew32-testival.exe" a[$]="%CD%\writeconsole-shellcodes\w32-writeconsole-shellcode.bin" eip=$ --EH 2>&1 | CALL match_output.cmd "Hello, world![\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + RET to EIP
"%~dp0build\exe\w32-testival.exe" a[$]="%CD%\writeconsole-shellcodes\w32-writeconsole-shellcode.bin" eip=$ --ret --EH 2>&1 | CALL match_output.cmd "Hello, world![\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + Set ESP and ret-into-libc
"%~dp0build\exe\w32-testival.exe" [$+2000]=$+2004 a[$+2004]="%CD%\writeconsole-shellcodes\w32-writeconsole-shellcode.bin" esp=$+2000 --ret --EH --mem:size=4000 2>&1 | CALL match_output.cmd "Hello, world![\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + Set ESP and JMP to RIP
"%~dp0build\exe\w32-testival.exe" a[$+2004]="%CD%\writeconsole-shellcodes\w32-writeconsole-shellcode.bin" esp=$+800 eip=$+2004 --mem:size=4000 --EH 2>&1 | CALL match_output.cmd "Hello, world![\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + Detect NULL pointer execution AV
"%~dp0build\exe\w32-testival.exe" eip=0 --EH 2>&1 | CALL match_output.cmd "Second chance access violation while executing \[0x00000000\]: no memory allocated\.[\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + Load DLL with writeconsole shellcode
"%~dp0build\exe\w32-testival.exe" --loadlibrary "%CD%\writeconsole-shellcodes\w32-writeconsole-shellcode.dll" 2>&1 | CALL match_output.cmd "Hello, world![\r\n]*" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

EXIT /B %ERRORLEVEL%

:FAILED
  ECHO     * Test failed!
  EXIT /B %ERRORLEVEL%