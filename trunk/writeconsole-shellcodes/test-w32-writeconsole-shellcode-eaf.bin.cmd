@ECHO OFF

ECHO     + Checking shellcode for NULL bytes:

ECHO       + w32-writeconsole-shellcode-eaf.bin
CALL BETA3.cmd h --nullfree w32-writeconsole-shellcode-eaf.bin > nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO     + Running shellcode with timeout to enable EAF:
ECHO       + w32-writeconsole-shellcode-eaf.bin
w32-testival.exe [$]=ascii:w32-writeconsole-shellcode-eaf.bin eip=$ --delay=2000 --EH 2>&1 | CALL match_output.cmd "^Hello, world![\r\n]*$" --verbose > nul
IF ERRORLEVEL 1 GOTO :FAILED

EXIT /B %ERRORLEVEL%

:FAILED
  ECHO     * Test failed!
  EXIT /B %ERRORLEVEL%