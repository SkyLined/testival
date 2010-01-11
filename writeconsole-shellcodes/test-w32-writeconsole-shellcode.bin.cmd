@ECHO OFF

ECHO     + Checking shellcode for NULL bytes:

ECHO       + w32-writeconsole-shellcode.bin
BETA3 h --nullfree w32-writeconsole-shellcode.bin > nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO     + Running shellcode:
ECHO       + w32-writeconsole-shellcode.bin
w32-testival [$]=ascii:w32-writeconsole-shellcode.bin eip=$ --EH 2>&1 | match_output "^Hello, world![\r\n]*$" --verbose > nul
IF ERRORLEVEL 1 GOTO :FAILED

EXIT /B %ERRORLEVEL%

:FAILED
  ECHO     * Test failed!
  EXIT /B %ERRORLEVEL%