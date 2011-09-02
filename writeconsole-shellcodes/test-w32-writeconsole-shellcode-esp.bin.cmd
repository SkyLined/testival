@ECHO OFF

ECHO     + Checking shellcode for NULL bytes:

ECHO       + w32-writeconsole-shellcode-esp.bin
CALL BETA3.cmd h --nullfree w32-writeconsole-shellcode-esp.bin > nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO     + Running shellcode with unalligned ESP:
ECHO       + w32-writeconsole-shellcode-esp.bin
w32-testival.exe [$+800]=ascii:w32-writeconsole-shellcode-esp.bin eip=$+800 esp=$+7FF --EH 2>&1 | CALL match_output.cmd "^Hello, world![\r\n]*$" --verbose > nul
IF ERRORLEVEL 1 GOTO :FAILED

EXIT /B %ERRORLEVEL%

:FAILED
  ECHO     * Test failed!
  EXIT /B %ERRORLEVEL%