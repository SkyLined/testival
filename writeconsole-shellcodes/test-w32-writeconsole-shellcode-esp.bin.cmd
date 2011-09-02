@ECHO OFF

IF NOT EXIST "..\w32-testival.exe" (
  ECHO     - Skipped testing w32-writeconsole-shellcode-esp.bin: w64-testival not found.
  EXIT /B 0
)
ECHO     + Checking shellcode for NULL bytes:

ECHO       + w32-writeconsole-shellcode-esp.bin
CALL BETA3.cmd h --nullfree w32-writeconsole-shellcode-esp.bin > nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO     + Running shellcode with unalligned ESP:
ECHO       + w32-writeconsole-shellcode-esp.bin
..\w32-testival.exe a[$+2000]=w32-writeconsole-shellcode-esp.bin eip=$+2000 esp=$+1FFB --EH --mem:size=4000 2>&1 | CALL match_output.cmd "^Hello, world![\r\n]*$" --verbose > nul
IF ERRORLEVEL 1 GOTO :FAILED

EXIT /B %ERRORLEVEL%

:FAILED
  ECHO     * Test failed!
  EXIT /B %ERRORLEVEL%