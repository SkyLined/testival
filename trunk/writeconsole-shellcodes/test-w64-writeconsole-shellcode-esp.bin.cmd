@ECHO OFF

IF NOT EXIST "..\w64-testival.exe" (
  ECHO     - Skipped testing w64-writeconsole-shellcode-esp.bin: w64-testival not found.
  EXIT /B 0
)
ECHO     + Testing w64-writeconsole-shellcode-esp.bin:

..\w64-testival.exe > nul
IF ERRORLEVEL 1 (
  ECHO       * Cannot test w64-writeconsole-shellcode-esp.bin on x86 platform.
  EXIT /B 0
)

ECHO       + Checking w64-writeconsole-shellcode-esp.bin for NULL bytes...
CALL BETA3.cmd h --nullfree w64-writeconsole-shellcode-esp.bin > nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + Running w64-writeconsole-shellcode-esp.bin...
..\w64-testival.exe a[$]=w64-writeconsole-shellcode-esp.bin rip=$ --EH 2>&1 | CALL match_output.cmd "^Hello, world![\r\n]*$" --verbose > nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + Running w64-writeconsole-shellcode-esp.bin with unalligned RSP...
..\w64-testival.exe a[$+2000]=w64-writeconsole-shellcode-esp.bin rip=$+2000 rsp=$+1FFF --EH --mem:size=4000 2>&1 | CALL match_output.cmd "^Hello, world![\r\n]*$" --verbose > nul
IF ERRORLEVEL 1 GOTO :FAILED

EXIT /B %ERRORLEVEL%

:FAILED
  ECHO     * Test failed!
  EXIT /B %ERRORLEVEL%