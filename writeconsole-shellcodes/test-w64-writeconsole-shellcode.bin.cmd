@ECHO OFF

ECHO     + Testing w64-writeconsole-shellcode.bin:

IF "%PROCESSOR_ARCHITECTURE%"=="x86" (
  ECHO       * Cannot test w64-testival.exe on x86 platform.
  EXIT /B 0
)

ECHO       + Checking w64-writeconsole-shellcode.bin for NULL bytes...
BETA3 h --nullfree w64-writeconsole-shellcode.bin > nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + Running w32-writeconsole-shellcode.bin...
w64-testival.exe [$]=ascii:w64-writeconsole-shellcode.bin rip=$ --EH 2>&1 | match_output "^Hello, world![\r\n]*$" --verbose > nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO       + Running w32-writeconsole-shellcode.bin with unalligned RSP...
w64-testival.exe [$+800]=ascii:w64-writeconsole-shellcode.bin rip=$+800 rsp=$+7FF --EH 2>&1 | match_output "^Hello, world![\r\n]*$" --verbose > nul
IF ERRORLEVEL 1 GOTO :FAILED
  
EXIT /B %ERRORLEVEL%

:FAILED
  ECHO     * Test failed!
  EXIT /B %ERRORLEVEL%