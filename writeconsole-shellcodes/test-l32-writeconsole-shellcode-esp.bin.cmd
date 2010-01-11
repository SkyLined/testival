@ECHO OFF

ECHO     + Checking shellcode for NULL bytes:

ECHO       + l32-writeconsole-shellcode-esp.bin
BETA3 h --nullfree l32-writeconsole-shellcode-esp.bin > nul
IF ERRORLEVEL 1 GOTO :FAILED

EXIT /B %ERRORLEVEL%

:FAILED
  ECHO     * Test failed!
  EXIT /B %ERRORLEVEL%