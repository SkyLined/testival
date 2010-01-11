@ECHO OFF

ECHO     + Testing w32-writeconsole-shellcode.dll:

w32-testival.exe --loadlibrary w32-writeconsole-shellcode.dll 2>&1 | match_output "^Hello, world![\r\n]*$" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

EXIT /B %ERRORLEVEL%

:FAILED
  ECHO     * Test failed!
  EXIT /B %ERRORLEVEL%