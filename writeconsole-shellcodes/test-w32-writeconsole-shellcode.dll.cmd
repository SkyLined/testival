@ECHO OFF

IF NOT EXIST "..\w32-testival.exe" (
  ECHO     - Skipped testing w32-writeconsole-shellcode.dll: w32-testival not found.
  EXIT /B 0
)
ECHO     + Testing w32-writeconsole-shellcode.dll:
..\w32-testival.exe --loadlibrary %CD%\w32-writeconsole-shellcode.dll 2>&1 | CALL CALL match_output.cmd "^Hello, world![\r\n]*$" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

EXIT /B %ERRORLEVEL%

:FAILED
  ECHO     * Test failed!
  EXIT /B %ERRORLEVEL%