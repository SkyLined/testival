@ECHO OFF

IF NOT EXIST "..\w64-testival.exe" (
  ECHO     - Skipped testing w64-writeconsole-shellcode.dll: w64-testival not found.
  EXIT /B 0
)

ECHO     + Testing w64-writeconsole-shellcode.dll:

IF "%PROCESSOR_ARCHITECTURE%"=="x86" (
  ECHO       * Cannot test w64-writeconsole-shellcode.dll on x86 platform.
  EXIT /B 0
)

..\w64-testival.exe --loadlibrary %CD%\w64-writeconsole-shellcode.dll | CALL match_output.cmd "^Hello, world![\r\n]*$" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

EXIT /B %ERRORLEVEL%

:FAILED
  ECHO     * Test failed!
  EXIT /B %ERRORLEVEL%