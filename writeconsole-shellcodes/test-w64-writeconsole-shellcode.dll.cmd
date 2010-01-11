@ECHO OFF

ECHO     + Testing w64-writeconsole-shellcode.dll:

IF "%PROCESSOR_ARCHITECTURE%"=="x86" (
  ECHO       * Cannot test w64-writeconsole-shellcode.dll on x86 platform.
  EXIT /B 0
)

w64-testival.exe --loadlibrary w64-writeconsole-shellcode.dll | match_output "^Hello, world![\r\n]*$" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

EXIT /B %ERRORLEVEL%

:FAILED
  ECHO     * Test failed!
  EXIT /B %ERRORLEVEL%