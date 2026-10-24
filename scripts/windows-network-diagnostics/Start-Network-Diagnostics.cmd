@echo off
setlocal
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Collect-WindowsNetworkTrace.ps1"
set "trace_exit=%ERRORLEVEL%"
echo.
if not "%trace_exit%"=="0" echo Die Diagnose meldet einen Fehler. Bitte den Fehlertext und die erzeugte Diagnose-ZIP senden.
pause
exit /b %trace_exit%
