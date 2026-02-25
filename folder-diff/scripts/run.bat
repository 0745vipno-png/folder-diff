@echo off
setlocal EnableExtensions
chcp 65001 >nul

REM Usage:
REM   run.bat --a ".\outA\snapshot_20260225_101010.json" ^
REM           --b ".\outB\snapshot_20260226_101010.json" ^
REM           --out ".\diff_out"

python "%~dp0diff.py" %*
set "ec=%ERRORLEVEL%"
echo.
echo ExitCode=%ec%
exit /b %ec%