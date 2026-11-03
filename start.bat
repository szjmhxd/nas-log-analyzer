@echo off
chcp 65001 >nul 2>&1
setlocal
title NAS Log Analyzer
cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 goto nopython

echo Starting NAS Log Analyzer ...
echo.
python tool\server.py
set RC=%ERRORLEVEL%
if not "%RC%"=="0" (
  echo.
  echo [ERROR] Server exited with code %RC%.
  pause
)
goto :eof

:nopython
echo.
echo [ERROR] Python not found in PATH.
echo Install Python 3.8+ and make sure "python" works in cmd.
echo.
pause
