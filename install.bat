@echo off
title HTTP Proxy Logger - Install
echo ==========================================
echo   HTTP Proxy Logger - Install
echo ==========================================
echo.

:: Check Python
where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo         Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version 2^>^&1') do echo [OK] %%i

:: Check OpenSSL
where openssl >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [WARN] OpenSSL not found - MITM HTTPS inspection will be disabled.
    echo         Install from: https://slproweb.com/products/Win32OpenSSL.html
) else (
    for /f "tokens=*" %%i in ('openssl version 2^>^&1') do echo [OK] %%i
)

:: Create config
if not exist config.json (
    echo [INFO] Creating config.json from example...
    copy config.example.json config.json >nul
    echo [OK] Config created: config.json
) else (
    echo [OK] Config exists: config.json
)

:: Create directories
if not exist logs mkdir logs
if not exist certs mkdir certs
echo [OK] Directories: logs\ certs\

echo.
echo ==========================================
echo   Installation complete!
echo   Run start.bat to launch the proxy.
echo ==========================================
echo.
pause
