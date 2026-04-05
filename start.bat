@echo off
title HTTP Proxy Logger
echo ==========================================
echo   HTTP Proxy Logger
echo ==========================================
echo.

:: Check Python
where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python not found. Run install.bat first.
    pause
    exit /b 1
)

:: Check config
if not exist config.json (
    echo [INFO] Config not found. Running install first...
    call install.bat
)

echo   Proxy:     http://localhost:8080
echo   Dashboard: http://localhost:8081
echo   Logs:      .\logs\proxy.log
echo.
echo   Press Ctrl+C to stop
echo ==========================================
echo.

python main.py --config config.json %*
pause
