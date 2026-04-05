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

:: Generate CA cert if not exists
if not exist certs\ca.crt (
    echo [INFO] Generating CA certificate...
    python -c "from proxy_logger.cert_manager import CertManager; CertManager(ca_dir='certs')"
    echo [OK] CA certificate generated: certs\ca.crt
) else (
    echo [OK] CA certificate exists: certs\ca.crt
)

:: Install CA cert to Windows trust store
echo.
echo ==========================================
echo   Install CA Certificate
echo ==========================================
echo.
echo   De HTTPS inspection hoat dong, ban can cai
echo   CA certificate vao Windows trust store.
echo.

set /p INSTALL_CERT="Ban co muon cai CA cert khong? (Y/N): "
if /I "%INSTALL_CERT%"=="Y" (
    echo [INFO] Cai dat CA certificate vao Windows...
    echo        (Can quyen Administrator - UAC se hien len)
    certutil -addstore -user Root "certs\ca.crt"
    if %ERRORLEVEL% equ 0 (
        echo [OK] CA certificate da duoc cai dat thanh cong!
        echo     Chrome/Edge se tu dong tin tuong cert nay.
    ) else (
        echo [WARN] Khong the cai tu dong. Thu cach thu cong:
        echo        1. Mo file: certs\ca.crt
        echo        2. Click "Install Certificate"
        echo        3. Chon "Current User"
        echo        4. Chon "Place all certificates in the following store"
        echo        5. Browse -^> chon "Trusted Root Certification Authorities"
        echo        6. Click Finish
    )
) else (
    echo [SKIP] Bo qua cai dat cert.
    echo.
    echo   De cai thu cong sau:
    echo     1. Mo file: certs\ca.crt
    echo     2. Click "Install Certificate"
    echo     3. Chon "Current User"
    echo     4. Chon "Place all certificates in the following store"
    echo     5. Browse -^> chon "Trusted Root Certification Authorities"
    echo     6. Click Finish
)

echo.
echo ==========================================
echo   Installation complete!
echo   Run start.bat to launch the proxy.
echo.
echo   Proxy:     http://localhost:8080
echo   Dashboard: http://localhost:8081
echo ==========================================
echo.
pause
