@echo off
title Install Proxy CA Certificate
echo ==========================================
echo   Install CA Certificate
echo ==========================================
echo.

if not exist certs\ca.crt (
    echo [INFO] Generating CA certificate first...
    python -c "from proxy_logger.cert_manager import CertManager; CertManager(ca_dir='certs')"
)

if not exist certs\ca.crt (
    echo [ERROR] CA certificate not found. Run install.bat first.
    pause
    exit /b 1
)

echo Cai dat CA certificate vao Windows trust store...
echo (Chrome/Edge se tu dong tin tuong cert sau khi cai)
echo.

certutil -addstore -user Root "certs\ca.crt"

if %ERRORLEVEL% equ 0 (
    echo.
    echo ==========================================
    echo   [OK] CA certificate da cai thanh cong!
    echo.
    echo   Luu y:
    echo   - Chrome/Edge: hoat dong ngay, khong can restart
    echo   - Firefox: can cai rieng (xem ben duoi)
    echo ==========================================
    echo.
    echo   Firefox (neu dung):
    echo     1. Mo Firefox, vao Settings
    echo     2. Tim "Certificates" -^> View Certificates
    echo     3. Tab "Authorities" -^> Import
    echo     4. Chon file: certs\ca.crt
    echo     5. Tick "Trust this CA to identify websites"
    echo.
) else (
    echo.
    echo [ERROR] Cai dat that bai. Thu cach thu cong:
    echo   1. Double-click file: certs\ca.crt
    echo   2. Click "Install Certificate"
    echo   3. Chon "Current User" -^> Next
    echo   4. Chon "Place all certificates in the following store"
    echo   5. Browse -^> "Trusted Root Certification Authorities"
    echo   6. Next -^> Finish
    echo.
)

pause
