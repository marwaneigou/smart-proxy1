@echo off
echo ========================================
echo   Smart Proxy - Certificate Installation
echo ========================================
echo.

echo Checking for mitmproxy certificates...
set CERT_DIR=%USERPROFILE%\.mitmproxy
set CERT_FILE=%CERT_DIR%\mitmproxy-ca-cert.cer

if not exist "%CERT_DIR%" (
    echo ERROR: mitmproxy certificate directory not found!
    echo Please start the proxy first to generate certificates.
    echo Run: mitmdump -s main.py --listen-port 8080
    pause
    exit /b 1
)

if not exist "%CERT_FILE%" (
    echo ERROR: mitmproxy certificate file not found!
    echo Expected location: %CERT_FILE%
    pause
    exit /b 1
)

echo Found certificate: %CERT_FILE%
echo.

echo Installing mitmproxy certificate to Windows Certificate Store...
echo This will allow HTTPS interception without certificate warnings.
echo.

echo Installing to Trusted Root Certification Authorities...
certlm -addstore "Root" "%CERT_FILE%"

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo   Certificate Installation Successful!
    echo ========================================
    echo.
    echo The mitmproxy certificate has been installed.
    echo You can now use the proxy without certificate warnings.
    echo.
    echo Proxy Configuration:
    echo   HTTP Proxy: 127.0.0.1:8080
    echo   HTTPS Proxy: 127.0.0.1:8080
    echo.
    echo To configure your browser:
    echo   1. Go to browser proxy settings
    echo   2. Set HTTP proxy to 127.0.0.1:8080
    echo   3. Set HTTPS proxy to 127.0.0.1:8080
    echo   4. Save settings and restart browser
    echo.
) else (
    echo.
    echo ========================================
    echo   Certificate Installation Failed!
    echo ========================================
    echo.
    echo Error code: %ERRORLEVEL%
    echo.
    echo Possible solutions:
    echo   1. Run this script as Administrator
    echo   2. Check if the certificate file exists
    echo   3. Try manual installation:
    echo      - Double-click: %CERT_FILE%
    echo      - Choose "Install Certificate"
    echo      - Select "Local Machine"
    echo      - Choose "Trusted Root Certification Authorities"
    echo.
)

echo.
echo Certificate file location: %CERT_FILE%
echo.
pause
