@echo off
setlocal enabledelayedexpansion

echo ========================================
echo   Smart Proxy - Management Console
echo ========================================
echo.

:MENU
echo Choose an option:
echo.
echo 1. Start Smart Proxy (Port 8080)
echo 2. Start Web Interface (Port 5000)
echo 3. Start Both Services
echo 4. Stop All Services
echo 5. Check Service Status
echo 6. Install mitmproxy Certificate
echo 7. Test Certificate Installation
echo 8. View Proxy Logs
echo 9. Open Grafana Dashboard
echo 0. Exit
echo.

set /p choice="Enter your choice (0-9): "

if "%choice%"=="1" goto START_PROXY
if "%choice%"=="2" goto START_WEB
if "%choice%"=="3" goto START_BOTH
if "%choice%"=="4" goto STOP_ALL
if "%choice%"=="5" goto CHECK_STATUS
if "%choice%"=="6" goto INSTALL_CERT
if "%choice%"=="7" goto TEST_CERT
if "%choice%"=="8" goto VIEW_LOGS
if "%choice%"=="9" goto OPEN_GRAFANA
if "%choice%"=="0" goto EXIT

echo Invalid choice. Please try again.
echo.
goto MENU

:START_PROXY
echo.
echo Starting Smart Proxy on port 8080...
echo.
start "Smart Proxy" cmd /k "mitmdump -s main.py --listen-port 8080"
echo Smart Proxy started in new window.
echo Configure your browser to use proxy: 127.0.0.1:8080
echo.
pause
goto MENU

:START_WEB
echo.
echo Starting Web Interface on port 5000...
echo.
start "Web Interface" cmd /k "python scanner_app.py"
echo Web Interface started in new window.
echo Access at: http://127.0.0.1:5000
echo.
pause
goto MENU

:START_BOTH
echo.
echo Starting both Smart Proxy and Web Interface...
echo.
start "Smart Proxy" cmd /k "mitmdump -s main.py --listen-port 8080"
timeout /t 3 /nobreak > nul
start "Web Interface" cmd /k "python scanner_app.py"
echo.
echo Both services started!
echo   Smart Proxy: 127.0.0.1:8080
echo   Web Interface: http://127.0.0.1:5000
echo.
pause
goto MENU

:STOP_ALL
echo.
echo Stopping all Smart Proxy services...
echo.
taskkill /f /im mitmdump.exe 2>nul
taskkill /f /im python.exe /fi "WINDOWTITLE eq Web Interface*" 2>nul
echo Services stopped.
echo.
pause
goto MENU

:CHECK_STATUS
echo.
echo Checking service status...
echo.

echo Smart Proxy (mitmdump):
tasklist /fi "imagename eq mitmdump.exe" 2>nul | find /i "mitmdump.exe" >nul
if %ERRORLEVEL% EQU 0 (
    echo   Status: RUNNING
    netstat -an | find ":8080" >nul
    if %ERRORLEVEL% EQU 0 (
        echo   Port 8080: LISTENING
    ) else (
        echo   Port 8080: NOT LISTENING
    )
) else (
    echo   Status: NOT RUNNING
)

echo.
echo Web Interface (Python):
netstat -an | find ":5000" >nul
if %ERRORLEVEL% EQU 0 (
    echo   Status: RUNNING on port 5000
) else (
    echo   Status: NOT RUNNING
)

echo.
echo Grafana Dashboard:
netstat -an | find ":3000" >nul
if %ERRORLEVEL% EQU 0 (
    echo   Status: RUNNING on port 3000
) else (
    echo   Status: NOT RUNNING
)

echo.
pause
goto MENU

:INSTALL_CERT
echo.
echo Installing mitmproxy certificate...
echo.
call install_mitmproxy_certificate.bat
goto MENU

:TEST_CERT
echo.
echo Testing certificate installation...
echo.
set CERT_DIR=%USERPROFILE%\.mitmproxy
set CERT_FILE=%CERT_DIR%\mitmproxy-ca-cert.cer

if exist "%CERT_FILE%" (
    echo Certificate file found: %CERT_FILE%
    
    echo Checking if certificate is installed in Windows store...
    certlm -store "Root" | find "mitmproxy" >nul
    if %ERRORLEVEL% EQU 0 (
        echo   Certificate is INSTALLED in Windows Certificate Store
    ) else (
        echo   Certificate is NOT INSTALLED in Windows Certificate Store
        echo   Run option 6 to install the certificate
    )
) else (
    echo Certificate file NOT FOUND
    echo Start the proxy first to generate certificates
)

echo.
pause
goto MENU

:VIEW_LOGS
echo.
echo Opening logs directory...
echo.
if exist "logs" (
    start explorer "logs"
    echo Logs directory opened in Explorer
) else (
    echo Logs directory not found. Generate some data first.
)
echo.
pause
goto MENU

:OPEN_GRAFANA
echo.
echo Opening Grafana Dashboard...
echo.
start http://localhost:3000
echo Grafana opened in browser
echo Login: admin / admin123
echo.
pause
goto MENU

:EXIT
echo.
echo Goodbye!
exit /b 0
