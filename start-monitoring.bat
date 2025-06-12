@echo off
echo ========================================
echo   Smart Proxy Monitoring Stack Setup
echo ========================================
echo.

echo Creating necessary directories...
if not exist "logs" mkdir logs
if not exist "grafana\provisioning\datasources" mkdir grafana\provisioning\datasources
if not exist "grafana\provisioning\dashboards" mkdir grafana\provisioning\dashboards
if not exist "grafana\dashboards" mkdir grafana\dashboards
if not exist "loki" mkdir loki
if not exist "prometheus" mkdir prometheus
if not exist "promtail" mkdir promtail

echo.
echo Starting monitoring stack with Docker Compose...
docker-compose up -d

echo.
echo Waiting for services to start...
timeout /t 30 /nobreak > nul

echo.
echo ========================================
echo   Monitoring Stack Started Successfully!
echo ========================================
echo.
echo Access URLs:
echo   Grafana Dashboard: http://localhost:3000
echo   Username: admin
echo   Password: admin123
echo.
echo   Prometheus: http://localhost:9090
echo   Loki: http://localhost:3100
echo.
echo Available Dashboards:
echo   - Smart Proxy Cybersecurity Dashboard
echo   - Threat Intelligence Dashboard  
echo   - Performance Monitoring Dashboard
echo.
echo ========================================

pause
