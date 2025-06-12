# 🛡️ Smart Proxy - Professional Cybersecurity Monitoring Dashboard

## 📊 Overview

This monitoring setup provides a comprehensive cybersecurity dashboard using Grafana, Loki, Prometheus, and Promtail to monitor your Smart Proxy phishing detection system in real-time.

## 🏗️ Architecture

```
Smart Proxy Application
         ↓ (JSON logs)
    Promtail Agent
         ↓ (Log shipping)
      Loki Database
         ↓ (Query)
    Grafana Dashboard
```

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose installed
- Smart Proxy application running and generating logs

### 1. Start Monitoring Stack

```bash
# Windows
start-monitoring.bat

# Linux/Mac
docker-compose up -d
```

### 2. Access Dashboards

- **Grafana**: http://localhost:3000
  - Username: `admin`
  - Password: `admin123`

- **Prometheus**: http://localhost:9090
- **Loki**: http://localhost:3100

## 📈 Available Dashboards

### 1. 🛡️ Smart Proxy Cybersecurity Dashboard
**Main security monitoring dashboard with:**

- **Real-time Threat Metrics**
  - Phishing threats detected (1h)
  - Total requests processed
  - Bypass requests granted
  - Average analysis time

- **Security Timeline**
  - Phishing detections over time
  - Safe vs malicious requests
  - Real-time event stream

- **Threat Distribution**
  - Pie chart of security status
  - Detection method breakdown

### 2. 🎯 Threat Intelligence Dashboard
**Advanced threat analysis with:**

- **Detailed Threat Table**
  - Timestamp of detection
  - Full URL of threat
  - ML confidence score
  - Domain information
  - Detection method used

- **Threat Patterns**
  - Common attack vectors
  - Confidence score distribution
  - Geographic threat mapping

### 3. ⚡ Performance Monitoring Dashboard
**System performance metrics:**

- **Response Times**
  - ML prediction time
  - Total analysis time
  - Request processing latency

- **Throughput Metrics**
  - Requests per second
  - Detection rate
  - System load indicators

## 🔧 Configuration

### Log Format
The system uses structured JSON logging:

```json
{
  "timestamp": 1749563025790,
  "level": "INFO",
  "logger": "root",
  "message": "EVENT:ml_phishing_detected",
  "event": "ml_phishing_detected",
  "url": "https://suspicious-site.com",
  "confidence": 0.95,
  "domain": "suspicious-site.com",
  "detection_method": "machine_learning"
}
```

### Key Metrics Tracked

- **Security Events**
  - `ml_phishing_detected`: ML model detections
  - `bypass_granted`: User bypasses
  - `web_scan_request`: Manual scans

- **Performance Metrics**
  - `ml_prediction_time`: ML inference time
  - `analysis_time_ms`: Total analysis time
  - `request`: Request count

- **System Health**
  - `model_loaded`: ML model status
  - `ml_model_load_time`: Model loading time

## 🎨 Dashboard Features

### Visual Elements
- **🚨 Red Alerts**: Active threats
- **✅ Green Status**: Safe operations
- **⚡ Performance**: Speed indicators
- **📊 Analytics**: Trend analysis

### Interactive Features
- **Time Range Selection**: 5m, 15m, 1h, 6h, 24h
- **Auto-refresh**: 5-10 second intervals
- **Drill-down**: Click metrics for details
- **Filtering**: By domain, confidence, method

## 🔍 Query Examples

### Loki Queries
```logql
# All phishing detections
{job="smart_proxy"} |= "EVENT:ml_phishing_detected"

# High confidence threats
{job="smart_proxy"} |= "ml_phishing_detected" | json | confidence > 0.9

# Performance issues
{job="smart_proxy"} |= "analysis_time_ms" | json | analysis_time_ms > 1000
```

### Prometheus Queries
```promql
# Request rate
rate(smart_proxy_requests_total[5m])

# Error rate
rate(smart_proxy_errors_total[5m]) / rate(smart_proxy_requests_total[5m])
```

## 🚨 Alerting

### Alert Rules
Configure alerts for:
- High phishing detection rate
- System performance degradation
- ML model failures
- Unusual bypass activity

### Notification Channels
- Email alerts
- Slack integration
- PagerDuty escalation
- SMS notifications

## 📁 File Structure

```
monitoring/
├── docker-compose.yml          # Main orchestration
├── grafana/
│   ├── provisioning/
│   │   ├── datasources/        # Data source configs
│   │   └── dashboards/         # Dashboard configs
│   └── dashboards/             # Dashboard JSON files
├── loki/
│   └── local-config.yaml       # Loki configuration
├── prometheus/
│   └── prometheus.yml          # Prometheus config
├── promtail/
│   └── promtail-config.yaml    # Log shipping config
└── logs/                       # Application logs
```

## 🛠️ Troubleshooting

### Common Issues

1. **No data in dashboards**
   - Check if logs are being generated
   - Verify Promtail is reading log files
   - Ensure Loki is receiving data

2. **Performance issues**
   - Increase log retention settings
   - Optimize query time ranges
   - Check Docker resource limits

3. **Connection errors**
   - Verify all containers are running
   - Check network connectivity
   - Review firewall settings

### Debug Commands

```bash
# Check container status
docker-compose ps

# View logs
docker-compose logs grafana
docker-compose logs loki
docker-compose logs promtail

# Restart services
docker-compose restart
```

## 🔒 Security Considerations

- Change default Grafana password
- Enable HTTPS for production
- Restrict network access
- Regular backup of dashboards
- Monitor log file permissions

## 📚 Additional Resources

- [Grafana Documentation](https://grafana.com/docs/)
- [Loki Documentation](https://grafana.com/docs/loki/)
- [Prometheus Documentation](https://prometheus.io/docs/)
- [LogQL Query Language](https://grafana.com/docs/loki/latest/logql/)
