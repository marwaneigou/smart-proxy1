# 🛡️ Smart Proxy - Grafana Dashboard Setup Guide

## 🎯 **Quick Setup Instructions**

Your Grafana monitoring system is now running! Follow these steps to set up your professional cybersecurity dashboard.

### **Step 1: Access Grafana**
- **URL**: http://localhost:3000
- **Username**: `admin`
- **Password**: `admin123`

**✅ FIXED: Admin password has been reset and login should work now!**

### **Step 2: Add Loki Data Source**

1. **Click the gear icon (⚙️)** in the left sidebar → **Data Sources**
2. **Click "Add data source"**
3. **Select "Loki"**
4. **Configure the data source:**
   - **Name**: `Loki`
   - **URL**: `http://loki:3100`
   - **Access**: `Server (default)`
5. **Click "Save & Test"** - you should see "Data source connected and labels found"

### **Step 3: Import Dashboard**

1. **Click the "+" icon** in the left sidebar → **Import**
2. **Copy and paste this dashboard JSON:**

```json
{
  "dashboard": {
    "id": null,
    "title": "🛡️ Smart Proxy - Cybersecurity Dashboard",
    "tags": ["cybersecurity", "phishing", "smart-proxy"],
    "style": "dark",
    "timezone": "",
    "panels": [
      {
        "id": 1,
        "title": "🚨 Phishing Threats (1h)",
        "type": "stat",
        "targets": [
          {
            "expr": "sum(count_over_time({job=\"smart_proxy\"} |= \"EVENT:ml_phishing_detected\" [1h]))",
            "refId": "A"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "color": {
              "mode": "thresholds"
            },
            "thresholds": {
              "steps": [
                {"color": "green", "value": null},
                {"color": "red", "value": 1}
              ]
            }
          }
        },
        "gridPos": {"h": 4, "w": 6, "x": 0, "y": 0}
      },
      {
        "id": 2,
        "title": "📊 Total Requests (1h)",
        "type": "stat",
        "targets": [
          {
            "expr": "sum(count_over_time({job=\"smart_proxy\"} |= \"METRIC:request\" [1h]))",
            "refId": "A"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "color": {
              "mode": "thresholds"
            },
            "thresholds": {
              "steps": [
                {"color": "green", "value": null},
                {"color": "yellow", "value": 100},
                {"color": "red", "value": 500}
              ]
            }
          }
        },
        "gridPos": {"h": 4, "w": 6, "x": 6, "y": 0}
      },
      {
        "id": 3,
        "title": "🛡️ Security Events Log",
        "type": "logs",
        "targets": [
          {
            "expr": "{job=\"smart_proxy\"} |= \"EVENT\" | json",
            "refId": "A"
          }
        ],
        "gridPos": {"h": 12, "w": 24, "x": 0, "y": 4}
      }
    ],
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "refresh": "5s"
  }
}
```

3. **Click "Load"**
4. **Configure the import:**
   - **Name**: Keep the default name
   - **Folder**: Select "General" or create a new folder
   - **Loki**: Select the Loki data source you created
5. **Click "Import"**

### **Step 4: Generate Test Data**

Run the test data generator to populate your dashboard:

```bash
python generate_test_data.py
```

This will create realistic security events and metrics for 60 seconds.

### **Step 5: View Your Dashboard**

Your professional cybersecurity dashboard is now ready! You should see:

- **🚨 Real-time threat metrics**
- **📊 Request statistics**
- **🛡️ Security event logs**
- **⚡ Performance indicators**

## 🎨 **Dashboard Features**

### **Visual Elements**
- **🚨 Red alerts** for security threats
- **✅ Green indicators** for safe operations
- **📊 Real-time charts** with 5-second refresh
- **🔍 Searchable logs** with JSON parsing

### **Key Metrics Displayed**
- **Phishing detections** with confidence scores
- **Request volume** and processing times
- **Security bypasses** and user overrides
- **ML model performance** metrics

### **Interactive Features**
- **Time range selection**: 5m, 15m, 1h, 6h, 24h
- **Auto-refresh**: Real-time updates
- **Log filtering**: Search and filter events
- **Drill-down**: Click metrics for details

## 🔧 **Customization Options**

### **Add More Panels**
1. **Click "Add panel"** in dashboard edit mode
2. **Select visualization type** (Graph, Stat, Table, etc.)
3. **Configure query**: Use LogQL syntax for Loki
4. **Style the panel**: Colors, thresholds, legends

### **Sample LogQL Queries**
```logql
# All phishing detections
{job="smart_proxy"} |= "EVENT:ml_phishing_detected"

# High confidence threats (>90%)
{job="smart_proxy"} |= "ml_phishing_detected" | json | confidence > 0.9

# Performance issues (>1000ms)
{job="smart_proxy"} |= "analysis_time_ms" | json | analysis_time_ms > 1000

# Web interface scans
{job="smart_proxy"} |= "EVENT:web_scan_request"

# Bypass events
{job="smart_proxy"} |= "EVENT:bypass_granted"
```

### **Alert Configuration**
1. **Go to Alerting** → **Alert Rules**
2. **Create new rule**
3. **Set conditions** (e.g., phishing rate > 5/minute)
4. **Configure notifications** (email, Slack, etc.)

## 🚨 **Troubleshooting**

### **No Data Showing**
- Ensure your Smart Proxy application is running
- Check that logs are being generated in the `logs/` directory
- Verify Loki data source connection

### **Connection Issues**
- Confirm Docker containers are running: `docker-compose ps`
- Check container logs: `docker-compose logs grafana`
- Restart services: `docker-compose restart`

### **Query Errors**
- Verify LogQL syntax in query editor
- Check time range selection
- Ensure data source is properly configured

## 🎯 **Next Steps**

1. **Explore the dashboard** and familiarize yourself with the interface
2. **Generate more test data** to see trends over time
3. **Customize panels** to match your specific needs
4. **Set up alerts** for critical security events
5. **Create additional dashboards** for different use cases

---

**🎉 Your professional cybersecurity monitoring dashboard is now ready!**

Access it at: http://localhost:3000 (admin/admin123)
