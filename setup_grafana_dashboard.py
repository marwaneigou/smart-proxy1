#!/usr/bin/env python3
"""
Automated Grafana Dashboard Setup Script
This script automatically configures Grafana with Loki data source and imports the cybersecurity dashboard
"""

import requests
import json
import time
import sys

# Grafana configuration
GRAFANA_URL = "http://localhost:3000"
GRAFANA_USER = "admin"
GRAFANA_PASSWORD = "admin123"
LOKI_URL = "http://loki:3100"

def wait_for_grafana():
    """Wait for Grafana to be ready"""
    print("🔄 Waiting for Grafana to be ready...")
    for i in range(30):
        try:
            response = requests.get(f"{GRAFANA_URL}/api/health", timeout=5)
            if response.status_code == 200:
                print("✅ Grafana is ready!")
                return True
        except requests.exceptions.RequestException:
            pass
        
        print(f"⏳ Waiting... ({i+1}/30)")
        time.sleep(2)
    
    print("❌ Grafana is not responding after 60 seconds")
    return False

def create_loki_datasource():
    """Create Loki data source in Grafana"""
    print("🔧 Creating Loki data source...")
    
    datasource_config = {
        "name": "Loki",
        "type": "loki",
        "url": LOKI_URL,
        "access": "proxy",
        "isDefault": True,
        "jsonData": {
            "maxLines": 1000
        }
    }
    
    try:
        response = requests.post(
            f"{GRAFANA_URL}/api/datasources",
            auth=(GRAFANA_USER, GRAFANA_PASSWORD),
            headers={"Content-Type": "application/json"},
            json=datasource_config,
            timeout=10
        )
        
        if response.status_code == 200:
            print("✅ Loki data source created successfully!")
            return True
        elif response.status_code == 409:
            print("ℹ️  Loki data source already exists")
            return True
        else:
            print(f"❌ Failed to create data source: {response.status_code} - {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Error creating data source: {e}")
        return False

def create_dashboard():
    """Create the cybersecurity dashboard"""
    print("📊 Creating cybersecurity dashboard...")
    
    dashboard_config = {
        "dashboard": {
            "id": None,
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
                            "color": {"mode": "thresholds"},
                            "thresholds": {
                                "steps": [
                                    {"color": "green", "value": None},
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
                            "color": {"mode": "thresholds"},
                            "thresholds": {
                                "steps": [
                                    {"color": "green", "value": None},
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
                    "title": "🛡️ Security Events Timeline",
                    "type": "timeseries",
                    "targets": [
                        {
                            "expr": "sum(rate({job=\"smart_proxy\"} |= \"EVENT:ml_phishing_detected\" [5m]))",
                            "legendFormat": "Phishing Detected",
                            "refId": "A"
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "color": {"mode": "palette-classic"},
                            "custom": {
                                "drawStyle": "line",
                                "lineInterpolation": "linear",
                                "lineWidth": 2,
                                "fillOpacity": 10
                            }
                        }
                    },
                    "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0}
                },
                {
                    "id": 4,
                    "title": "🛡️ Security Events Log",
                    "type": "logs",
                    "targets": [
                        {
                            "expr": "{job=\"smart_proxy\"} |= \"EVENT\" | json | line_format \"{{.timestamp}} | {{.level}} | {{.message}} | {{.url}} | {{.confidence}}\"",
                            "refId": "A"
                        }
                    ],
                    "gridPos": {"h": 12, "w": 24, "x": 0, "y": 4}
                }
            ],
            "time": {"from": "now-1h", "to": "now"},
            "refresh": "5s"
        },
        "overwrite": True
    }
    
    try:
        response = requests.post(
            f"{GRAFANA_URL}/api/dashboards/db",
            auth=(GRAFANA_USER, GRAFANA_PASSWORD),
            headers={"Content-Type": "application/json"},
            json=dashboard_config,
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            dashboard_url = f"{GRAFANA_URL}/d/{result['uid']}"
            print(f"✅ Dashboard created successfully!")
            print(f"🌐 Dashboard URL: {dashboard_url}")
            return True
        else:
            print(f"❌ Failed to create dashboard: {response.status_code} - {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Error creating dashboard: {e}")
        return False

def main():
    """Main setup function"""
    print("🛡️ Smart Proxy - Grafana Dashboard Setup")
    print("=" * 50)
    
    # Wait for Grafana to be ready
    if not wait_for_grafana():
        sys.exit(1)
    
    # Create Loki data source
    if not create_loki_datasource():
        print("❌ Failed to create Loki data source")
        sys.exit(1)
    
    # Create dashboard
    if not create_dashboard():
        print("❌ Failed to create dashboard")
        sys.exit(1)
    
    print("\n🎉 Setup completed successfully!")
    print(f"🌐 Access Grafana: {GRAFANA_URL}")
    print(f"👤 Username: {GRAFANA_USER}")
    print(f"🔑 Password: {GRAFANA_PASSWORD}")
    print("\n📊 Your cybersecurity dashboard is ready!")

if __name__ == "__main__":
    main()
