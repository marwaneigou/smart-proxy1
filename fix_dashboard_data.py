#!/usr/bin/env python3
"""
Fix dashboard data issues and verify Grafana setup
"""

import requests
import json
import time
from datetime import datetime, timedelta

def test_grafana_connection():
    """Test if Grafana is accessible"""
    try:
        response = requests.get("http://localhost:3000/api/health", timeout=5)
        if response.status_code == 200:
            print("✅ Grafana is accessible")
            return True
        else:
            print(f"❌ Grafana returned status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Cannot connect to Grafana: {e}")
        return False

def test_grafana_datasource():
    """Test Grafana Loki data source"""
    try:
        # Test data source
        response = requests.get(
            "http://localhost:3000/api/datasources",
            auth=("admin", "admin123"),
            timeout=10
        )
        
        if response.status_code == 200:
            datasources = response.json()
            loki_ds = None
            for ds in datasources:
                if ds.get('type') == 'loki':
                    loki_ds = ds
                    break
            
            if loki_ds:
                print(f"✅ Loki data source found: {loki_ds['name']} (ID: {loki_ds['id']})")
                
                # Test data source connectivity
                test_response = requests.get(
                    f"http://localhost:3000/api/datasources/{loki_ds['id']}/health",
                    auth=("admin", "admin123"),
                    timeout=10
                )
                
                if test_response.status_code == 200:
                    health = test_response.json()
                    print(f"✅ Data source health: {health.get('status', 'Unknown')}")
                    return True
                else:
                    print(f"❌ Data source health check failed: {test_response.status_code}")
                    return False
            else:
                print("❌ No Loki data source found")
                return False
        else:
            print(f"❌ Failed to get data sources: {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Error testing data source: {e}")
        return False

def test_dashboard_queries():
    """Test dashboard queries directly"""
    try:
        # Test the main dashboard queries
        queries = [
            {
                "name": "Phishing Threats Count",
                "query": 'sum(count_over_time({job="smart_proxy"} |= "EVENT:ml_phishing_detected" [1h]))',
                "range": "1h"
            },
            {
                "name": "Total Requests Count", 
                "query": 'sum(count_over_time({job="smart_proxy"} |= "METRIC:request" [1h]))',
                "range": "1h"
            },
            {
                "name": "Event Logs",
                "query": '{job="smart_proxy"} |= "EVENT" | json | line_format "{{.timestamp}} | {{.level}} | {{.message}} | {{.url}} | {{.confidence}}"',
                "range": "1h"
            }
        ]
        
        end_time = int(time.time())
        start_time = end_time - 3600  # 1 hour ago
        
        for query_info in queries:
            print(f"\n🔍 Testing query: {query_info['name']}")
            
            # Prepare query parameters
            params = {
                "query": query_info["query"],
                "start": start_time,
                "end": end_time,
                "step": "60s"
            }
            
            # Make request to Grafana's proxy to Loki
            response = requests.get(
                "http://localhost:3000/api/datasources/proxy/1/loki/api/v1/query_range",
                params=params,
                auth=("admin", "admin123"),
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    result_count = len(data.get('data', {}).get('result', []))
                    print(f"   ✅ Query successful: {result_count} result streams")
                    
                    # Show sample data
                    for i, stream in enumerate(data.get('data', {}).get('result', [])[:2]):
                        values = stream.get('values', [])
                        print(f"   Stream {i+1}: {len(values)} entries")
                        if values:
                            print(f"   Sample: {values[0][1][:80]}...")
                else:
                    print(f"   ❌ Query failed: {data}")
            else:
                print(f"   ❌ HTTP error: {response.status_code} - {response.text[:200]}")
                
    except requests.exceptions.RequestException as e:
        print(f"❌ Error testing queries: {e}")

def generate_fresh_data():
    """Generate fresh test data"""
    print("\n🔄 Generating fresh test data...")
    
    import logging
    import uuid
    import random
    
    # Setup logging to match the proxy format
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s',
        handlers=[
            logging.FileHandler('logs/smart_proxy.json', mode='a'),
        ]
    )
    
    logger = logging.getLogger()
    
    # Generate some test events
    events = [
        {
            "event": "ml_phishing_detected",
            "url": "https://fake-paypal.net",
            "confidence": 0.95,
            "host": "fake-paypal.net"
        },
        {
            "event": "ml_phishing_detected", 
            "url": "https://evil-amazon.org",
            "confidence": 0.88,
            "host": "evil-amazon.org"
        },
        {
            "event": "web_scan_request",
            "url": "https://test-site.com",
            "result": "safe"
        }
    ]
    
    timestamp = int(time.time() * 1000)
    
    for i, event_data in enumerate(events):
        log_entry = {
            "timestamp": timestamp + i * 1000,
            "level": "INFO",
            "logger": "root",
            "message": f"EVENT:{event_data['event']}",
            **event_data
        }
        
        logger.info(json.dumps(log_entry))
        
        # Also log a metric
        metric_entry = {
            "timestamp": timestamp + i * 1000 + 500,
            "level": "INFO", 
            "logger": "root",
            "message": "METRIC:request:1",
            "request": 1,
            "host": event_data.get('host', 'unknown')
        }
        
        logger.info(json.dumps(metric_entry))
    
    print(f"✅ Generated {len(events)} test events")

def main():
    print("🔧 Dashboard Data Troubleshooting")
    print("=" * 60)
    
    # Test 1: Grafana connection
    print("\n1. Testing Grafana connection...")
    if not test_grafana_connection():
        print("❌ Cannot proceed - Grafana is not accessible")
        return
    
    # Test 2: Data source
    print("\n2. Testing Grafana data source...")
    test_grafana_datasource()
    
    # Test 3: Generate fresh data
    print("\n3. Generating fresh test data...")
    generate_fresh_data()
    
    # Wait for data to be ingested
    print("\n⏳ Waiting 10 seconds for data ingestion...")
    time.sleep(10)
    
    # Test 4: Dashboard queries
    print("\n4. Testing dashboard queries...")
    test_dashboard_queries()
    
    print("\n" + "=" * 60)
    print("🎯 Dashboard Troubleshooting Complete!")
    print("\n📊 Next Steps:")
    print("1. Open dashboard: http://localhost:3000/d/d4b2371e-81ed-4692-98c5-77a97994b141")
    print("2. Set time range to 'Last 1 hour' or 'Last 5 minutes'")
    print("3. Click refresh button in top right")
    print("4. Check that all panels show data")
    print("\n🔧 If still no data:")
    print("1. Check time range matches when data was generated")
    print("2. Verify queries in panel edit mode")
    print("3. Check Loki data source settings")
    
    print(f"\n⏰ Current time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("📅 Use this time as reference for dashboard time range")

if __name__ == "__main__":
    main()
