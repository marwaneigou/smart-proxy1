#!/usr/bin/env python3
"""
Test Loki connection and data ingestion
"""

import requests
import json
import time
from datetime import datetime, timedelta

def test_loki_connection():
    """Test if Loki is accessible"""
    try:
        response = requests.get("http://localhost:3100/ready", timeout=5)
        if response.status_code == 200:
            print("✅ Loki is ready and accessible")
            return True
        else:
            print(f"❌ Loki returned status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Cannot connect to Loki: {e}")
        return False

def test_loki_labels():
    """Test if Loki has any labels (data)"""
    try:
        response = requests.get("http://localhost:3100/loki/api/v1/labels", timeout=10)
        if response.status_code == 200:
            labels = response.json()
            print(f"✅ Loki labels found: {labels}")
            return len(labels.get('data', [])) > 0
        else:
            print(f"❌ Failed to get labels: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Error getting labels: {e}")
        return False

def test_loki_query():
    """Test a simple Loki query"""
    try:
        # Query for any logs in the last hour
        end_time = int(time.time() * 1000000000)  # nanoseconds
        start_time = end_time - (3600 * 1000000000)  # 1 hour ago
        
        query = '{job="smart_proxy"}'
        params = {
            'query': query,
            'start': start_time,
            'end': end_time,
            'limit': 10
        }
        
        response = requests.get(
            "http://localhost:3100/loki/api/v1/query_range",
            params=params,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            result_count = len(data.get('data', {}).get('result', []))
            print(f"✅ Loki query successful: {result_count} streams found")
            
            if result_count > 0:
                # Show sample data
                for stream in data['data']['result'][:2]:  # Show first 2 streams
                    labels = stream.get('stream', {})
                    values = stream.get('values', [])
                    print(f"   Stream labels: {labels}")
                    print(f"   Log entries: {len(values)}")
                    if values:
                        # Show first log entry
                        timestamp, log_line = values[0]
                        print(f"   Sample log: {log_line[:100]}...")
                return True
            else:
                print("⚠️  No data found in Loki")
                return False
        else:
            print(f"❌ Query failed: {response.status_code} - {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Error querying Loki: {e}")
        return False

def test_specific_events():
    """Test for specific event types"""
    try:
        end_time = int(time.time() * 1000000000)
        start_time = end_time - (3600 * 1000000000)  # 1 hour ago
        
        queries = [
            '{job="smart_proxy"} |= "EVENT:ml_phishing_detected"',
            '{job="smart_proxy"} |= "METRIC:request"',
            '{job="smart_proxy"} |= "EVENT"'
        ]
        
        for query in queries:
            params = {
                'query': query,
                'start': start_time,
                'end': end_time,
                'limit': 5
            }
            
            response = requests.get(
                "http://localhost:3100/loki/api/v1/query_range",
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                result_count = len(data.get('data', {}).get('result', []))
                total_entries = sum(len(stream.get('values', [])) for stream in data.get('data', {}).get('result', []))
                print(f"✅ Query '{query}': {total_entries} entries found")
            else:
                print(f"❌ Query '{query}' failed: {response.status_code}")
                
    except requests.exceptions.RequestException as e:
        print(f"❌ Error testing specific events: {e}")

def main():
    print("🔍 Testing Loki Connection and Data Ingestion")
    print("=" * 60)
    
    # Test 1: Basic connection
    print("\n1. Testing Loki connection...")
    if not test_loki_connection():
        print("❌ Cannot proceed - Loki is not accessible")
        return
    
    # Test 2: Check for labels
    print("\n2. Testing Loki labels...")
    test_loki_labels()
    
    # Test 3: Basic query
    print("\n3. Testing basic Loki query...")
    if test_loki_query():
        print("✅ Data is being ingested successfully!")
    else:
        print("⚠️  No data found - checking specific events...")
        
        # Test 4: Specific event queries
        print("\n4. Testing specific event queries...")
        test_specific_events()
    
    print("\n" + "=" * 60)
    print("🎯 Dashboard Troubleshooting Tips:")
    print("1. Wait 30-60 seconds for data to appear in Grafana")
    print("2. Check time range in dashboard (try 'Last 1 hour')")
    print("3. Refresh the dashboard manually")
    print("4. Verify Loki data source in Grafana settings")
    print("\n📊 Dashboard URL: http://localhost:3000")

if __name__ == "__main__":
    main()
