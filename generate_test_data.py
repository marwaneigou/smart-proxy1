#!/usr/bin/env python3
"""
Generate test data for the Smart Proxy monitoring dashboard
This script simulates various security events and metrics
"""

import json
import time
import random
import os
from datetime import datetime
from log_config import setup_logging, log_metric, log_event

# Initialize logger
logger = setup_logging(log_dir="logs", log_level=20)

def generate_phishing_detection():
    """Generate a simulated phishing detection event"""
    domains = [
        "suspicious-bank.com",
        "fake-paypal.net", 
        "phishing-amazon.org",
        "malicious-google.co",
        "evil-microsoft.net",
        "scam-ebay.com",
        "fake-apple.org"
    ]
    
    domain = random.choice(domains)
    confidence = random.uniform(0.85, 0.99)
    
    log_event(logger, "ml_phishing_detected", {
        "url": f"https://{domain}/login",
        "domain": domain,
        "confidence": confidence,
        "detection_method": "machine_learning",
        "client_id": f"client_{random.randint(1000, 9999)}",
        "prediction_time": random.uniform(0.05, 0.3)
    })

def generate_safe_request():
    """Generate a simulated safe request"""
    safe_domains = [
        "google.com",
        "microsoft.com",
        "github.com",
        "stackoverflow.com",
        "wikipedia.org",
        "youtube.com",
        "amazon.com"
    ]
    
    domain = random.choice(safe_domains)
    
    log_metric(logger, "request", 1, {
        "host": domain,
        "client_id": f"client_{random.randint(1000, 9999)}",
        "path_type": "standard"
    })
    
    # Log analysis time
    analysis_time = random.uniform(50, 200)
    log_metric(logger, "analysis_time_ms", analysis_time, {
        "url": f"https://{domain}",
        "host": domain,
        "is_slow": analysis_time > 150
    })

def generate_bypass_event():
    """Generate a simulated bypass event"""
    domains = ["questionable-site.com", "flagged-domain.net", "suspicious-app.org"]
    domain = random.choice(domains)
    
    log_event(logger, "bypass_granted", {
        "client_id": f"client_{random.randint(1000, 9999)}",
        "domain": domain,
        "reason": "user_override"
    })

def generate_performance_metrics():
    """Generate performance-related metrics"""
    # ML prediction time
    ml_time = random.uniform(0.02, 0.15)
    log_metric(logger, "ml_prediction_time", ml_time, {
        "is_phishing": random.choice([True, False]),
        "confidence": random.uniform(0.1, 0.95),
        "domain": f"test-domain-{random.randint(1, 100)}.com"
    })

def generate_web_scan():
    """Generate a web interface scan event"""
    test_urls = [
        "https://example.com",
        "https://test-phishing.fake",
        "https://legitimate-site.org",
        "https://suspicious-login.net"
    ]
    
    url = random.choice(test_urls)
    is_phishing = "phishing" in url or "suspicious" in url
    
    log_event(logger, "web_scan_request", {
        "url": url,
        "source": "web_interface",
        "user_agent": "Mozilla/5.0 (Test Browser)"
    })
    
    if is_phishing:
        log_event(logger, "web_phishing_detected", {
            "url": url,
            "confidence": random.uniform(0.85, 0.98),
            "detection_method": "machine_learning",
            "source": "web_interface",
            "scan_time": random.uniform(0.5, 2.0)
        })

def main():
    """Main function to generate test data"""
    print("🔄 Generating test data for Smart Proxy monitoring...")
    print("📊 This will create realistic security events and metrics")
    print("⏱️  Running for 60 seconds with random intervals...")
    print()
    
    start_time = time.time()
    event_count = 0
    
    while time.time() - start_time < 60:  # Run for 60 seconds
        # Generate different types of events with realistic probabilities
        event_type = random.choices(
            ['safe_request', 'phishing', 'bypass', 'performance', 'web_scan'],
            weights=[70, 5, 2, 15, 8],  # Realistic distribution
            k=1
        )[0]
        
        if event_type == 'safe_request':
            generate_safe_request()
        elif event_type == 'phishing':
            generate_phishing_detection()
        elif event_type == 'bypass':
            generate_bypass_event()
        elif event_type == 'performance':
            generate_performance_metrics()
        elif event_type == 'web_scan':
            generate_web_scan()
        
        event_count += 1
        
        # Random delay between events (0.1 to 2 seconds)
        delay = random.uniform(0.1, 2.0)
        time.sleep(delay)
        
        # Progress indicator
        if event_count % 10 == 0:
            elapsed = time.time() - start_time
            print(f"📈 Generated {event_count} events in {elapsed:.1f}s")
    
    print()
    print(f"✅ Test data generation complete!")
    print(f"📊 Generated {event_count} total events")
    print(f"📁 Check the logs/ directory for generated data")
    print(f"🌐 View results in Grafana: http://localhost:3000")

if __name__ == "__main__":
    main()
