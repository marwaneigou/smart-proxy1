#!/usr/bin/env python3
"""
Comprehensive URL Test Suite for Smart Proxy Dashboard
This script provides categorized test URLs and can automatically test them
"""

import requests
import time
import json
from urllib.parse import urlparse

# Test URL categories
TEST_URLS = {
    "legitimate_sites": [
        "https://google.com",
        "https://microsoft.com", 
        "https://github.com",
        "https://stackoverflow.com",
        "https://wikipedia.org",
        "https://youtube.com",
        "https://amazon.com",
        "https://paypal.com",
        "https://chase.com",
        "https://wellsfargo.com"
    ],
    
    "suspicious_patterns": [
        "https://paypal-security.net",
        "https://amazon-verify.org", 
        "https://microsoft-update.co",
        "https://google-security.info",
        "https://apple-support.net",
        "https://facebook-security.org",
        "https://secure-paypal.net",
        "https://verify-amazon.com",
        "https://login-google.net",
        "https://confirm-facebook.org"
    ],
    
    "phishing_test_sites": [
        "https://phishing-quiz.withgoogle.com",
        "https://www.phishtank.com",
        "https://openphish.com",
        "https://phishing.org",
        "https://www.knowbe4.com"
    ],
    
    "banking_legitimate": [
        "https://chase.com",
        "https://bankofamerica.com",
        "https://wellsfargo.com",
        "https://citibank.com",
        "https://usbank.com"
    ],
    
    "social_media": [
        "https://facebook.com",
        "https://twitter.com",
        "https://linkedin.com",
        "https://instagram.com",
        "https://tiktok.com"
    ],
    
    "ecommerce": [
        "https://amazon.com",
        "https://ebay.com",
        "https://walmart.com",
        "https://target.com",
        "https://bestbuy.com"
    ]
}

def test_url_via_web_interface(url, base_url="http://127.0.0.1:5000"):
    """Test a URL through the Smart Proxy web interface"""
    try:
        response = requests.post(
            f"{base_url}/scan",
            data={"url": url},
            timeout=10,
            allow_redirects=True
        )
        
        if response.status_code == 200:
            try:
                result = response.json()
                return {
                    "url": url,
                    "status": "success",
                    "safe": result.get("safe", True),
                    "result": result.get("result", "Unknown"),
                    "confidence": result.get("ml_confidence", result.get("confidence", 0)),
                    "detection_method": result.get("detection_method", "Unknown"),
                    "response_time": result.get("ml_time_ms", 0)
                }
            except json.JSONDecodeError:
                return {
                    "url": url,
                    "status": "success",
                    "safe": True,
                    "result": "Scanned successfully",
                    "confidence": 0,
                    "detection_method": "Web Interface",
                    "response_time": 0
                }
        else:
            return {
                "url": url,
                "status": "error",
                "error": f"HTTP {response.status_code}"
            }
            
    except requests.exceptions.RequestException as e:
        return {
            "url": url,
            "status": "error", 
            "error": str(e)
        }

def print_test_results(results, category_name):
    """Print formatted test results"""
    print(f"\n🔍 {category_name.upper().replace('_', ' ')} RESULTS:")
    print("=" * 60)
    
    for result in results:
        if result["status"] == "success":
            safety_icon = "✅" if result["safe"] else "🚨"
            confidence = result["confidence"]
            if isinstance(confidence, (int, float)) and confidence > 0:
                conf_str = f"({confidence:.2f})" if confidence < 1 else f"({confidence:.0f}%)"
            else:
                conf_str = ""
            
            print(f"{safety_icon} {result['url']}")
            print(f"   Result: {result['result']} {conf_str}")
            print(f"   Method: {result['detection_method']}")
            if result['response_time'] > 0:
                print(f"   Time: {result['response_time']:.1f}ms")
        else:
            print(f"❌ {result['url']}")
            print(f"   Error: {result['error']}")
        print()

def test_category(category_name, urls, delay=2):
    """Test all URLs in a category"""
    print(f"\n🧪 Testing {category_name.replace('_', ' ').title()}...")
    print(f"📊 Testing {len(urls)} URLs with {delay}s delay between requests")
    
    results = []
    for i, url in enumerate(urls, 1):
        print(f"⏳ Testing {i}/{len(urls)}: {url}")
        result = test_url_via_web_interface(url)
        results.append(result)
        
        if i < len(urls):  # Don't delay after the last URL
            time.sleep(delay)
    
    print_test_results(results, category_name)
    return results

def interactive_test():
    """Interactive testing menu"""
    print("🛡️ Smart Proxy - URL Test Suite")
    print("=" * 50)
    print("Choose a category to test:")
    print()
    
    categories = list(TEST_URLS.keys())
    for i, category in enumerate(categories, 1):
        count = len(TEST_URLS[category])
        print(f"{i}. {category.replace('_', ' ').title()} ({count} URLs)")
    
    print(f"{len(categories) + 1}. Test All Categories")
    print(f"{len(categories) + 2}. Custom URL Test")
    print("0. Exit")
    
    while True:
        try:
            choice = input(f"\nEnter your choice (0-{len(categories) + 2}): ").strip()
            
            if choice == "0":
                print("👋 Goodbye!")
                break
            elif choice == str(len(categories) + 1):
                # Test all categories
                print("\n🚀 Testing All Categories...")
                all_results = {}
                for category in categories:
                    all_results[category] = test_category(category, TEST_URLS[category])
                
                # Summary
                print("\n📊 SUMMARY:")
                print("=" * 50)
                for category, results in all_results.items():
                    safe_count = sum(1 for r in results if r.get("safe", True))
                    total_count = len(results)
                    threat_count = total_count - safe_count
                    print(f"{category.replace('_', ' ').title()}: {safe_count} safe, {threat_count} threats")
                
            elif choice == str(len(categories) + 2):
                # Custom URL test
                custom_url = input("Enter URL to test: ").strip()
                if custom_url:
                    if not custom_url.startswith(('http://', 'https://')):
                        custom_url = 'https://' + custom_url
                    
                    print(f"\n🔍 Testing: {custom_url}")
                    result = test_url_via_web_interface(custom_url)
                    print_test_results([result], "custom_test")
                
            elif choice.isdigit() and 1 <= int(choice) <= len(categories):
                # Test specific category
                category_index = int(choice) - 1
                category = categories[category_index]
                test_category(category, TEST_URLS[category])
            else:
                print("❌ Invalid choice. Please try again.")
                
        except KeyboardInterrupt:
            print("\n👋 Interrupted by user. Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

def quick_test():
    """Quick test with a few URLs from each category"""
    print("🚀 Quick Test - 2 URLs from each category")
    print("=" * 50)
    
    for category, urls in TEST_URLS.items():
        # Test first 2 URLs from each category
        test_urls = urls[:2]
        test_category(category, test_urls, delay=1)

if __name__ == "__main__":
    print("🛡️ Smart Proxy URL Test Suite")
    print("=" * 50)
    print("Make sure your Smart Proxy web app is running on http://127.0.0.1:5000")
    print()
    print("Choose test mode:")
    print("1. Interactive Testing (choose categories)")
    print("2. Quick Test (2 URLs per category)")
    print("3. Show Test URLs Only")
    print("0. Exit")
    
    choice = input("\nEnter your choice (0-3): ").strip()
    
    if choice == "1":
        interactive_test()
    elif choice == "2":
        quick_test()
    elif choice == "3":
        print("\n📋 Available Test URLs by Category:")
        print("=" * 50)
        for category, urls in TEST_URLS.items():
            print(f"\n{category.replace('_', ' ').title()}:")
            for url in urls:
                print(f"  • {url}")
    elif choice == "0":
        print("👋 Goodbye!")
    else:
        print("❌ Invalid choice")
