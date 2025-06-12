#!/usr/bin/env python3
"""
Test script for the Smart Proxy analyzer
Tests both legitimate and phishing-like URLs safely
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scanner_analyzer import ScannerAnalyzer

def test_analyzer():
    print("🧪 Testing Smart Proxy Analyzer")
    print("=" * 50)
    
    # Initialize analyzer
    analyzer = ScannerAnalyzer()
    
    # Test URLs - mix of legitimate and suspicious patterns
    test_cases = [
        # Legitimate URLs (should be safe)
        {
            'url': 'https://www.google.com',
            'expected': 'safe',
            'description': 'Google (whitelisted)'
        },
        {
            'url': 'https://github.com/user/repo',
            'expected': 'safe', 
            'description': 'GitHub (legitimate)'
        },
        {
            'url': 'https://stackoverflow.com/questions/123',
            'expected': 'safe',
            'description': 'StackOverflow (legitimate)'
        },
        
        # Test URLs with phishing characteristics (safe to test)
        {
            'url': 'http://paypal-security-update.fake-domain.test',
            'expected': 'phishing',
            'description': 'Fake PayPal (test domain)'
        },
        {
            'url': 'https://amazon-account-suspended.evil-test.com',
            'expected': 'phishing', 
            'description': 'Fake Amazon (test domain)'
        },
        {
            'url': 'http://192.168.1.100/facebook-login.php',
            'expected': 'phishing',
            'description': 'IP-based fake Facebook'
        },
        {
            'url': 'https://secure-bank-login.phishing-test.org',
            'expected': 'phishing',
            'description': 'Fake bank (test domain)'
        },
        {
            'url': 'http://microsoft-security-alert.fake.net',
            'expected': 'phishing',
            'description': 'Fake Microsoft (test domain)'
        }
    ]
    
    print(f"Testing {len(test_cases)} URLs...\n")
    
    correct_predictions = 0
    total_tests = len(test_cases)
    
    for i, case in enumerate(test_cases, 1):
        print(f"Test {i}/{total_tests}: {case['description']}")
        print(f"URL: {case['url']}")
        
        try:
            # Analyze the URL
            result = analyzer.analyze_url(case['url'])
            
            # Determine prediction
            prediction = 'safe' if result['safe'] else 'phishing'
            confidence = result.get('confidence', 0)
            analysis_time = result.get('analysis_time', 0)
            
            # Check if prediction matches expected
            is_correct = prediction == case['expected']
            if is_correct:
                correct_predictions += 1
                status = "✅ CORRECT"
            else:
                status = "❌ INCORRECT"
            
            print(f"Expected: {case['expected']}")
            print(f"Predicted: {prediction} (confidence: {confidence:.2f})")
            print(f"Analysis time: {analysis_time:.1f}ms")
            print(f"Result: {status}")
            
            # Show features for phishing URLs
            if 'features' in result and not result['safe']:
                features = result['features']
                print(f"Suspicious features detected:")
                if features.get('has_suspicious_words'):
                    print("  - Contains suspicious keywords")
                if features.get('has_ip'):
                    print("  - Uses IP address instead of domain")
                if not features.get('has_https'):
                    print("  - No HTTPS encryption")
                if features.get('url_length', 0) > 75:
                    print(f"  - Very long URL ({features['url_length']} chars)")
                if features.get('subdomain_count', 0) > 3:
                    print(f"  - Too many subdomains ({features['subdomain_count']})")
            
        except Exception as e:
            print(f"❌ ERROR: {e}")
            status = "ERROR"
        
        print("-" * 50)
    
    # Summary
    accuracy = (correct_predictions / total_tests) * 100
    print(f"\n📊 TEST RESULTS SUMMARY")
    print(f"Total tests: {total_tests}")
    print(f"Correct predictions: {correct_predictions}")
    print(f"Accuracy: {accuracy:.1f}%")
    
    if accuracy >= 80:
        print("🎉 Great! Your analyzer is working well!")
    elif accuracy >= 60:
        print("👍 Good performance, but could be improved")
    else:
        print("⚠️  Analyzer needs improvement")
    
    return accuracy

def test_whitelist():
    print("\n🔍 Testing Whitelist Functionality")
    print("=" * 50)
    
    analyzer = ScannerAnalyzer()
    
    # Test whitelist domains
    whitelist_tests = [
        'google.com',
        'www.google.com', 
        'youtube.com',
        'facebook.com',
        'github.com'
    ]
    
    print(f"Current whitelist size: {len(analyzer.whitelist)}")
    print(f"Testing {len(whitelist_tests)} domains...")
    
    for domain in whitelist_tests:
        is_whitelisted = analyzer._is_whitelisted(domain)
        status = "✅ WHITELISTED" if is_whitelisted else "❌ NOT WHITELISTED"
        print(f"{domain}: {status}")
    
    # Test adding a new domain
    print(f"\n➕ Adding 'example.com' to whitelist...")
    analyzer.whitelist.add('example.com')
    analyzer.save_whitelist()
    
    # Test the new domain
    is_whitelisted = analyzer._is_whitelisted('example.com')
    status = "✅ SUCCESSFULLY ADDED" if is_whitelisted else "❌ FAILED TO ADD"
    print(f"example.com: {status}")

if __name__ == "__main__":
    try:
        # Test the analyzer
        accuracy = test_analyzer()
        
        # Test whitelist
        test_whitelist()
        
        print(f"\n🏁 All tests completed!")
        
    except KeyboardInterrupt:
        print("\n⏹️  Tests interrupted by user")
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        import traceback
        traceback.print_exc()
