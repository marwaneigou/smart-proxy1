import re
import time
import logging
import json
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ScannerAnalyzer:
    """A version of TrafficAnalyzer adapted for direct URL scanning without mitmproxy"""
    
    # Class variables for better performance
    PHISHING_KEYWORDS = [
        "login", "password", "signin", "account", "bank", "credit", "wallet",
        "verify", "secure", "authenticate", "paypal", "billing", "suspended",
        "security", "update", "confirm", "limited", "locked", "expired",
        "amazon", "microsoft", "google", "facebook", "apple", "netflix",
        "ebay", "instagram", "twitter", "linkedin", "dropbox", "adobe"
    ]
    
    MALICIOUS_JS_PATTERNS = [
        r"eval\s*\(",
        r"document\.write\s*\(",
        r"(?:document|window)\.location\s*=\s*['\"][^'\"]*['\"]"
    ]
    
    IFRAME_PATTERN = r"<iframe[^>]*src=['\"]([^'\"]+)['\"]"
    XSS_PATTERN = r"<script>[\s\S]*?</script>"
    
    def __init__(self):
        self.cache = {}  # Simple cache for recent URLs
        self.cache_limit = 100  # Maximum cache size
        
        # Load whitelist from file
        self.whitelist = set()
        self._load_whitelist()
    
    def analyze_url(self, url):
        """
        Analyze just the URL for phishing patterns (without HTML content)
        Returns a dictionary with safe/unsafe classification
        """
        start_time = time.time()

        # Handle test URLs that don't actually exist
        if any(test_domain in url for test_domain in ['.test', '.fake', '.evil', '.phishing-test']):
            # This is a test URL - analyze it without making network requests
            return self._analyze_test_url(url)

        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Clean domain (remove www. if present)
        if domain.startswith('www.'):
            clean_domain = domain[4:]
        else:
            clean_domain = domain

        # Check if domain is in whitelist (directly or via wildcard)
        is_trusted = self._is_whitelisted(domain) or self._is_whitelisted(clean_domain)

        if is_trusted:
            logging.info(f"Domain {domain} is recognized as trusted (from whitelist)")
            return {
                'safe': True,
                'confidence': 0.95,
                'analysis_time': (time.time() - start_time) * 1000,
                'trusted': True
            }

        # Analyze URL characteristics for phishing indicators
        features = self._extract_url_features(url)
        is_suspicious = self._classify_url_features(features)

        return {
            'safe': not is_suspicious,
            'confidence': 0.8 if is_suspicious else 0.7,
            'analysis_time': (time.time() - start_time) * 1000,
            'features': features
        }

    def _analyze_test_url(self, url):
        """Analyze test URLs without making network requests"""
        # Extract features that indicate phishing
        features = self._extract_url_features(url)
        is_phishing = self._classify_url_features(features)

        return {
            'safe': not is_phishing,
            'confidence': 0.9 if is_phishing else 0.8,
            'analysis_time': 50,  # Simulated analysis time
            'features': features,
            'test_url': True
        }

    def _extract_url_features(self, url):
        """Extract features from URL for analysis"""
        from urllib.parse import urlparse
        import re

        parsed = urlparse(url)

        return {
            'url_length': len(url),
            'domain_length': len(parsed.netloc),
            'has_ip': bool(re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc)),
            'has_https': parsed.scheme == 'https',
            'has_suspicious_words': any(word in url.lower() for word in self.PHISHING_KEYWORDS),
            'subdomain_count': parsed.netloc.count('.'),
            'special_char_count': sum(1 for c in url if c in '!@#$%^&*()'),
            'path_length': len(parsed.path),
            'query_length': len(parsed.query or '')
        }

    def _classify_url_features(self, features):
        """Enhanced rule-based classification of URL features"""
        suspicious_score = 0

        # Long URLs are suspicious
        if features['url_length'] > 75:
            suspicious_score += 2
        elif features['url_length'] > 50:
            suspicious_score += 1

        # IP addresses instead of domains (very suspicious)
        if features['has_ip']:
            suspicious_score += 4

        # No HTTPS (less secure)
        if not features['has_https']:
            suspicious_score += 1

        # Suspicious keywords (very important indicator)
        if features['has_suspicious_words']:
            suspicious_score += 3

        # Too many subdomains (suspicious)
        if features['subdomain_count'] > 4:
            suspicious_score += 3
        elif features['subdomain_count'] > 2:
            suspicious_score += 1

        # Many special characters
        if features['special_char_count'] > 8:
            suspicious_score += 2
        elif features['special_char_count'] > 5:
            suspicious_score += 1

        # Very long domain names
        if features['domain_length'] > 30:
            suspicious_score += 2

        # Long paths (could indicate complex phishing URLs)
        if features['path_length'] > 50:
            suspicious_score += 1

        # Long query strings (suspicious)
        if features['query_length'] > 100:
            suspicious_score += 1

        print(f"DEBUG: Suspicious score: {suspicious_score} for features: {features}")

        # Return True if suspicious (lowered threshold to 3)
        return suspicious_score >= 3

    def analyze(self, url, html_content):
        """
        Analyze URL and HTML content for phishing and malicious patterns
        Returns a dictionary with detected patterns and malicious flag
        """
        start_time = time.time()

        # Check cache first for performance
        if url in self.cache:
            logging.info(f"[Cache Hit] Using cached result for {url}")
            return self.cache[url]

        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Clean domain (remove www. if present)
        if domain.startswith('www.'):
            clean_domain = domain[4:]
        else:
            clean_domain = domain

        # Check if domain is in whitelist (directly or via wildcard)
        is_trusted = self._is_whitelisted(domain) or self._is_whitelisted(clean_domain)

        if is_trusted:
            logging.info(f"Domain {domain} is recognized as trusted (from whitelist)")
            # For trusted domains, return immediately with empty patterns
            # This ensures no further detection is done on trusted domains
            return {
                'is_malicious': False,
                'detected_patterns': [],
                'analysis_time_ms': (time.time() - start_time) * 1000,
                'trusted': True
            }
        
        html_lower = html_content.lower()  # Convert once for case-insensitive checks
        detected_patterns = []
        
        # Only do keyword matching if not a trusted domain
        # Fast check for phishing keywords
        for keyword in self.PHISHING_KEYWORDS:
            if keyword in html_lower:
                warning = f"Suspicious keyword '{keyword}' found"
                logging.warning(f"[Phishing Detection] {warning} in {url}")
                detected_patterns.append(warning)
        
        # Check for malicious JavaScript - only perform on non-trusted domains or with more validation
        if not is_trusted:
            for pattern in self.MALICIOUS_JS_PATTERNS:
                if re.search(pattern, html_content):
                    warning = f"Dangerous JavaScript pattern detected: {pattern}"
                    logging.warning(f"[Suspicious JS] {warning} in {url}")
                    detected_patterns.append(warning)
        
        # Check for suspicious iframes - trusted sites often legitimately use iframes
        if not is_trusted:
            iframes = re.findall(self.IFRAME_PATTERN, html_content)
            if iframes and len(iframes) > 3:  # Allow a few iframes for legitimate sites
                warning = f"Found {len(iframes)} iframe(s) that could be malicious"
                logging.warning(f"[Iframe Injection] {warning} in {url}")
                detected_patterns.append(warning)
        
        # Check for potential XSS - but be more cautious with this check
        if not is_trusted:
            xss_scripts = re.findall(self.XSS_PATTERN, html_content)
            if xss_scripts and len(xss_scripts) > 5:  # Allow legitimate sites to have several scripts
                warning = f"Found {len(xss_scripts)} script tags that could be XSS attempts"
                logging.warning(f"[XSS Risk] {warning} in {url}")
                detected_patterns.append(warning)
        
        # Create result dictionary
        result = {
            'is_malicious': len(detected_patterns) > 0,
            'detected_patterns': detected_patterns,
            'analysis_time_ms': (time.time() - start_time) * 1000
        }
        
        # Update cache (simple LRU implementation)
        if len(self.cache) >= self.cache_limit:
            # Remove oldest item
            self.cache.pop(next(iter(self.cache)))
        self.cache[url] = result
        
        # Log performance metrics
        analysis_time = time.time() - start_time
        logging.info(f"Analysis completed in {analysis_time:.4f} seconds for {url}")
        
        return result
        
    def _load_whitelist(self):
        """Load whitelist patterns from whitelist.json"""
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            self.whitelist_path = os.path.join(script_dir, 'whitelist.json')
            
            if os.path.exists(self.whitelist_path):
                with open(self.whitelist_path, 'r') as f:
                    try:
                        whitelist_patterns = json.load(f)
                        print(f"DEBUG: Loaded whitelist with {len(whitelist_patterns)} patterns")
                        print(f"DEBUG: First few patterns: {list(whitelist_patterns)[:5]}")
                        
                        # Make sure we convert to a set of strings
                        self.whitelist = set(str(pattern) for pattern in whitelist_patterns)
                        logging.info(f"Loaded {len(whitelist_patterns)} whitelist patterns")
                        
                        # Explicitly add common domains
                        for domain in ["google.com", "www.google.com", "youtube.com", "facebook.com"]:
                            self.whitelist.add(domain)
                            
                    except json.JSONDecodeError as je:
                        print(f"DEBUG: JSON decode error: {je}")
                        logging.error(f"Error parsing whitelist JSON: {je}")
            else:
                logging.warning(f"Whitelist file not found at {self.whitelist_path}")
                print(f"DEBUG: Whitelist file not found at {self.whitelist_path}")
                # Initialize empty whitelist
                self.whitelist = set()
                # Add common domains
                for domain in ["google.com", "www.google.com", "youtube.com", "facebook.com"]:
                    self.whitelist.add(domain)
                # Save the whitelist file
                self.save_whitelist()
        except Exception as e:
            logging.error(f"Error loading whitelist: {e}")
            print(f"DEBUG: Error loading whitelist: {e}")
            
    def save_whitelist(self):
        """Save the current whitelist to whitelist.json"""
        try:
            # Create a sorted list from the set to ensure consistent file format
            whitelist_list = sorted(list(self.whitelist))
            
            with open(self.whitelist_path, 'w') as f:
                json.dump(whitelist_list, f, indent=2)
            logging.info(f"Saved {len(whitelist_list)} whitelist patterns to {self.whitelist_path}")
            return True
        except Exception as e:
            logging.error(f"Error saving whitelist: {e}")
            print(f"DEBUG: Error saving whitelist: {e}")
            return False
    
    def _is_whitelisted(self, host):
        """Check if a host matches any whitelist pattern"""
        # For debugging
        print(f"DEBUG: Checking if {host} is in whitelist with {len(self.whitelist)} patterns")
        
        # Direct match
        if host in self.whitelist:
            print(f"DEBUG: Found direct match for {host} in whitelist")
            return True
            
        # For common domains, hardcode the check
        common_domains = ["google.com", "youtube.com", "facebook.com", "twitter.com", "microsoft.com"]
        if host in common_domains or any(host.endswith('.' + domain) for domain in common_domains):
            print(f"DEBUG: {host} matched common trusted domain list")
            return True
            
        # Wildcard match - for each pattern that starts with *.
        for pattern in self.whitelist:
            if isinstance(pattern, str) and pattern.startswith('*.'):
                suffix = pattern[1:]
                if host.endswith(suffix):
                    print(f"DEBUG: Found wildcard match: {pattern} matches {host}")
                    return True
                    
        return False
