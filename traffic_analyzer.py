import re
import time
from mitmproxy import ctx

class TrafficAnalyzer:
    # Class variables for better performance
    PHISHING_KEYWORDS = ["login", "password", "signin", "account", "bank", "credit", "wallet", 
                        "verify", "secure", "authenticate", "paypal", "billing"]
    
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
    
    def analyze(self, flow):
        start_time = time.time()
        url = flow.request.pretty_url
        
        # Check cache first for performance
        if url in self.cache:
            ctx.log.info(f"[Cache Hit] Using cached result for {url}")
            return self.cache[url]
        
        html = flow.response.text
        html_lower = html.lower()  # Convert once for case-insensitive checks
        results = []
        
        # Fast check for phishing keywords
        if any(keyword in html_lower for keyword in self.PHISHING_KEYWORDS):
            warning = f"[Phishing Detection] Suspicious keywords found in {url}"
            ctx.log.warn(warning)
            results.append(warning)
        
        # Check for malicious JavaScript
        for pattern in self.MALICIOUS_JS_PATTERNS:
            if re.search(pattern, html):
                warning = f"[Suspicious JS] Found dangerous JS pattern in {url}"
                ctx.log.warn(warning)
                results.append(warning)
                break  # One detection is enough
        
        # Check for suspicious iframes
        iframes = re.findall(self.IFRAME_PATTERN, html)
        if iframes:
            warning = f"[Iframe Injection] Found {len(iframes)} iframes in {url}"
            ctx.log.warn(warning)
            results.append(warning)
        
        # Check for potential XSS
        if re.search(self.XSS_PATTERN, html):
            warning = f"[XSS Risk] Found script tags in {url}"
            ctx.log.warn(warning)
            results.append(warning)
        
        # Update cache (simple LRU implementation)
        if len(self.cache) >= self.cache_limit:
            # Remove oldest item
            self.cache.pop(next(iter(self.cache)))
        self.cache[url] = results
        
        # Log performance metrics
        analysis_time = time.time() - start_time
        ctx.log.info(f"Analysis completed in {analysis_time:.4f} seconds for {url}")
        
        return results
