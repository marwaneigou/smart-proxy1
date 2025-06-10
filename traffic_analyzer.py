import re
import time
import urllib.parse
from mitmproxy import ctx
from log_config import setup_logging, log_metric, log_event

# Initialize logger
logger = setup_logging()

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
            
            # Log cache hit metrics for Grafana
            log_metric(logger, "analyzer_cache_hit", 1, {
                "url": url,
                "domain": urllib.parse.urlparse(url).netloc
            })
            
            return self.cache[url]
        
        html = flow.response.text
        html_lower = html.lower()  # Convert once for case-insensitive checks
        results = []
        
        # Fast check for phishing keywords
        detected_keywords = [k for k in self.PHISHING_KEYWORDS if k in html_lower]
        if detected_keywords:
            warning = f"[Phishing Detection] Suspicious keywords found in {url}"
            ctx.log.warn(warning)
            results.append(warning)
            
            # Log phishing keyword detection for Grafana
            log_event(logger, "phishing_keywords_detected", {
                "url": url,
                "domain": urllib.parse.urlparse(url).netloc,
                "keyword_count": len(detected_keywords),
                "keywords": ",".join(detected_keywords[:5])  # Log first 5 keywords
            })
        
        # Check for malicious JavaScript
        js_pattern_detected = False
        detected_pattern = ""
        
        for pattern in self.MALICIOUS_JS_PATTERNS:
            if re.search(pattern, html):
                js_pattern_detected = True
                detected_pattern = pattern
                warning = f"[Suspicious JS] Found dangerous JS pattern in {url}"
                ctx.log.warn(warning)
                results.append(warning)
                
                # Log JavaScript pattern detection for Grafana
                log_event(logger, "malicious_js_detected", {
                    "url": url,
                    "domain": urllib.parse.urlparse(url).netloc,
                    "pattern_type": "eval" if "eval" in pattern else "document_write" if "write" in pattern else "location_redirect"
                })
                
                break  # One detection is enough
        
        # Check for suspicious iframes
        iframes = re.findall(self.IFRAME_PATTERN, html)
        if iframes:
            warning = f"[Iframe Injection] Found {len(iframes)} iframes in {url}"
            ctx.log.warn(warning)
            results.append(warning)
            
            # Log iframe detection for Grafana
            log_event(logger, "iframe_detected", {
                "url": url,
                "domain": urllib.parse.urlparse(url).netloc,
                "iframe_count": len(iframes),
                "iframe_sources": ",".join([urllib.parse.urlparse(src).netloc for src in iframes[:3]])  # Log first 3 iframe sources
            })
        
        # Check for potential XSS
        xss_matches = re.findall(self.XSS_PATTERN, html)
        if xss_matches:
            warning = f"[XSS Risk] Found {len(xss_matches)} script tags in {url}"
            ctx.log.warn(warning)
            results.append(warning)
            
            # Log XSS detection for Grafana
            log_event(logger, "xss_detected", {
                "url": url,
                "domain": urllib.parse.urlparse(url).netloc,
                "script_count": len(xss_matches)
            })
        
        # Update cache (simple LRU implementation)
        if len(self.cache) >= self.cache_limit:
            # Remove oldest item
            self.cache.pop(next(iter(self.cache)))
        self.cache[url] = results
        
        # Log performance metrics
        analysis_time = time.time() - start_time
        ctx.log.info(f"Analysis completed in {analysis_time:.4f} seconds for {url}")
        
        # Log performance and results for Grafana
        log_metric(logger, "analyzer_time_seconds", float(analysis_time), {
            "url": url,
            "domain": urllib.parse.urlparse(url).netloc,
            "hit_count": len(results),
            "is_phishing": len(results) > 0
        })
        
        # Log analysis result
        if results:
            log_event(logger, "traffic_analyzer_detection", {
                "url": url,
                "domain": urllib.parse.urlparse(url).netloc,
                "detection_count": len(results),
                "detection_types": ",".join([r.split("]")[0][1:] for r in results])
            })
        
        return results
