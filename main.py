import logging
import time
import re
import urllib.parse
import os
import json
from mitmproxy import http, ctx
from log_config import setup_logging, log_metric, log_event
from traffic_analyzer import TrafficAnalyzer
from ml_detector import MLPhishingDetector

# Initialize logger
logger = setup_logging()

class SmartProxy:
    def __init__(self):
        self.analyzer = TrafficAnalyzer()
        # Initialize ML-based phishing detector with model and brands paths
        model_path = os.path.join(os.path.dirname(__file__), 'phishing_xgb_model.pkl')
        brands_path = os.path.join(os.path.dirname(__file__), 'popular_brands.txt')
        self.ml_detector = MLPhishingDetector(model_path, brands_path)
        self.whitelist = set()  # Trusted domains
        self.blacklist = set()  # Known malicious domains
        self.analyzed_urls = {}  # Track analyzed URLs and timestamps
        self.whitelisted_tabs = {}  # Track tabs with whitelisted domains
        self.bypass_tokens = {}  # Store bypass tokens for blacklisted domains
        self.config = {
            'scan_timeout_ms': 500,    # Maximum time for scanning (ms)
            'cache_duration': 3600,    # Cache results for 1 hour
            'exclude_extensions': ['.js', '.css', '.jpg', '.png', '.gif', '.svg', '.woff', '.woff2'],
            'exclude_domains': ['googleapis.com', 'gstatic.com', 'jquery.com', 'cloudflare.com'],
            'ml_confidence_threshold': 0.85  # Threshold for ML model confidence
        }
        
        # Load config if exists
        self._load_config()
        # Load whitelist
        self._load_whitelist()
        ctx.log.info("Smart Proxy initialized with config:")
        ctx.log.info(json.dumps(self.config, indent=2))
    
    def _load_config(self):
        """Load config from file if exists"""
        config_path = os.path.join(os.path.dirname(__file__), 'config.json')
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    self.config.update(user_config)
                    ctx.log.info("Config loaded from config.json")
        except Exception as e:
            ctx.log.error(f"Error loading config: {e}")
            
    def _load_whitelist(self):
        """Load whitelist patterns from file"""
        whitelist_path = os.path.join(os.path.dirname(__file__), 'whitelist.json')
        try:
            if os.path.exists(whitelist_path):
                with open(whitelist_path, 'r') as f:
                    patterns = json.load(f)
                    # Add patterns directly to whitelist set
                    self.whitelist.update(patterns)
                    ctx.log.info(f"Loaded {len(patterns)} whitelist patterns from whitelist.json")
            else:
                ctx.log.warn("whitelist.json not found. Running without whitelist.")
        except Exception as e:
            ctx.log.error(f"Error loading whitelist: {e}")
            
    def _is_whitelisted(self, host):
        """Check if a host matches any whitelist pattern"""
        # Direct match
        if host in self.whitelist:
            return True
            
        # Wildcard match (for patterns like *.google.com)
        for pattern in self.whitelist:
            if pattern.startswith('*.'):
                suffix = pattern[1:]  # Remove the '*'
                if host.endswith(suffix):
                    return True
                    
        return False

    def request(self, flow):
        # Fast path: Skip known file extensions
        url = flow.request.pretty_url
        path = flow.request.path
        host = flow.request.host
        client_id = flow.client_conn.id
        
        # Log request metrics for Grafana
        log_metric(logger, "request", 1, {
            "host": host,
            "client_id": client_id,
            "path_type": "bypass" if path.startswith('/bypass') else "standard"
        })
        
        # Check if this is a bypass request
        if path.startswith('/bypass'):
            ctx.log.info(f"Received bypass request: {url}")
            
            # Extract full path and query
            full_url = url
            ctx.log.info(f"Full URL: {full_url}")
            
            # Most reliable way to get the bypass token is to extract it from the raw URL
            token = None
            # Regular token extraction
            if '?token=' in full_url:
                try:
                    token = full_url.split('?token=')[1].split('&')[0]
                    ctx.log.info(f"Extracted token from URL: {token}")
                except Exception as e:
                    ctx.log.error(f"Error extracting token from URL: {e}")
            
            # Debug: Show all available tokens
            ctx.log.info(f"Available tokens: {list(self.bypass_tokens.keys())}")
            
            # Find matching token even if it's not exact
            matched_token = None
            if token:
                for existing_token in self.bypass_tokens:
                    if existing_token == token:
                        matched_token = existing_token
                        break
                    # Partial match for malformed URLs
                    elif existing_token.startswith(host) and token.startswith(host):
                        matched_token = existing_token
                        break
            
            if matched_token:
                token = matched_token
                # Get the domain associated with this token
                bypass_domain = self.bypass_tokens[token]
                ctx.log.warn(f"Bypass granted for domain: {bypass_domain}")
                
                # Create temporary whitelist for this client
                client_id = flow.client_conn.id
                self.whitelisted_tabs[client_id] = bypass_domain
                
                # Log successful bypass for Grafana
                log_event(logger, "bypass_granted", {
                    "client_id": client_id,
                    "domain": bypass_domain
                })
                
                # Create a redirect response - use the same protocol (http/https) as original request
                protocol = "https" if flow.request.scheme == "https" else "http"
                redirect_url = f"{protocol}://{bypass_domain}"
                ctx.log.info(f"Redirecting to: {redirect_url}")
                
                flow.response = http.Response.make(
                    302, 
                    b"", 
                    {"Location": redirect_url, "Content-Type": "text/html"}
                )
                
                # Clean up used token
                del self.bypass_tokens[token]
                ctx.log.info(f"Removed used token {token}")
                return
            else:
                # Invalid token
                ctx.log.warn(f"Invalid bypass token request. URL: {full_url}")
                error_html = f"""
                <html>
                <head>
                    <title>Invalid Bypass Request</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f8f9fa; }}
                        .container {{ max-width: 800px; margin: 50px auto; padding: 30px; background-color: white; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                        h1 {{ color: #d9534f; }}
                        pre {{ background: #f5f5f5; padding: 10px; overflow-x: auto; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>Invalid Bypass Request</h1>
                        <p>The bypass token you provided is invalid or has expired.</p>
                        <p><strong>Available tokens:</strong></p>
                        <pre>{', '.join(self.bypass_tokens.keys()) or 'None'}</pre>
                        <p><a href="javascript:history.back()">Go back</a></p>
                    </div>
                </body>
                </html>
                """
                flow.response = http.Response.make(
                    400,
                    error_html.encode('utf-8'),
                    {"Content-Type": "text/html"}
                )
                return
        
        # Get tab or window ID from client connection
        client_id = flow.client_conn.id
        
        # Check if this client is already associated with a whitelisted domain
        if client_id in self.whitelisted_tabs:
            ctx.log.info(f"Allowing request from whitelisted tab: {url}")
            flow.metadata["skip_analysis"] = True
            return
        
        # Check if host matches any whitelist pattern
        if self._is_whitelisted(host):
            ctx.log.info(f"Host {host} is in whitelist, marking tab as trusted")
            # Mark this tab/client as trusted for future requests
            self.whitelisted_tabs[client_id] = host
            flow.metadata["skip_analysis"] = True
            return
        
        # Block blacklisted domains immediately
        if host in self.blacklist:
            # Create a unique bypass token for this host - make sure to create one that's unique
            # but consistent for the same domain during a short time window
            timestamp = int(time.time()) // 10 * 10  # Round to nearest 10 seconds for stability
            bypass_token = f"{host}_{timestamp}"
            self.bypass_tokens[bypass_token] = host
            # Log token for debugging
            ctx.log.info(f"Created bypass token for {host}: {bypass_token}")
            
            # Create a more informative block page with bypass option
            block_html = f"""
            <html>
            <head>
                <title>Security Warning - Access Blocked</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f8f9fa; }}
                    .container {{ max-width: 800px; margin: 50px auto; padding: 30px; background-color: white; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                    h1 {{ color: #d9534f; }}
                    .alert {{ background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                    .info {{ background-color: #e2e3e5; border: 1px solid #d6d8db; color: #383d41; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                    .detection-method {{ font-weight: bold; }}
                    .btn {{ display: inline-block; padding: 10px 15px; background-color: #6c757d; color: white; text-decoration: none; border-radius: 5px; margin-right: 10px; }}
                    .btn-danger {{ background-color: #dc3545; }}
                    .btn:hover {{ opacity: 0.9; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Access Blocked</h1>
                    <div class="alert">
                        <p><strong>Warning:</strong> This site has been flagged as potentially malicious.</p>
                    </div>
                    <div class="info">
                        <p><span class="detection-method">Detection Method:</span> Domain Blacklist</p>
                        <p><span class="detection-method">Domain:</span> {host}</p>
                        <p>This site has been manually added to our blacklist of known malicious websites.</p>
                    </div>
                    <p>If you believe this is a mistake, you can:</p>
                    <a href="/" class="btn">Go Back</a>
                    <a href="/bypass?token={bypass_token}" class="btn btn-danger">Proceed Anyway (Not Recommended)</a>
                    <p><small>Note: Proceeding to blocked sites may put your data and device at risk.</small></p>
                </div>
            </body>
            </html>
            """
            
            flow.response = http.Response.make(
                403,
                block_html.encode('utf-8'),
                {"Content-Type": "text/html"}
            )
            return
            
        # Skip non-HTML resource types by extension
        if any(path.endswith(ext) for ext in self.config['exclude_extensions']):
            flow.metadata["skip_analysis"] = True
            return
            
        # Skip resource domains
        if any(domain in host for domain in self.config['exclude_domains']):
            flow.metadata["skip_analysis"] = True
            return
            
        # Skip non-HTML requests based on headers
        accept_header = flow.request.headers.get("accept", "")
        if "text/html" not in accept_header and "*/*" not in accept_header:
            flow.metadata["skip_analysis"] = True

    def response(self, flow):
        if flow.metadata.get("skip_analysis", False):
            return
        
        # Double-check the host against whitelist before analyzing
        host = flow.request.host
        client_id = flow.client_conn.id
        
        # If host is whitelisted or client_id is in whitelisted_tabs, skip analysis
        if self._is_whitelisted(host) or client_id in self.whitelisted_tabs:
            flow.metadata["skip_analysis"] = True
            return
        
        # Check content type - only analyze HTML
        content_type = flow.response.headers.get("content-type", "")
        if not content_type.startswith("text/html"):
            # Log skipped content types for Grafana
            log_metric(logger, "skipped_content", 1, {"content_type": content_type.split(';')[0]})
            return
        
        # Skip if response is too large (for performance)
        if len(flow.response.content) > 1000000:  # 1MB limit
            ctx.log.info(f"Skipping large page: {flow.request.pretty_url.rstrip('/')} ({len(flow.response.content)} bytes)")
            return
        
        # Performance tracking
        start_time = time.time()
        
        # Run ML-based detection first
        try:
            # Get URL and strip trailing slash if present
            url = flow.request.pretty_url.rstrip('/')
            html_content = flow.response.text
            is_phishing, confidence, ml_time_ms = self.ml_detector.predict(url, html_content)
            
            # Log ML detection results
            ctx.log.info(f"ML detection: {ml_time_ms*1000:.2f}ms, confidence: {confidence:.4f}, is_phishing: {is_phishing}")
            
            # If ML detection says it's phishing with high confidence
            if is_phishing and confidence > self.config['ml_confidence_threshold']:
                ctx.log.warn(f"ML Phishing detected: {flow.request.pretty_url} with {confidence*100:.1f}% confidence")
                
                # Log ML phishing detection for Grafana
                log_event(logger, "ml_phishing_detected", {
                    "url": flow.request.pretty_url,
                    "host": flow.request.host,
                    "confidence": float(confidence),
                    "client_id": flow.client_conn.id
                })
                
                # Remove trailing slash for URL in logs
                clean_url = url.rstrip('/')
                ctx.log.warn(f"[ML-PHISHING] High confidence phishing detected: {clean_url} ({confidence:.4f})")
                self.blacklist.add(flow.request.host)
                # Create a unique bypass token for this host - make sure to create one that's unique
                # but consistent for the same domain during a short time window
                timestamp = int(time.time()) // 10 * 10  # Round to nearest 10 seconds for stability
                bypass_token = f"{host}_{timestamp}"
                self.bypass_tokens[bypass_token] = host
                # Log token for debugging
                ctx.log.info(f"Created bypass token for {host}: {bypass_token}")
                
                # Create detailed blocked page with styled information
                blocked_page = f"""
                <html>
                <head>
                    <title>Phishing Site Blocked</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px; }}
                        h1 {{ color: #d32f2f; text-align: center; }}
                        .warning-box {{ background-color: #ffebee; border: 1px solid #ffcdd2; padding: 20px; border-radius: 4px; margin-bottom: 20px; }}
                        .info-box {{ background-color: #e3f2fd; border: 1px solid #bbdefb; padding: 20px; border-radius: 4px; }}
                        .detection-method {{ font-weight: bold; color: #d32f2f; }}
                        .confidence {{ font-size: 1.2em; font-weight: bold; }}
                        .details {{ margin-top: 20px; }}
                        .url {{ word-break: break-all; font-family: monospace; background: #f5f5f5; padding: 10px; }}
                        .actions {{ margin-top: 30px; text-align: center; }}
                        .btn {{ display: inline-block; padding: 10px 15px; background-color: #6c757d; color: white; text-decoration: none; border-radius: 5px; margin-right: 10px; }}
                        .btn-danger {{ background-color: #dc3545; }}
                        .btn:hover {{ opacity: 0.9; }}
                    </style>
                </head>
                <body>
                    <div class="warning-box">
                        <h1>Phishing Site Blocked</h1>
                        <p>This site has been detected as a phishing attempt with <span class="confidence">{confidence*100:.2f}%</span> confidence.</p>
                    </div>
                    
                    <div class="info-box">
                        <h2>Detection Details</h2>
                        <p><strong>Detection Method:</strong> <span class="detection-method">Machine Learning Model</span></p>
                        <p><strong>URL:</strong> <div class="url">{flow.request.pretty_url.rstrip('/')}</div></p>
                        <p><strong>ML Confidence:</strong> {confidence*100:.2f}%</p>
                        <p><strong>Detection Time:</strong> {ml_time_ms*1000:.2f} ms</p>
                        
                        <div class="details">
                            <h3>Why was this blocked?</h3>
                            <p>Our machine learning model has identified this site as likely phishing based on multiple factors including URL structure, domain characteristics, and content analysis.</p>
                            <p>This site has been added to the blacklist to protect you from potential credential theft or other malicious activity.</p>
                        </div>
                    </div>
                    
                    <div class="actions">
                        <p>If you believe this is a false positive:</p>
                        <a href="/" class="btn">Go Back</a>
                        <a href="/bypass?token={bypass_token}" class="btn btn-danger">Proceed Anyway (Not Recommended)</a>
                        <p><small>Note: Proceeding to blocked sites may put your data and device at risk.</small></p>
                    </div>
                </body>
                </html>
                """
                
                flow.response = http.Response.make(
                    403,
                    blocked_page.encode(),
                    {"Content-Type": "text/html"}
                )
                return
            
            # Only proceed to detailed analysis if ML detection isn't confident
            if not is_phishing or confidence < self.config['ml_confidence_threshold']:
                # Run traditional analysis
                analysis_results = self.analyzer.analyze(flow)
                
                # If serious issues found, add to blacklist
                if len(analysis_results) > 2:  # Multiple security issues
                    ctx.log.warn(f"Multiple security issues in {flow.request.host} - adding to blacklist")
                    self.blacklist.add(flow.request.host)
                    
                    # Create a unique bypass token for this host - make sure to create one that's unique
                    # but consistent for the same domain during a short time window
                    timestamp = int(time.time()) // 10 * 10  # Round to nearest 10 seconds for stability
                    bypass_token = f"{host}_{timestamp}"
                    self.bypass_tokens[bypass_token] = host
                    # Log token for debugging
                    ctx.log.info(f"Created bypass token for {host}: {bypass_token}")

                    # Create detailed blocked page with styled information for traditional detection
                    blocked_page = f"""
                    <html>
                    <head>
                        <title>Phishing Site Blocked</title>
                        <style>
                            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px; }}
                            h1 {{ color: #d32f2f; text-align: center; }}
                            .warning-box {{ background-color: #ffebee; border: 1px solid #ffcdd2; padding: 20px; border-radius: 4px; margin-bottom: 20px; }}
                            .info-box {{ background-color: #e3f2fd; border: 1px solid #bbdefb; padding: 20px; border-radius: 4px; }}
                            .detection-method {{ font-weight: bold; color: #2e7d32; }}
                            .issues {{ font-family: monospace; background: #f5f5f5; padding: 10px; }}
                            .details {{ margin-top: 20px; }}
                            .url {{ word-break: break-all; font-family: monospace; background: #f5f5f5; padding: 10px; }}
                            li {{ margin-bottom: 8px; }}
                            .actions {{ margin-top: 30px; text-align: center; }}
                            .btn {{ display: inline-block; padding: 10px 15px; background-color: #6c757d; color: white; text-decoration: none; border-radius: 5px; margin-right: 10px; }}
                            .btn-danger {{ background-color: #dc3545; }}
                            .btn:hover {{ opacity: 0.9; }}
                        </style>
                    </head>
                    <body>
                        <div class="warning-box">
                            <h1>Phishing Site Blocked</h1>
                            <p>This site has been detected as a phishing attempt based on multiple suspicious patterns.</p>
                        </div>
                        
                        <div class="info-box">
                            <h2>Detection Details</h2>
                            <p><strong>Detection Method:</strong> <span class="detection-method">Traditional Pattern Analysis</span></p>
                            <p><strong>URL:</strong> <div class="url">{flow.request.pretty_url.rstrip('/')}</div></p>
                            <p><strong>ML Confidence:</strong> {confidence*100:.2f}% (below threshold)</p>
                            
                            <div class="details">
                                <h3>Detected Issues:</h3>
                                <div class="issues">
                                    <ul>
                                        {''.join([f'<li>{issue}</li>' for issue in analysis_results])}
                                    </ul>
                                </div>
                                
                                <h3>Why was this blocked?</h3>
                                <p>Our security system detected multiple suspicious patterns that are commonly associated with phishing websites.</p>
                                <p>This site has been added to the blacklist to protect you from potential credential theft or other malicious activity.</p>
                            </div>
                        </div>
                        
                        <div class="actions">
                            <p>If you believe this is a false positive:</p>
                            <a href="/" class="btn">Go Back</a>
                            <a href="/bypass?token={bypass_token}" class="btn btn-danger">Proceed Anyway (Not Recommended)</a>
                            <p><small>Note: Proceeding to blocked sites may put your data and device at risk.</small></p>
                        </div>
                    </body>
                    </html>
                    """
                    
                    flow.response = http.Response.make(
                        403,
                        blocked_page.encode(),
                        {"Content-Type": "text/html"}
                    )
                    return
                
        except Exception as e:
            ctx.log.error(f"Error analyzing {flow.request.pretty_url}: {e}")
        
        # Report performance
        analysis_time = (time.time() - start_time) * 1000  # in ms
        if analysis_time > self.config['scan_timeout_ms']:
            ctx.log.warn(f"Slow analysis: {analysis_time:.1f}ms for {flow.request.pretty_url}")
        else:
            ctx.log.info(f"Fast analysis: {analysis_time:.1f}ms for {flow.request.pretty_url}")
            
        # Log performance metrics for Grafana
        log_metric(logger, "analysis_time_ms", float(analysis_time), {
            "url": flow.request.pretty_url,
            "host": flow.request.host,
            "is_slow": analysis_time > self.config['scan_timeout_ms']
        })

addons = [SmartProxy()]
