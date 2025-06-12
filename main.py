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
        print("Smart Proxy initialized with config:")
        print(json.dumps(self.config, indent=2))
    
    def _load_config(self):
        """Load config from file if exists"""
        config_path = os.path.join(os.path.dirname(__file__), 'config.json')
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    self.config.update(user_config)
                    print("Config loaded from config.json")
        except Exception as e:
            print(f"Error loading config: {e}")
            
    def _load_whitelist(self):
        """Load whitelist patterns from file"""
        whitelist_path = os.path.join(os.path.dirname(__file__), 'whitelist.json')
        try:
            if os.path.exists(whitelist_path):
                with open(whitelist_path, 'r') as f:
                    patterns = json.load(f)
                    # Add patterns directly to whitelist set
                    self.whitelist.update(patterns)
                    print(f"Loaded {len(patterns)} whitelist patterns from whitelist.json")
            else:
                print("whitelist.json not found. Running without whitelist.")
        except Exception as e:
            print(f"Error loading whitelist: {e}")
            
    def _is_whitelisted(self, host):
        """Check if a host matches any whitelist pattern"""
        # Direct match
        if host in self.whitelist:
            ctx.log.info(f"Exact match found for {host} in whitelist")
            return True
            
        # Wildcard match (for patterns like *.google.com)
        for pattern in self.whitelist:
            if pattern.startswith('*.'):
                # Extract the domain without the wildcard
                domain_part = pattern[2:] # Remove the '*.' prefix
                
                # Match either the exact domain or any subdomain
                if host == domain_part or host.endswith('.' + domain_part):
                    ctx.log.info(f"Wildcard match: {host} matches pattern {pattern}")
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
            
            # Use cybersecurity-themed blocked page
            try:
                with open('threat_message.html', 'r', encoding='utf-8') as f:
                    threat_template = f.read()

                # Replace placeholders with actual values for blacklist detection
                blocked_url = flow.request.pretty_url.rstrip('/')
                block_html = threat_template.replace('<!-- URL will be inserted here -->', blocked_url)

                # Update the title and description for blacklist detection
                block_html = block_html.replace('PHISHING WEBSITE BLOCKED', 'BLACKLISTED WEBSITE BLOCKED')
                block_html = block_html.replace('phishing site', 'blacklisted site')
                block_html = block_html.replace('Machine Learning analysis detected suspicious patterns',
                                              'Domain blacklist detection - manually flagged as malicious')

                # Add URL parameters for JavaScript
                block_html = block_html.replace('window.location.search',
                                              f"'?url={blocked_url}&method=blacklist&bypass={bypass_token}'")

            except FileNotFoundError:
                # Fallback to cybersecurity-themed blocked page
                block_html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>⚠️ ACCESS BLOCKED - Smart Proxy</title>
                    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
                    <style>
                        body {{
                            font-family: 'Segoe UI', sans-serif;
                            background: linear-gradient(135deg, #1a0000 0%, #330000 50%, #1a0000 100%);
                            color: white;
                            text-align: center;
                            padding: 50px;
                            margin: 0;
                            min-height: 100vh;
                        }}
                        .threat-container {{
                            max-width: 800px;
                            margin: 0 auto;
                            background: rgba(0,0,0,0.9);
                            padding: 40px;
                            border-radius: 20px;
                            border: 2px solid #ff0000;
                            box-shadow: 0 0 30px rgba(255,0,0,0.3);
                            backdrop-filter: blur(15px);
                        }}
                        h1 {{
                            color: #ff0000;
                            font-size: 2.5rem;
                            margin-bottom: 20px;
                            text-shadow: 0 0 10px rgba(255,0,0,0.5);
                            animation: textGlow 2s ease-in-out infinite;
                        }}
                        @keyframes textGlow {{
                            0%, 100% {{ text-shadow: 0 0 10px rgba(255,0,0,0.5); }}
                            50% {{ text-shadow: 0 0 20px rgba(255,0,0,0.8); }}
                        }}
                        .warning-icon {{
                            font-size: 4rem;
                            color: #ff0000;
                            margin-bottom: 20px;
                            animation: pulse 1.5s infinite;
                        }}
                        @keyframes pulse {{
                            0%, 100% {{ transform: scale(1); }}
                            50% {{ transform: scale(1.1); }}
                        }}
                        .url-display {{
                            background: rgba(255,0,0,0.1);
                            border: 2px solid #ff0000;
                            padding: 15px;
                            margin: 20px 0;
                            border-radius: 10px;
                            word-break: break-all;
                            font-family: monospace;
                            color: #ff6666;
                        }}
                        .detection-info {{
                            background: rgba(255,0,0,0.05);
                            border-left: 4px solid #ff0000;
                            padding: 15px;
                            margin: 20px 0;
                            text-align: left;
                            border-radius: 8px;
                        }}
                        .btn {{
                            display: inline-block;
                            padding: 15px 30px;
                            margin: 10px;
                            border-radius: 10px;
                            text-decoration: none;
                            font-weight: bold;
                            transition: all 0.3s;
                            border: none;
                            cursor: pointer;
                        }}
                        .btn-safe {{
                            background: linear-gradient(135deg, #10b981, #34d399);
                            color: white;
                        }}
                        .btn-danger {{
                            background: linear-gradient(135deg, #ef4444, #f87171);
                            color: white;
                        }}
                        .btn:hover {{ transform: translateY(-2px); }}
                    </style>
                </head>
                <body>
                    <div class="threat-container">
                        <div class="warning-icon">🛡️</div>
                        <h1>BLACKLISTED WEBSITE BLOCKED</h1>
                        <p>This website has been manually flagged as malicious and added to our security blacklist.</p>
                        <div class="url-display">{flow.request.pretty_url.rstrip('/')}</div>
                        <div class="detection-info">
                            <h3>🚨 Detection Details:</h3>
                            <p><strong>Detection Method:</strong> Domain Blacklist</p>
                            <p><strong>Domain:</strong> {host}</p>
                            <p><strong>Status:</strong> Manually flagged as malicious</p>
                            <p>This site has been identified as potentially harmful and blocked to protect your security.</p>
                        </div>
                        <div style="margin-top: 30px;">
                            <a href="javascript:history.back()" class="btn btn-safe">🛡️ Go Back Safely</a>
                            <a href="{flow.request.pretty_url.rstrip('/')}?bypass={bypass_token}" class="btn btn-danger">⚠️ Proceed Anyway (Risky)</a>
                        </div>
                        <p style="margin-top: 20px; font-size: 0.9rem; color: #ccc;">
                            Protected by Smart Proxy Security System
                        </p>
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
            # Log that this domain was skipped due to whitelist
            ctx.log.info(f"Skipping analysis for whitelisted domain: {host}")
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
                
                # Only add to blacklist if not in whitelist
                if not self._is_whitelisted(flow.request.host):
                    self.blacklist.add(flow.request.host)
                else:
                    ctx.log.info(f"Domain {flow.request.host} flagged by ML but is whitelisted, not adding to blacklist")
                # Create a unique bypass token for this host - make sure to create one that's unique
                # but consistent for the same domain during a short time window
                timestamp = int(time.time()) // 10 * 10  # Round to nearest 10 seconds for stability
                bypass_token = f"{host}_{timestamp}"
                self.bypass_tokens[bypass_token] = host
                # Log token for debugging
                ctx.log.info(f"Created bypass token for {host}: {bypass_token}")
                
                # Load the cybersecurity-themed threat message
                try:
                    with open('threat_message.html', 'r', encoding='utf-8') as f:
                        threat_template = f.read()

                    # Replace placeholders with actual values
                    blocked_page = threat_template.replace('<!-- URL will be inserted here -->',
                                                         flow.request.pretty_url.rstrip('/'))

                    # Add URL parameters for JavaScript to use
                    clean_url = flow.request.pretty_url.rstrip('/')
                    blocked_page = blocked_page.replace('window.location.search',
                                                      f"'?url={clean_url}&confidence={confidence}&bypass={bypass_token}'")

                except FileNotFoundError:
                    # Fallback to basic threat message if template not found
                    blocked_page = f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>⚠️ SECURITY THREAT DETECTED</title>
                        <style>
                            body {{
                                font-family: 'Segoe UI', sans-serif;
                                background: linear-gradient(135deg, #1a0000 0%, #330000 50%, #1a0000 100%);
                                color: white;
                                text-align: center;
                                padding: 50px;
                                margin: 0;
                            }}
                            .threat-container {{
                                max-width: 800px;
                                margin: 0 auto;
                                background: rgba(0,0,0,0.8);
                                padding: 40px;
                                border-radius: 20px;
                                border: 2px solid #ff0000;
                                box-shadow: 0 0 30px rgba(255,0,0,0.3);
                            }}
                            h1 {{
                                color: #ff0000;
                                font-size: 2.5rem;
                                margin-bottom: 20px;
                                text-shadow: 0 0 10px rgba(255,0,0,0.5);
                            }}
                            .warning-icon {{
                                font-size: 4rem;
                                color: #ff0000;
                                margin-bottom: 20px;
                                animation: pulse 1.5s infinite;
                            }}
                            @keyframes pulse {{
                                0%, 100% {{ transform: scale(1); }}
                                50% {{ transform: scale(1.1); }}
                            }}
                            .url-display {{
                                background: rgba(255,0,0,0.1);
                                border: 2px solid #ff0000;
                                padding: 15px;
                                margin: 20px 0;
                                border-radius: 10px;
                                word-break: break-all;
                                font-family: monospace;
                            }}
                            .btn {{
                                display: inline-block;
                                padding: 15px 30px;
                                margin: 10px;
                                border-radius: 10px;
                                text-decoration: none;
                                font-weight: bold;
                                transition: all 0.3s;
                            }}
                            .btn-safe {{
                                background: linear-gradient(135deg, #10b981, #34d399);
                                color: white;
                            }}
                            .btn-danger {{
                                background: linear-gradient(135deg, #ef4444, #f87171);
                                color: white;
                            }}
                            .btn:hover {{ transform: translateY(-2px); }}
                        </style>
                    </head>
                    <body>
                        <div class="threat-container">
                            <div class="warning-icon">⚠️</div>
                            <h1>PHISHING WEBSITE BLOCKED</h1>
                            <p>Our AI security system detected this site as a phishing threat with <strong>{confidence*100:.1f}%</strong> confidence.</p>
                            <div class="url-display">{clean_url}</div>
                            <p>This website may steal your passwords, personal information, or install malware on your device.</p>
                            <div style="margin-top: 30px;">
                                <a href="javascript:history.back()" class="btn btn-safe">🛡️ Go Back Safely</a>
                                <a href="{clean_url}?bypass={bypass_token}" class="btn btn-danger">⚠️ Proceed Anyway (Risky)</a>
                            </div>
                            <p style="margin-top: 20px; font-size: 0.9rem; color: #ccc;">
                                Protected by Smart Proxy Advanced Threat Detection
                            </p>
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

                    # Use the same cybersecurity-themed threat message for traditional detection
                    try:
                        with open('threat_message.html', 'r', encoding='utf-8') as f:
                            threat_template = f.read()

                        # Replace placeholders with actual values
                        blocked_page = threat_template.replace('<!-- URL will be inserted here -->',
                                                             flow.request.pretty_url.rstrip('/'))

                        # Add URL parameters for JavaScript to use
                        clean_url = flow.request.pretty_url.rstrip('/')
                        blocked_page = blocked_page.replace('window.location.search',
                                                          f"'?url={clean_url}&confidence={confidence}&bypass={bypass_token}&patterns={','.join(analysis_results)}'")

                        # Add detected patterns to the threat details
                        patterns_html = ''.join([f'<li><i class="fas fa-exclamation-circle"></i> {pattern}</li>' for pattern in analysis_results])
                        blocked_page = blocked_page.replace('<!-- Detected patterns will be inserted here -->', patterns_html)

                    except FileNotFoundError:
                        # Fallback to basic threat message for traditional detection
                        blocked_page = f"""
                        <!DOCTYPE html>
                        <html>
                        <head>
                            <title>⚠️ SECURITY THREAT DETECTED</title>
                            <style>
                                body {{
                                    font-family: 'Segoe UI', sans-serif;
                                    background: linear-gradient(135deg, #1a0000 0%, #330000 50%, #1a0000 100%);
                                    color: white;
                                    text-align: center;
                                    padding: 50px;
                                    margin: 0;
                                }}
                                .threat-container {{
                                    max-width: 800px;
                                    margin: 0 auto;
                                    background: rgba(0,0,0,0.8);
                                    padding: 40px;
                                    border-radius: 20px;
                                    border: 2px solid #ff0000;
                                    box-shadow: 0 0 30px rgba(255,0,0,0.3);
                                }}
                                h1 {{
                                    color: #ff0000;
                                    font-size: 2.5rem;
                                    margin-bottom: 20px;
                                    text-shadow: 0 0 10px rgba(255,0,0,0.5);
                                }}
                                .warning-icon {{
                                    font-size: 4rem;
                                    color: #ff0000;
                                    margin-bottom: 20px;
                                    animation: pulse 1.5s infinite;
                                }}
                                @keyframes pulse {{
                                    0%, 100% {{ transform: scale(1); }}
                                    50% {{ transform: scale(1.1); }}
                                }}
                                .url-display {{
                                    background: rgba(255,0,0,0.1);
                                    border: 2px solid #ff0000;
                                    padding: 15px;
                                    margin: 20px 0;
                                    border-radius: 10px;
                                    word-break: break-all;
                                    font-family: monospace;
                                }}
                                .patterns {{
                                    background: rgba(255,0,0,0.05);
                                    border-left: 4px solid #ff0000;
                                    padding: 15px;
                                    margin: 20px 0;
                                    text-align: left;
                                }}
                                .btn {{
                                    display: inline-block;
                                    padding: 15px 30px;
                                    margin: 10px;
                                    border-radius: 10px;
                                    text-decoration: none;
                                    font-weight: bold;
                                    transition: all 0.3s;
                                }}
                                .btn-safe {{
                                    background: linear-gradient(135deg, #10b981, #34d399);
                                    color: white;
                                }}
                                .btn-danger {{
                                    background: linear-gradient(135deg, #ef4444, #f87171);
                                    color: white;
                                }}
                                .btn:hover {{ transform: translateY(-2px); }}
                            </style>
                        </head>
                        <body>
                            <div class="threat-container">
                                <div class="warning-icon">🛡️</div>
                                <h1>SUSPICIOUS WEBSITE BLOCKED</h1>
                                <p>Our pattern analysis system detected multiple security threats on this website.</p>
                                <div class="url-display">{flow.request.pretty_url.rstrip('/')}</div>
                                <div class="patterns">
                                    <h3>🚨 Detected Threat Patterns:</h3>
                                    <ul>
                                        {''.join([f'<li>• {issue}</li>' for issue in analysis_results])}
                                    </ul>
                                </div>
                                <p>This website may be attempting to steal your information or compromise your security.</p>
                                <div style="margin-top: 30px;">
                                    <a href="javascript:history.back()" class="btn btn-safe">🛡️ Go Back Safely</a>
                                    <a href="{flow.request.pretty_url.rstrip('/')}?bypass={bypass_token}" class="btn btn-danger">⚠️ Proceed Anyway (Risky)</a>
                                </div>
                                <p style="margin-top: 20px; font-size: 0.9rem; color: #ccc;">
                                    Protected by Smart Proxy Pattern Analysis Engine
                                </p>
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
