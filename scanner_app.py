from flask import Flask, request, render_template, jsonify, redirect, url_for
import requests
from urllib.parse import urlparse
import os
import urllib3

# Disable SSL warnings for scanning purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import json
from ml_detector import MLPhishingDetector
from scanner_analyzer import ScannerAnalyzer
import math
import time
from log_config import setup_logging, log_metric, log_event

# Initialize logger for web app
logger = setup_logging(log_dir="logs", log_level=20)  # INFO level

app = Flask(__name__)

# Load configuration
with open('config.json', 'r') as f:
    config = json.load(f)

# Initialize detectors
script_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(script_dir, config.get('ml_model_path', 'phishing_xgb_model.pkl'))
brands_path = os.path.join(script_dir, config.get('popular_brands_path', 'popular_brands.txt'))
whitelist_path = os.path.join(script_dir, 'whitelist.json')

# Note: ScannerAnalyzer now handles whitelist loading and checking

ml_detector = MLPhishingDetector(model_path, brands_path)
ml_detector.confidence_threshold = config.get('ml_confidence_threshold', 0.85)
traffic_analyzer = ScannerAnalyzer()

# Make sure to initialize the whitelist in ScannerAnalyzer
traffic_analyzer._load_whitelist()

@app.route('/')
def index():
    return render_template('index.html')
    
@app.route('/whitelist')
def whitelist_manager():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    search = request.args.get('search', '')
    
    # Convert whitelist set to a sorted list for easier pagination
    whitelist = list(sorted(traffic_analyzer.whitelist))
    
    # Filter by search term if provided
    if search:
        whitelist = [domain for domain in whitelist if search.lower() in domain.lower()]
    
    # Calculate pagination values
    total_items = len(whitelist)
    total_pages = math.ceil(total_items / per_page)
    start_idx = (page - 1) * per_page
    end_idx = min(start_idx + per_page, total_items)
    current_items = whitelist[start_idx:end_idx]
    
    return render_template('whitelist.html',
                          domains=current_items,
                          page=page,
                          per_page=per_page,
                          total_pages=total_pages,
                          total_items=total_items,
                          total_domains=total_items,  # Add this for the stats card
                          search=search)

@app.route('/whitelist/add', methods=['POST'])
def add_whitelist_item():
    domain_input = request.form.get('domain', '').strip()

    if not domain_input:
        return jsonify({'error': 'Domain is required'}), 400

    # Extract domain from URL if a full URL was provided
    if domain_input.startswith(('http://', 'https://')):
        try:
            parsed = urlparse(domain_input)
            domain = parsed.netloc
        except Exception:
            return jsonify({'error': 'Invalid URL format'}), 400
    else:
        domain = domain_input

    # Remove www. prefix if present
    if domain.startswith('www.'):
        domain = domain[4:]

    if not domain:
        return jsonify({'error': 'Invalid domain'}), 400

    # Add to whitelist
    traffic_analyzer.whitelist.add(domain)
    traffic_analyzer.save_whitelist()

    return jsonify({'success': True, 'message': f'Added {domain} to whitelist'})

@app.route('/whitelist/delete/<path:domain>', methods=['POST', 'DELETE'])
def delete_whitelist_item(domain):
    # Remove from whitelist
    if domain in traffic_analyzer.whitelist:
        traffic_analyzer.whitelist.remove(domain)
        traffic_analyzer.save_whitelist()
        return jsonify({'success': True, 'message': f'Removed {domain} from whitelist'})
    else:
        return jsonify({'error': f'Domain {domain} not found in whitelist'}), 404

@app.route('/whitelist/bulk-delete', methods=['POST'])
def bulk_delete_whitelist():
    domains = request.json.get('domains', [])
    
    if not domains:
        return jsonify({'error': 'No domains specified for deletion'}), 400
    
    removed = []
    for domain in domains:
        if domain in traffic_analyzer.whitelist:
            traffic_analyzer.whitelist.remove(domain)
            removed.append(domain)
    
    if removed:
        traffic_analyzer.save_whitelist()
        return jsonify({'success': True, 'message': f'Removed {len(removed)} domains from whitelist'})
    else:
        return jsonify({'error': 'No matching domains found for deletion'}), 404

@app.route('/whitelist/bulk-add', methods=['POST'])
def bulk_add_whitelist():
    # Check for file upload first
    if 'file' in request.files:
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        try:
            # Read domains from file (one per line)
            content = file.read().decode('utf-8')
            domains = [line.strip() for line in content.split('\n') if line.strip()]
        except Exception as e:
            return jsonify({'error': f'Error reading file: {str(e)}'}), 400
    else:
        # Check for text input
        text_input = request.form.get('domains', '')
        domains = [line.strip() for line in text_input.split('\n') if line.strip()]
    
    if not domains:
        return jsonify({'error': 'No domains provided'}), 400
    
    # Add all domains to whitelist
    added = 0
    for domain_input in domains:
        # Extract domain from URL if a full URL was provided
        if domain_input.startswith(('http://', 'https://')):
            try:
                parsed = urlparse(domain_input)
                domain = parsed.netloc
            except Exception:
                continue  # Skip invalid URLs
        else:
            domain = domain_input

        # Remove www. prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]

        if domain and domain not in traffic_analyzer.whitelist:
            traffic_analyzer.whitelist.add(domain)
            added += 1
    
    traffic_analyzer.save_whitelist()
    return jsonify({'success': True, 'message': f'Added {added} domains to whitelist'})

@app.route('/whitelist/export')
def export_whitelist():
    """Export whitelist as a text file"""
    from flask import Response

    # Get all domains from whitelist
    domains = sorted(list(traffic_analyzer.whitelist))

    # Create text content
    content = '\n'.join(domains)

    # Return as downloadable file
    return Response(
        content,
        mimetype='text/plain',
        headers={'Content-Disposition': 'attachment; filename=whitelist.txt'}
    )

@app.route('/scan', methods=['POST'])
def scan_url():
    # Get URL and strip trailing slash if present
    url = request.form.get('url', '')
    url = url.rstrip('/')
    print(url)
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
        
    # Check if the URL's host is in whitelist
    try:
        parsed = urlparse(url)
        host = parsed.netloc
        
        # Remove www. prefix if present for matching
        if host.startswith('www.'):
            clean_host = host[4:]
        else:
            clean_host = host
            
        print(f"Checking if {clean_host} is in whitelist")

        # Use ScannerAnalyzer's whitelist checking
        host_whitelisted = traffic_analyzer._is_whitelisted(host)
        clean_host_whitelisted = traffic_analyzer._is_whitelisted(clean_host)
        print(f"Host {host} whitelisted: {host_whitelisted}")
        print(f"Clean host {clean_host} whitelisted: {clean_host_whitelisted}")

        if host_whitelisted or clean_host_whitelisted:
            print(f"Found whitelist match for {host} - returning trusted response")
            return jsonify({
                'result': 'Trusted domain',
                'safe': True,
                'whitelisted': True,
                'detection_method': 'Whitelist',
                'explanation': f'The domain {host} is in our trusted whitelist and was not scanned.',
                'ml_confidence': 0.0,
                'ml_time_ms': 0.0,
                'analysis_time_ms': 0.0
            })
        else:
            print(f"No whitelist match found for {host} or {clean_host}")
    except Exception as e:
        print(f"Error checking whitelist: {e}")
    
    # Validate URL format
    try:
        parsed = urlparse(url)
        if not all([parsed.scheme, parsed.netloc]):
            return jsonify({'error': 'Invalid URL format'}), 400
    except Exception:
        return jsonify({'error': 'Invalid URL format'}), 400
    
    try:
        start_time = time.time()

        # Log scan request
        log_event(logger, "web_scan_request", {
            "url": url,
            "source": "web_interface",
            "user_agent": request.headers.get('User-Agent', 'Unknown')
        })

        # Fetch URL content safely
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        # Disable SSL verification to avoid certificate issues during scanning
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        # Only process HTML content
        content_type = response.headers.get('Content-Type', '')
        if not content_type.startswith('text/html'):
            return jsonify({'result': 'Not HTML content', 'safe': True, 'content_type': content_type})
        
        html_content = response.text
        
        # Check with ML detector first
        is_phishing, confidence, ml_time_ms = ml_detector.predict(url, html_content)
        
        # If high confidence ML detection, return result
        if is_phishing and confidence >= ml_detector.confidence_threshold:
            # Log phishing detection
            log_event(logger, "web_phishing_detected", {
                "url": url,
                "confidence": float(confidence),
                "detection_method": "machine_learning",
                "source": "web_interface",
                "scan_time": time.time() - start_time
            })

            return jsonify({
                'result': 'High confidence phishing detected',
                'safe': False,
                'confidence': float(confidence),  # Ensure it's a Python float
                'ml_time_ms': float(ml_time_ms),  # Ensure it's a Python float
                'detection_method': 'Machine Learning Model',
                'explanation': 'Our machine learning model has identified this site as likely phishing based on multiple factors including URL structure, domain characteristics, and content analysis.'
            })
        
        # Otherwise, check with traditional analyzer
        traffic_results = traffic_analyzer.analyze(url, html_content)
        is_malicious = traffic_results.get('is_malicious', False)
        
        if is_malicious:
            return jsonify({
                'result': 'Malicious patterns detected',
                'safe': False,
                'ml_confidence': float(confidence),
                'ml_time_ms': float(ml_time_ms),
                'patterns': traffic_results.get('detected_patterns', []),
                'analysis_time_ms': traffic_results.get('analysis_time_ms', 0.0),
                'detection_method': 'Traditional Pattern Analysis',
                'explanation': 'Our security system detected multiple suspicious patterns that are commonly associated with phishing websites.'
            })
        
        return jsonify({
            'result': 'No phishing detected',
            'safe': True,
            'ml_confidence': float(confidence),
            'ml_time_ms': float(ml_time_ms),
            'analysis_time_ms': traffic_results.get('analysis_time_ms', 0.0),
            'detection_method': 'Combined Analysis',
            'explanation': 'Neither our machine learning model nor our pattern analysis detected any phishing indicators on this site.'
        })
        
    except requests.RequestException as e:
        return jsonify({'error': f'Error fetching URL: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Error analyzing URL: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
