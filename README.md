# Smart Proxy - Advanced Phishing URL Scanner with ML Detection

A comprehensive web security solution that combines traditional pattern analysis with machine learning to detect and block phishing websites while allowing legitimate bypasses for false positives.

## Project Overview

This smart proxy system serves as an intermediary between users and the web, automatically scanning websites for phishing attempts, malicious scripts, and other security threats. It uses multi-layered detection methods including machine learning models, traditional pattern analysis, and blacklist/whitelist mechanisms.

## Key Features

### Phishing Detection
- **Machine Learning Model**: XGBoost-based classifier for advanced phishing detection
- **Traditional Pattern Analysis**: Rule-based scanning for suspicious keywords and patterns
- **Blacklist Integration**: Block known malicious domains with direct blacklist matching

### User-Friendly Interfaces
- **Web Interface**: Easy-to-use scanner UI for manual URL checking
- **Block Pages**: Informative block pages with explanation of detected threats
- **Whitelist Management**: Complete CRUD interface with pagination for managing trusted domains

### Intelligent Bypass System
- **Token-Based Bypass**: Secure one-time token generation for authorized bypasses
- **Tab/Client Tracking**: Remember trusted bypasses for specific browser sessions
- **Warning Notices**: Clear risk notifications when users choose to bypass blocks

### Performance Optimizations
- **Result Caching**: Prevent re-scanning of recently visited sites
- **Resource Filtering**: Skip unnecessary resource files (images, stylesheets, etc.)
- **Targeted Analysis**: Focus intensive scanning only on HTML content

## System Components

### Core Components
- **Proxy Server (mitmproxy)**: Intercepts and analyzes web traffic (`main.py`)
- **Scanner App (Flask)**: Web interface for URL scanning (`scanner_app.py`)
- **ML Detector**: Machine learning model for phishing detection (`ml_detector.py`)
- **Scanner Analyzer**: Traditional pattern-based detection (`scanner_analyzer.py`)

### Supporting Components
- **Web Interface**: HTML/CSS/JS front-end for scanner and whitelist management
- **Configuration**: Customizable settings via `config.json`
- **Whitelist/Blacklist**: Domain management system with JSON storage

## Technical Requirements

- Python 3.11 or higher
- mitmproxy 9.0.0 or higher
- Flask for web interface
- XGBoost and joblib for ML model
- Other dependencies listed in `requirements.txt`

## Installation

1. Install required packages:
```bash
pip install -r requirements.txt
```

2. Configure your system certificates for HTTPS inspection (follow mitmproxy instructions)

## Usage

### Starting the Proxy Server
```bash
mitmproxy -s main.py
```

### Starting the Scanner Web Interface
```bash
python scanner_app.py
```

### Configuring Your Browser
Configure your browser to use the proxy (default: 127.0.0.1:8080)

## Whitelist Management

Access the whitelist manager at `/whitelist` to:
- View all whitelisted domains with pagination
- Add single domains to the whitelist
- Remove domains from the whitelist
- Bulk import/export of domains
- Search for specific domains

## Understanding Block Pages

When a potentially malicious site is detected, the proxy will display a block page with:
- Detection method (ML model, pattern analysis, or blacklist)
- Confidence score (for ML detection)
- Detected suspicious patterns (for traditional analysis)
- Options to go back or proceed with caution

## Bypass System

The bypass feature allows users to access sites flagged as potentially dangerous when they believe it's a false positive:

1. When a user clicks "Proceed Anyway" on a block page
2. A one-time bypass token is generated for that specific domain
3. The token is validated when used and then discarded
4. The domain is temporarily whitelisted only for that specific browser tab/session

## Configuration

Edit `config.json` to customize behavior:

- `ml_confidence_threshold`: Sensitivity of ML detection (0.0-1.0)
- `ml_model_path`: Path to the XGBoost model file
- `scan_timeout_ms`: Maximum analysis time per page
- `exclude_extensions`: File types to skip scanning

## Security Notes

- This tool is designed for educational and protective purposes only
- The bypass feature should be used with caution
- Always keep definitions and ML models updated for best protection

## Project Structure

```
smart_proxy/
├── main.py              # mitmproxy addon for traffic interception
├── scanner_app.py       # Flask web application for URL scanning
├── scanner_analyzer.py  # Traditional pattern-based analyzer
├── ml_detector.py       # Machine learning phishing detector
├── config.json          # Configuration settings
├── requirements.txt     # Python dependencies
├── whitelist.json       # Trusted domains list
├── blacklist.json       # Blocked domains list
├── phishing_xgb_model.pkl  # ML model file
└── templates/           # Web interface templates
    ├── index.html       # Scanner interface
    └── whitelist.html   # Whitelist management interface
```

## License

© 2025. All rights reserved. This project is for educational purposes.

- `exclude_domains`: Domains to skip (CDNs, etc.)

## How It Works

1. When you visit a website, the proxy intercepts the request
2. It filters out API calls, resource files, and other non-HTML content
3. HTML responses are scanned for security issues
4. Warnings are displayed in the console for suspicious content
5. Performance metrics are tracked to ensure speed

## Safety

- Sites with multiple security issues are automatically blacklisted
- Whitelisting is available for trusted domains
- Large pages (>1MB) are skipped to maintain performance
