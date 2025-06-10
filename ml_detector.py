import os
import re
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse
import time
import logging
from collections import Counter
import math
from Levenshtein import distance as levenshtein_distance

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class MLPhishingDetector:
    def __init__(self, model_path, brands_path):
        self.model = None
        self.model_path = model_path
        self.brands_path = brands_path
        self.confidence_threshold = 0.85
        self.popular_brands = []
        self.load_model()
        self.load_brands()

    def load_model(self):
        try:
            start_time = time.time()
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                logging.info(f"Model loaded in {time.time() - start_time:.3f} seconds")
            else:
                logging.error(f"Model not found at {self.model_path}")
        except Exception as e:
            logging.error(f"Error loading model: {e}")

    def load_brands(self):
        if os.path.exists(self.brands_path):
            with open(self.brands_path, 'r') as f:
                self.popular_brands = [line.strip().lower() for line in f if line.strip()]
        else:
            logging.warning(f"Brands file not found at {self.brands_path}")

    def entropy(self, string):
        counts = Counter(string)
        frequencies = [count / len(string) for count in counts.values()]
        return -sum(freq * math.log2(freq) for freq in frequencies)

    def brand_mismatch(self, domain):
        for brand in self.popular_brands:
            if brand in domain and not domain.endswith(brand + ".com") and not domain.endswith("." + brand):
                return 1
        return 0

    def has_char_substitution(self, domain):
        substitutions = {"0": "o", "1": "l", "3": "e", "$": "s", "@": "a", "5": "s"}
        return int(any(char in domain for char in substitutions))

    def extract_features(self, url, html_content):
        try:
            parsed = urlparse(url if url.startswith("http") else "http://" + url)
            netloc = parsed.netloc.lower()
            path = parsed.path.lower()
            full_url = parsed.geturl().lower()
            domain_parts = netloc.split(".")
            domain_part = domain_parts[-2] if len(domain_parts) >= 2 else netloc
            digit_count = sum(c.isdigit() for c in full_url)
            special_chars = sum(not c.isalnum() and not c.isspace() for c in full_url)

            features = {
                "url_length": len(url),
                "has_ip": 1 if re.search(r"(\d{1,3}\.){3}\d{1,3}", netloc) else 0,
                "has_https": 1 if parsed.scheme == "https" else 0,
                "num_dots": full_url.count("."),
                "has_at_symbol": 1 if "@" in full_url else 0,
                "has_hyphen": 1 if "-" in netloc else 0,
                "has_suspicious_words": int(any(w in full_url for w in [
                    "login", "secure", "account", "verify", "bank", "update", "confirm",
                    "paypal", "password", "credit", "billing", "suspend", "unusual",
                    "alert", "limited", "security", "identity", "amazon", "apple",
                    "microsoft", "netflix", "support", "service", "signin"])),
                "domain_length": len(netloc),
                "path_length": len(path),
                "subdomain_count": len(domain_parts) - 2 if len(domain_parts) > 2 else 0,
                "has_port": 1 if parsed.port is not None else 0,
                "has_fragment": 1 if parsed.fragment else 0,
                "has_query": 1 if parsed.query else 0,
                "num_params": len(parsed.query.split("&")) if parsed.query else 0,
                "digit_ratio": digit_count / len(full_url) if full_url else 0,
                "special_char_ratio": special_chars / len(full_url) if full_url else 0,
                "domain_entropy": self.entropy(netloc) if netloc else 0,
                "tld": domain_parts[-1] if len(domain_parts) > 1 else "",  # Added this field
                "num_redirects": full_url.count("http") - 1,
                "url_shortener": int(any(s in netloc for s in [
                    "bit.ly", "tinyurl", "goo.gl", "t.co", "tr.im", "is.gd"])),
                "suspicious_tld": int(domain_parts[-1] in [
                    "xyz", "top", "club", "online", "tk", "ga", "ml", "cf", "gq", "buzz",
                    "info", "icu", "wang", "live", "cn", "host", "ru"]),
                "num_subdomains": netloc.count("."),
                "path_depth": path.count("/"),
                "has_double_slash_redirect": int("//" in path),
                "has_unicode": int(any(ord(c) > 127 for c in full_url)),
                "is_encoded": int("%" in full_url),
                "is_long_url": int(len(url) > 75),
                "brand_mismatch": self.brand_mismatch(netloc),
                "has_char_substitution": self.has_char_substitution(domain_part)
            }
            return features
        except Exception as e:
            logging.error(f"Error parsing URL: {url} -> {e}")
            return None

        return features

    def prepare_features(self, features_dict):
        # Convert to DataFrame first, like in the sample script
        df = pd.DataFrame([features_dict])
        
        # Drop columns that should not be used in prediction, just like the sample script
        if 'tld' in df.columns:
            df = df.drop(columns=['tld'])
        
        # Convert to numpy array
        return df.values

    def predict(self, url, html_content):
        if self.model is None:
            logging.error("Model not loaded")
            return False, 0.0, 0.0

        start = time.time()
        try:
            features_dict = self.extract_features(url, html_content)
            if features_dict is None:
                return False, 0.0, float(time.time() - start)
                
            X = self.prepare_features(features_dict)
            probas = self.model.predict_proba(X)[0]
            
            # Convert NumPy float32 to standard Python float for JSON serialization
            confidence = float(probas[1])  # phishing class
            prediction = int(confidence >= self.confidence_threshold)
            
            return prediction == 1, confidence, float(time.time() - start)
        except Exception as e:
            logging.error(f"Prediction error: {e}")
            return False, 0.0, float(time.time() - start)
