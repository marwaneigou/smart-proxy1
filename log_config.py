import logging
import json
import time
import os
from logging.handlers import RotatingFileHandler

# Configure the root logger
def setup_logging(log_dir="logs", log_level=logging.INFO):
    """
    Setup logging configuration for Grafana-compatible logs
    """
    # Create logs directory if it doesn't exist
    os.makedirs(log_dir, exist_ok=True)
    
    # Configure the root logger
    logger = logging.getLogger()
    logger.setLevel(log_level)
    
    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    
    # Create JSON file handler for Grafana
    json_handler = RotatingFileHandler(
        os.path.join(log_dir, 'smart_proxy.json'),
        maxBytes=10485760,  # 10MB
        backupCount=10
    )
    json_handler.setLevel(log_level)
    
    class JSONFormatter(logging.Formatter):
        def format(self, record):
            log_record = {
                "timestamp": int(record.created * 1000),  # milliseconds for Grafana
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
            
            # Add extra fields if they exist
            if hasattr(record, 'metrics'):
                log_record.update(record.metrics)
                
            return json.dumps(log_record)
    
    json_handler.setFormatter(JSONFormatter())
    logger.addHandler(json_handler)
    
    return logger

# Helper for logging metrics in a Grafana-friendly format
def log_metric(logger, metric_name, value, context=None):
    """
    Log a metric in a format that's easy to query in Grafana
    
    Args:
        logger: The logger instance
        metric_name: Name of the metric (e.g., 'scan_time', 'is_phishing')
        value: Value of the metric
        context: Additional context as a dictionary
    """
    # Put metric name and value directly in the root of the log entry for easier querying
    extra = {'metrics': {metric_name: value}, metric_name: value}
    
    # Add context if provided
    if context:
        extra['metrics'].update(context)
        # Also add context items to the root for easier querying
        for key, val in context.items():
            extra[key] = val
    
    logger.info(f"METRIC:{metric_name}:{value}", extra=extra)

# Helper for logging events in a Grafana-friendly format
def log_event(logger, event_name, details=None):
    """
    Log an event in a format that's easy to query in Grafana
    
    Args:
        logger: The logger instance
        event_name: Name of the event (e.g., 'phishing_detected', 'bypass_granted')
        details: Additional details as a dictionary
    """
    # Put event directly in the root of the log entry for easier querying
    extra = {'metrics': {'event': event_name}, 'event': event_name}
    
    # Add details if provided
    if details:
        extra['metrics'].update(details)
        # Also add details to the root for easier querying
        for key, val in details.items():
            extra[key] = val
    
    logger.info(f"EVENT:{event_name}", extra=extra)
