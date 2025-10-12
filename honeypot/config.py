import os
from typing import Dict, Any

class Config:
    # Network settings
    BIND_IP = os.getenv("HONEYPOT_BIND_IP", "0.0.0.0")
    PORT = int(os.getenv("HONEYPOT_PORT", "2222"))
    MAX_CONNECTIONS = int(os.getenv("HONEYPOT_MAX_CONNECTIONS", "100"))
    
    # Data collection
    OUTDIR = "/data/honeypot"
    ROTATE_LOGS = True
    MAX_LOG_SIZE = 100 * 1024 * 1024  # 100MB
    MAX_LOG_FILES = 10
    
    # Security settings
    BANNER = os.getenv("HONEYPOT_BANNER", "SSH-2.0-OpenSSH_7.4p1 Debian-10")
    SESSION_TIMEOUT = int(os.getenv("HONEYPOT_SESSION_TIMEOUT", "300"))
    
    # Threat intelligence
    BLOCKLIST_UPDATE_URL = os.getenv("BLOCKLIST_UPDATE_URL", "")
    UPDATE_INTERVAL = 3600
    
    # Monitoring
    METRICS_PORT = int(os.getenv("METRICS_PORT", "9090"))
    ENABLE_METRICS = os.getenv("ENABLE_METRICS", "true").lower() == "true"
    
    # Integration
    SYSLOG_HOST = os.getenv("SYSLOG_HOST", "")
    SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "514"))

config = Config()
