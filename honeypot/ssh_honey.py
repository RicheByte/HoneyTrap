#!/usr/bin/env python3
import socket
import threading
import json
import os
import time
import hashlib
import logging
import logging.handlers
from datetime import datetime
from typing import Dict, Any, Optional
import re
from concurrent.futures import ThreadPoolExecutor
import prometheus_client as prom
from config import config

# Configure logging
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_handler = logging.handlers.RotatingFileHandler(
    os.path.join(config.OUTDIR, "logs/honeypot.log"),
    maxBytes=config.MAX_LOG_SIZE,
    backupCount=config.MAX_LOG_FILES
)
log_handler.setFormatter(log_formatter)
logger = logging.getLogger('ssh_honeypot')
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

# Also log to console for debugging
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
logger.addHandler(console_handler)

# Prometheus metrics
connections_total = prom.Counter('honeypot_connections_total', 'Total connections', ['src_ip', 'protocol'])
commands_total = prom.Counter('honeypot_commands_total', 'Total commands', ['command'])
login_attempts = prom.Counter('honeypot_login_attempts', 'Login attempts', ['username'])
session_duration = prom.Histogram('honeypot_session_duration_seconds', 'Session duration')

def setup_metrics():
    """Setup Prometheus metrics endpoint"""
    if config.ENABLE_METRICS:
        prom.start_http_server(config.METRICS_PORT)
        logger.info(f"Metrics server started on port {config.METRICS_PORT}")

def now_ts():
    """Returns current UTC timestamp in ISO format."""
    return datetime.utcnow().isoformat() + "Z"

def sanitize_input(text: str) -> str:
    """Sanitize user input to prevent log injection"""
    return re.sub(r'[\r\n]', '', text)[:1000]

def save_event(ev: Dict[str, Any]):
    """
    Appends a JSON-formatted event to the events log file.
    """
    fname = os.path.join(config.OUTDIR, "events.log")
    try:
        with open(fname, "a") as f:
            f.write(json.dumps(ev) + "\n")
        logger.info(f"Event saved: {ev['event_type']} from {ev['src_ip']}")
    except IOError as e:
        logger.error(f"Failed to save event: {e}")

def detect_protocol(data: bytes) -> str:
    """Detect if connection is SSH or raw TCP/Telnet"""
    if data.startswith(b'SSH-'):
        return "ssh"
    else:
        return "tcp"

def handle_ssh_protocol(conn, session_lines):
    """Handle SSH protocol interaction"""
    try:
        # Send SSH banner
        conn.send(f"{config.BANNER}\r\n".encode())
        data = conn.recv(4096)
        client_version = data.decode("latin1", errors="ignore").strip()
        session_lines.append(f"CLIENT_VERSION: {client_version}")
        
        # SSH authentication process
        conn.send(b"login: ")
        uname_data = conn.recv(1024)
        username = sanitize_input(uname_data.strip().decode("latin1", errors="ignore"))
        session_lines.append(f"USERNAME: {username}")
        login_attempts.labels(username=username).inc()
        
        conn.send(b"Password: ")
        pass_data = conn.recv(1024)
        password = sanitize_input(pass_data.strip().decode("latin1", errors="ignore"))
        session_lines.append(f"PASSWORD: {password}")
        
        # Fake authentication
        conn.send(b"Authentication failed.\r\n")
        time.sleep(1)
        conn.send(b"Authentication successful.\r\n")
        conn.send(f"Last login: {now_ts()}\r\n".encode())
        
        return username, password, "ssh"
        
    except Exception as e:
        logger.error(f"SSH protocol error: {e}")
        raise

def handle_tcp_protocol(conn, session_lines):
    """Handle raw TCP/Telnet protocol interaction"""
    try:
        # Send initial banner for telnet
        welcome_msg = f"Welcome to {config.BANNER}\r\n\r\n"
        conn.send(welcome_msg.encode())
        time.sleep(0.5)
        
        # Direct to login prompt
        conn.send(b"login: ")
        uname_data = conn.recv(1024)
        username = sanitize_input(uname_data.strip().decode("latin1", errors="ignore"))
        session_lines.append(f"USERNAME: {username}")
        login_attempts.labels(username=username).inc()
        
        conn.send(b"Password: ")
        pass_data = conn.recv(1024)
        password = sanitize_input(pass_data.strip().decode("latin1", errors="ignore"))
        session_lines.append(f"PASSWORD: {password}")
        
        # Fake authentication
        conn.send(b"\r\nLogin successful\r\n")
        conn.send(f"Last login: {now_ts()}\r\n".encode())
        
        return username, password, "tcp"
        
    except Exception as e:
        logger.error(f"TCP protocol error: {e}")
        raise

def generate_response(command: str) -> str:
    """Generate realistic responses to common commands"""
    cmd = command.lower().split()[0] if command else ""
    
    responses = {
        "ls": "bin  etc  lib  proc  tmp  var\r\nboot dev  home root sys  usr",
        "pwd": "/home/admin",
        "whoami": "admin",
        "id": "uid=1000(admin) gid=1000(admin) groups=1000(admin)",
        "uname": "Linux server-01 4.19.0-1-amd64 #1 SMP Debian 4.19.0-1 (2018-12-30) x86_64 GNU/Linux",
        "ps": "  PID TTY          TIME CMD\r\n    1 ?        00:00:01 init\r\n  123 ?        00:00:00 sshd",
        "netstat": "Active Internet connections (servers and established)",
        "help": "Available commands: ls, pwd, whoami, id, uname, ps, netstat, help, exit",
        "exit": "Logout",
        "": ""
    }
    
    return responses.get(cmd, f"bash: {command}: command not found")

def handle_client(conn, addr):
    """
    Handles an incoming client connection with protocol detection.
    """
    src_ip, src_port = addr
    start = time.time()
    session_lines = []
    protocol = "unknown"
    username = ""
    password = ""
    
    logger.info(f"New connection from {src_ip}:{src_port}")
    
    try:
        # Set timeout for initial data
        conn.settimeout(10.0)
        
        # Receive initial data to detect protocol
        initial_data = conn.recv(1024, socket.MSG_PEEK)
        if not initial_data:
            logger.info(f"No data received from {src_ip}, closing connection")
            conn.close()
            return
            
        protocol = detect_protocol(initial_data)
        logger.info(f"Detected protocol: {protocol} from {src_ip}")
        
        # Handle based on protocol
        if protocol == "ssh":
            username, password, protocol = handle_ssh_protocol(conn, session_lines)
        else:
            username, password, protocol = handle_tcp_protocol(conn, session_lines)
        
        # Common interaction loop for both protocols
        conn.settimeout(config.SESSION_TIMEOUT)
        conn.send(b"$ ")
        
        while True:
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                    
                # Handle telnet control characters
                text = chunk.decode("latin1", errors="ignore")
                # Remove telnet control sequences
                text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
                text = sanitize_input(text.strip())
                
                if text.lower() in ['exit', 'quit', 'logout']:
                    session_lines.append(f"CMD: {text}")
                    conn.send(b"Logout\r\n")
                    break
                    
                if text:
                    session_lines.append(f"CMD: {text}")
                    commands_total.labels(command=text.split()[0] if text else 'unknown').inc()
                    
                    response = generate_response(text)
                    if response:
                        conn.send(response.encode() + b"\r\n")
                    conn.send(b"$ ")
                else:
                    conn.send(b"$ ")
                    
            except socket.timeout:
                session_lines.append("SESSION_TIMEOUT")
                logger.info(f"Session timeout for {src_ip}")
                break
            except Exception as e:
                logger.error(f"Error during session with {src_ip}: {e}")
                session_lines.append(f"ERROR: {str(e)}")
                break
                
    except socket.timeout:
        logger.warning(f"Connection timeout from {src_ip} during handshake")
        session_lines.append("HANDSHAKE_TIMEOUT")
    except Exception as e:
        logger.error(f"Connection error from {src_ip}: {e}")
        session_lines.append(f"CONNECTION_ERROR: {str(e)}")
    finally:
        try:
            conn.close()
        except:
            pass
            
        duration = time.time() - start
        
        # Save session data
        content = "\n".join(session_lines)
        sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
        
        artifact = {
            "ts": now_ts(),
            "src_ip": src_ip,
            "src_port": src_port,
            "duration": round(duration, 2),
            "sha256": sha,
            "event_type": f"{protocol}_honeypot_session",
            "username": username,
            "password": password,
            "protocol": protocol,
            "session_id": sha[:16],
            "transcript_file": f"transcripts/{sha}.txt"
        }
        
        # Save transcript
        transcript_dir = os.path.join(config.OUTDIR, "transcripts")
        os.makedirs(transcript_dir, exist_ok=True)
        transcript_path = os.path.join(transcript_dir, f"{sha}.txt")
        
        try:
            with open(transcript_path, "w", encoding="utf-8") as tf:
                tf.write(content)
            
            save_event(artifact)
            connections_total.labels(src_ip=src_ip, protocol=protocol).inc()
            session_duration.observe(duration)
            
            logger.info(f"Session completed: {src_ip} -> {username} via {protocol} ({duration:.2f}s)")
            
        except Exception as e:
            logger.error(f"Failed to save session data: {e}")

def server():
    """Enhanced honeypot server with thread pooling"""
    logger.info(f"Starting enhanced honeypot server on {config.BIND_IP}:{config.PORT}")
    
    # Setup metrics
    if config.ENABLE_METRICS:
        setup_metrics()
    
    # Use thread pool for better resource management
    with ThreadPoolExecutor(max_workers=50) as executor:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((config.BIND_IP, config.PORT))
        s.listen(config.MAX_CONNECTIONS)
        
        logger.info(f"Honeypot listening on {config.BIND_IP}:{config.PORT}")
        logger.info("Ready to accept SSH and TCP connections...")
        
        try:
            while True:
                conn, addr = s.accept()
                executor.submit(handle_client, conn, addr)
        except KeyboardInterrupt:
            logger.info("Shutting down honeypot")
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            s.close()

if __name__ == "__main__":
    # Create necessary directories
    os.makedirs(os.path.join(config.OUTDIR, "transcripts"), exist_ok=True)
    os.makedirs(os.path.join(config.OUTDIR, "logs"), exist_ok=True)
    
    logger.info("Starting SSH/TCP Honeypot...")
    server()