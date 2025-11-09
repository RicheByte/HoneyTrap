#  HoneyTrap

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue.svg)](https://docs.docker.com/compose/)
[![Python](https://img.shields.io/badge/Python-3.8+-green.svg)](https://www.python.org/)

**HoneyTrap** is a production-ready, containerized honeypot system designed to detect, log, and analyze malicious SSH/TCP connection attempts. Built with Docker and Python, it provides comprehensive threat intelligence gathering with full packet capture, real-time monitoring, and detailed session transcripts.

##  Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [Monitoring & Metrics](#-monitoring--metrics)
- [Data Collection](#-data-collection)
- [Security Considerations](#-security-considerations)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

##  Features

### Core Capabilities

- ** Multi-Protocol Honeypot**: SSH and raw TCP/Telnet protocol detection and emulation
- ** Full Packet Capture**: Continuous PCAP collection of all network traffic
- ** Detailed Logging**: Structured JSON logs with session transcripts, credentials, and commands
- ** Real-time Metrics**: Prometheus integration for monitoring and alerting
- ** Visualization**: Grafana dashboards for threat intelligence visualization
- ** Session Recording**: Complete session transcripts with SHA-256 identification
- ** High Performance**: Thread-pooled architecture supporting 1000+ concurrent connections
- ** Containerized**: Easy deployment with Docker Compose
- ** Auto-restart**: Resilient services with health checks and automatic recovery

### Security Features

- **Input Sanitization**: Protection against log injection attacks
- **Timeout Management**: Configurable session timeouts to prevent resource exhaustion
- **Isolated Network**: Dedicated Docker network for containment
- **Rate Limiting**: Configurable connection limits
- **Rotating Logs**: Automatic log rotation to prevent disk exhaustion

##  Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Host System                              │
│                      (Ubuntu Server)                             │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             │ Docker Bridge Network (honeynet)
                             │
┌────────────────────────────┴────────────────────────────────────┐
│                    Docker Compose Stack                          │
│                                                                  │
│  ┌──────────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│  │   Honeypot       │  │  PCAP        │  │  Prometheus      │ │
│  │   Service        │  │  Capture     │  │  (Metrics)       │ │
│  │                  │  │              │  │                  │ │
│  │ Port: 2222       │  │ tcpdump      │  │ Port: 9091       │ │
│  │ Metrics: 9090    │  │              │  │                  │ │
│  └────────┬─────────┘  └──────┬───────┘  └────────┬─────────┘ │
│           │                   │                    │           │
│           └───────────────────┼────────────────────┘           │
│                               │                                │
│  ┌────────────────────────────┴──────────────────────────┐    │
│  │              Grafana Dashboard                         │    │
│  │              Port: 3000                                │    │
│  └────────────────────────────────────────────────────────┘    │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
                             │
                             │ Persistent Storage
                             │
┌────────────────────────────┴────────────────────────────────────┐
│                      ./data/ Directory                           │
│                                                                  │
│  ├── honeypot/                                                   │
│  │   ├── logs/              (Structured event logs)             │
│  │   ├── transcripts/       (Session recordings)                │
│  │   └── events.log         (JSON event stream)                 │
│  │                                                               │
│  ├── pcaps/                 (Full packet captures)              │
│  │   └── honeypot-*.pcap                                        │
│  │                                                               │
│  └── grafana/               (Dashboard data & plugins)           │
└──────────────────────────────────────────────────────────────────┘
```

##  Quick Start

### Prerequisites

- Ubuntu 20.04+ (or similar Linux distribution)
- Docker 20.10+
- Docker Compose 2.0+
- 2GB RAM minimum
- 10GB free disk space (more recommended for long-term PCAP storage)

### Automated Installation

The easiest way to get started:

```bash
# Clone the repository
git clone https://github.com/RicheByte/HoneyTrap.git
cd HoneyTrap

# Run the automated setup script
chmod +x setup.sh
./setup.sh

# Log out and back in for group changes to take effect
exit
```

### Manual Installation

If you prefer manual setup:

```bash
# 1. Update system packages
sudo apt update && sudo apt upgrade -y

# 2. Install Docker and Docker Compose
# Follow official Docker installation guide:
# https://docs.docker.com/engine/install/ubuntu/
# https://docs.docker.com/compose/install/

# Example for Ubuntu:
sudo apt install apt-transport-https ca-certificates curl gnupg lsb-release -y
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-compose-plugin -y
sudo usermod -aG docker $USER # Add your user to the docker group to run without sudo
newgrp docker # Apply group changes immediately

# 3. Create base directory for honeypot data
# This directory will hold all collected data (PCAPs, logs, transcripts)
mkdir -p ~/honeypot_data/data/pcaps
mkdir -p ~/honeypot_data/data/honeypot

# 4. Create the honeypot project directory
mkdir -p ~/honeypot/honeypot
cd ~/honeypot
```

#### or run the ./setup.sh as giving persimission for execute.



