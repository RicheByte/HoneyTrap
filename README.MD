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
![Architecture](/assets/image.png)

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

## 🚀 Quick Start

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

# 2. Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# 3. Install Docker Compose plugin
sudo apt install docker-compose-plugin -y

# 4. Create data directories
mkdir -p data/{honeypot/{logs,transcripts},pcaps,grafana}
chmod -R 755 data/

# 5. Start the honeypot
docker compose up -d
```

### Starting the Honeypot

```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f honeypot

# Check service status
docker compose ps
```

### Accessing Services

- **Honeypot SSH**: `localhost:2222` (exposed to network)
- **Grafana Dashboard**: `http://localhost:3000` (admin/admin)
- **Prometheus Metrics**: `http://localhost:9091`
- **Honeypot Metrics**: `http://localhost:9090/metrics`

##  Configuration

### Environment Variables

Configure the honeypot by editing `docker-compose.yml` or creating a `.env` file:

```yaml
environment:
  # Network Configuration
  HONEYPOT_BIND_IP: 0.0.0.0           # Bind address
  HONEYPOT_PORT: 2222                  # Listening port
  HONEYPOT_MAX_CONNECTIONS: 1000       # Max concurrent connections
  
  # Protocol Configuration
  HONEYPOT_BANNER: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3"
  HONEYPOT_SESSION_TIMEOUT: 300        # Session timeout (seconds)
  
  # Monitoring
  ENABLE_METRICS: "true"               # Enable Prometheus metrics
  METRICS_PORT: 9090                   # Metrics endpoint port
```

### Custom Configuration

Edit `honeypot/config.py` for advanced settings:

```python
# Logging
MAX_LOG_SIZE = 100 * 1024 * 1024  # 100MB
MAX_LOG_FILES = 10                 # Keep 10 rotated logs

# Security
SESSION_TIMEOUT = 300              # 5 minutes
MAX_CONNECTIONS = 1000             # Connection limit
```

##  Monitoring & Metrics

### Prometheus Metrics

Available at `http://localhost:9090/metrics`:

- `honeypot_connections_total{src_ip, protocol}`: Total connections by IP and protocol
- `honeypot_commands_total{command}`: Commands executed
- `honeypot_login_attempts{username}`: Login attempts by username
- `honeypot_session_duration_seconds`: Session duration histogram

### Grafana Dashboards

1. Access Grafana at `http://localhost:3000` (admin/admin)
2. Add Prometheus data source: `http://prometheus:9090`
3. Import pre-built dashboards for:
   - Connection overview
   - Attack patterns
   - Credential analysis
   - Geographic distribution (requires enrichment)

### Sample Queries

```promql
# Top attacking IPs
topk(10, sum by(src_ip) (honeypot_connections_total))

# Most attempted usernames
topk(20, sum by(username) (honeypot_login_attempts))

# Connection rate (last 5m)
rate(honeypot_connections_total[5m])
```

##  Data Collection

### Event Logs

Located in `data/honeypot/events.log`, each event is a JSON object:

```json
{
  "ts": "2025-11-09T12:34:56.789Z",
  "src_ip": "192.168.1.100",
  "src_port": 54321,
  "duration": 45.23,
  "event_type": "ssh_honeypot_session",
  "username": "root",
  "password": "password123",
  "protocol": "ssh",
  "session_id": "c7392773d067a9d0",
  "sha256": "c7392773d067a9d08ea9d6c37feb97b4be12a94b959ea61c150381f38d9eae8d",
  "transcript_file": "transcripts/c7392773d067a9d08ea9d6c37feb97b4be12a94b959ea61c150381f38d9eae8d.txt"
}
```

### Session Transcripts

Located in `data/honeypot/transcripts/`, contains complete session interaction:

```
CLIENT_VERSION: SSH-2.0-OpenSSH_7.4
USERNAME: admin
PASSWORD: admin123
CMD: ls
CMD: whoami
CMD: cat /etc/passwd
CMD: exit
```

### Packet Captures

Located in `data/pcaps/`, rotated daily:

```
honeypot-2025-11-09_12-00-00.pcap
```

Analyze with:
```bash
# View capture summary
tcpdump -r data/pcaps/honeypot-*.pcap | less

# Extract specific IP
tcpdump -r data/pcaps/honeypot-*.pcap host 192.168.1.100 -w filtered.pcap

# Analyze with Wireshark
wireshark data/pcaps/honeypot-*.pcap
```

##  Security Considerations

### Deployment Best Practices

1. **Network Isolation**: Deploy in isolated VLAN or DMZ
2. **Firewall Rules**: Restrict access to management interfaces (Grafana, Prometheus)
3. **Regular Updates**: Keep Docker images and host system updated
4. **Monitoring**: Set up alerts for unusual activity
5. **Legal Compliance**: Ensure compliance with local laws regarding honeypots

### Hardening Recommendations

```bash
# Restrict Grafana access to localhost only
# Edit docker-compose.yml:
grafana:
  ports:
    - "127.0.0.1:3000:3000"

# Enable UFW firewall
sudo ufw allow 2222/tcp  # Honeypot only
sudo ufw enable

# Set up log rotation
# Create /etc/logrotate.d/honeytrap
```

### What NOT to Do

 Don't expose Grafana/Prometheus to the internet without authentication  
 Don't deploy on production networks without proper isolation  
 Don't use this as your primary security defense  
 Don't forget to monitor disk space for PCAPs  

## 🗺️ Roadmap

### Current (v1.0)
-  SSH/TCP honeypot with session recording
-  Full packet capture
-  Prometheus metrics integration
-  Grafana visualization

### Planned Features

#### v1.1
- [ ] HTTP/HTTPS honeypot
- [ ] Automated IP enrichment (GeoIP, ASN, reputation)
- [ ] Email/Slack alerting
- [ ] File upload capture

#### v1.2
- [ ] Elasticsearch/Kibana integration
- [ ] Advanced malware analysis sandbox
- [ ] MISP integration for threat intelligence sharing
- [ ] Machine learning for attack pattern detection

#### v2.0
- [ ] Multi-node deployment
- [ ] Custom protocol emulation
- [ ] Automated playbook execution
- [ ] API for external integrations

##  Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/HoneyTrap.git
cd HoneyTrap

# Create a development branch
git checkout -b dev

# Make changes and test
docker compose up --build
```


##  Acknowledgments

- Built with [Paramiko](https://www.paramiko.org/) for SSH protocol handling
- Inspired by [Cowrie](https://github.com/cowrie/cowrie) and [HoneyPy](https://github.com/foospidy/HoneyPy)
- Packet capture powered by [tcpdump](https://www.tcpdump.org/)
- Monitoring by [Prometheus](https://prometheus.io/) and [Grafana](https://grafana.com/)

##  Contact & Support

- **Issues**: [GitHub Issues](https://github.com/RicheByte/HoneyTrap/issues)
- **Discussions**: [GitHub Discussions](https://github.com/RicheByte/HoneyTrap/discussions)

---

**Disclaimer**: This honeypot is for educational and research purposes. Deploy responsibly and ensure compliance with all applicable laws and regulations in your jurisdiction.







