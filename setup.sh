#!/bin/bash
set -e  # Exit on error
set -o pipefail

echo "[+] Updating system packages..."
sudo apt update -y && sudo apt upgrade -y

echo "[+] Installing prerequisites..."
sudo apt install -y apt-transport-https ca-certificates curl gnupg lsb-release

echo "[+] Setting up Docker repository..."
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

echo "[+] Installing Docker Engine and Docker Compose..."
sudo apt update -y
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

echo "[+] Enabling and starting Docker service..."
sudo systemctl enable docker
sudo systemctl start docker

echo "[+] Adding current user to docker group..."
sudo usermod -aG docker $USER

echo "[+] Creating directories for honeypot data..."
mkdir -p ~/honeypot_data/data/pcaps
mkdir -p ~/honeypot_data/data/honeypot
chmod -R 755 ~/honeypot_data

echo "[+] Creating honeypot project structure..."
mkdir -p ~/honeypot_mvp/honeypot
cd ~/honeypot_mvp

echo "[+] Verifying Docker installation..."
docker --version || { echo "[-] Docker not installed correctly"; exit 1; }
docker compose version || { echo "[-] Docker Compose not installed correctly"; exit 1; }

echo "[+] Setup complete. Log out and log back in for docker group changes to apply."
