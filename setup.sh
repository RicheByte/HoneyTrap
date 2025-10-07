
# Assuming an Ubuntu Server or similar host system
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
mkdir -p ~/honeypot_mvp/honeypot
cd ~/honeypot_mvp
