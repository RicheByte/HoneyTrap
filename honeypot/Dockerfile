# Start from scratch and build Python manually
FROM debian:bullseye-slim

# Install Python and required packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget \
    build-essential \
    zlib1g-dev \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download and install Python 3.11
RUN wget https://www.python.org/ftp/python/3.11.0/Python-3.11.0.tgz && \
    tar -xzf Python-3.11.0.tgz && \
    cd Python-3.11.0 && \
    ./configure --enable-optimizations && \
    make -j$(nproc) && \
    make altinstall && \
    cd .. && \
    rm -rf Python-3.11.0 Python-3.11.0.tgz

# Create symlinks
RUN ln -s /usr/local/bin/python3.11 /usr/local/bin/python3 && \
    ln -s /usr/local/bin/python3.11 /usr/local/bin/python && \
    ln -s /usr/local/bin/pip3.11 /usr/local/bin/pip3

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application
COPY ssh_honey.py .
COPY config.py .

# Create necessary directories with proper permissions
RUN mkdir -p /data/honeypot/transcripts /data/honeypot/logs && \
    chown -R nobody:nogroup /data && \
    chmod -R 750 /data

# Create non-root user
RUN groupadd -r -g 1001 appgroup && \
    useradd -r -u 1001 -g appgroup -d /app appuser && \
    chown -R appuser:appgroup /app /data

USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import socket; s = socket.socket(); s.settimeout(5); s.connect(('127.0.0.1', 2222)); s.close()" || exit 1

# Run the honeypot script
CMD ["python3", "-u", "ssh_honey.py"]
