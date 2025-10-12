#!/bin/sh
mkdir -p /data/pcaps
FILENAME="/data/pcaps/honeypot-$(date +'%Y-%m-%d_%H-%M-%S').pcap"
exec tcpdump -i any -w "$FILENAME" -G 3600 -n -s 65535 port 2222
