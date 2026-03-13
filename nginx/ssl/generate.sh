#!/bin/bash
# Generate self-signed TLS cert for development/testing
# For production, use Let's Encrypt or a real CA
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout key.pem -out cert.pem \
  -subj "/CN=recon-sentinel/O=Sentinel/C=US"
echo "Self-signed cert generated: cert.pem + key.pem"
