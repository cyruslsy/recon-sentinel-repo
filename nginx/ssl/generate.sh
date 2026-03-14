#!/bin/bash
# Generate self-signed TLS cert for development/testing
# For production, replace with Let's Encrypt or your CA certs:
#   cp /etc/letsencrypt/live/yourdomain/fullchain.pem nginx/ssl/cert.pem
#   cp /etc/letsencrypt/live/yourdomain/privkey.pem nginx/ssl/key.pem

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ -f cert.pem ] && [ -f key.pem ]; then
  echo "TLS certs already exist (nginx/ssl/cert.pem + key.pem). Skipping generation."
  echo "To regenerate, delete them first: rm nginx/ssl/cert.pem nginx/ssl/key.pem"
  exit 0
fi

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout key.pem -out cert.pem \
  -subj "/CN=recon-sentinel/O=Sentinel/C=US" \
  2>/dev/null

echo "Self-signed TLS cert generated: nginx/ssl/cert.pem + key.pem"
echo "WARNING: Self-signed certs are for dev/testing only. Use a real CA for production."
