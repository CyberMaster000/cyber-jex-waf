#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../certs" && pwd)"
mkdir -p "$DIR"
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout "$DIR/waf.key" -out "$DIR/waf.crt" \
  -days 365 -subj "/CN=localhost"
echo "Generated $DIR/waf.crt and $DIR/waf.key"
