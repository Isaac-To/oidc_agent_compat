#!/bin/bash
# Generate a self-signed CA, server cert, and client cert for mTLS testing.
# All certs are written to docker/certs/ with 0600 permissions on keys.
set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")" && pwd)/certs"
mkdir -p "$CERT_DIR"

# --- CA ---
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout "$CERT_DIR/ca.key" \
  -out "$CERT_DIR/ca.crt" \
  -subj "/CN=OAC Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# --- Server cert (central proxy) ---
openssl req -newkey rsa:2048 -nodes \
  -keyout "$CERT_DIR/server.key" \
  -out "$CERT_DIR/server.csr" \
  -subj "/CN=central"

openssl x509 -req -in "$CERT_DIR/server.csr" \
  -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
  -CAcreateserial \
  -out "$CERT_DIR/server.crt" -days 365 -sha256 \
  -extfile <(printf "subjectAltName=DNS:central,DNS:localhost,IP:127.0.0.1")

# --- Client cert (relay) ---
openssl req -newkey rsa:2048 -nodes \
  -keyout "$CERT_DIR/client.key" \
  -out "$CERT_DIR/client.csr" \
  -subj "/CN=relay"

openssl x509 -req -in "$CERT_DIR/client.csr" \
  -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
  -CAcreateserial \
  -out "$CERT_DIR/client.crt" -days 365 -sha256 \
  -extfile <(printf "subjectAltName=DNS:relay,DNS:localhost,IP:127.0.0.1")

# --- Permissions ---
chmod 600 "$CERT_DIR"/*.key

# --- Cleanup CSRs ---
rm -f "$CERT_DIR"/*.csr "$CERT_DIR"/*.srl

echo "Certificates generated in $CERT_DIR:"
ls -la "$CERT_DIR"
