#!/bin/bash
set -e

# Define directories
KEYS_DIR="deploy/dev-keys"
mkdir -p "$KEYS_DIR"

# File paths
PRIVATE_KEY="$KEYS_DIR/private_key.pem"
PUBLIC_KEY="$KEYS_DIR/public_key.pem"

# Check if keys already exist
if [ -f "$PRIVATE_KEY" ] && [ -f "$PUBLIC_KEY" ]; then
    echo "Development keys already exist in $KEYS_DIR."
    exit 0
fi

echo "Generating new RSA keypair (JWT Signing)..."

# Generate private key (2048-bit)
openssl genpkey -algorithm RSA -out "$PRIVATE_KEY" -pkeyopt rsa_keygen_bits:2048

# Generate public key
openssl rsa -pubout -in "$PRIVATE_KEY" -out "$PUBLIC_KEY"

echo "Development keys successfully generated."
echo "Private Key: $PRIVATE_KEY"
echo "Public Key:  $PUBLIC_KEY"
