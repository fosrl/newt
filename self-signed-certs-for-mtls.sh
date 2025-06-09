#!/usr/bin/env bash
set -eu

echo -n "Enter username for certs (eg alice): "
read CERT_USERNAME
echo

echo -n "Enter domain of user (eg example.com): "
read DOMAIN
echo

# Prompt for password at the start
echo -n "Enter password for certificate: "
read -s PASSWORD
echo
echo -n "Confirm password: "
read -s PASSWORD2
echo

if [ "$PASSWORD" != "$PASSWORD2" ]; then
    echo "Passwords don't match!"
    exit 1
fi
CA_DIR="./certs/ca"
CLIENT_DIR="./certs/clients"
FILE_PREFIX=$(echo "$CERT_USERNAME-at-$DOMAIN" | sed 's/\./-/')

mkdir -p "$CA_DIR"
mkdir -p "$CLIENT_DIR"

if [ ! -f "$CA_DIR/ca.crt" ]; then
# Generate CA private key
  openssl genrsa -out "$CA_DIR/ca.key" 4096
  echo "CA key ✅"

  # Generate CA root certificate
  openssl req -x509 -new -nodes \
    -key "$CA_DIR/ca.key" \
    -sha256 \
    -days 3650 \
    -out "$CA_DIR/ca.crt" \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=ca.$DOMAIN"

  echo "CA cert ✅"
fi

# Generate client private key
openssl genrsa -aes256 -passout pass:"$PASSWORD" -out "$CLIENT_DIR/$FILE_PREFIX.key" 2048
echo "Client key ✅"

# Generate client Certificate Signing Request (CSR)
openssl req -new \
  -key "$CLIENT_DIR/$FILE_PREFIX.key" \
  -out "$CLIENT_DIR/$FILE_PREFIX.csr" \
  -passin pass:"$PASSWORD" \
  -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=$CERT_USERNAME@$DOMAIN"
echo "Client cert ✅"

echo -n "Signing client cert..."
# Create client certificate configuration file
cat > "$CLIENT_DIR/$FILE_PREFIX.ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DOMAIN
EOF

# Generate client certificate signed by CA
openssl x509 -req \
  -in "$CLIENT_DIR/$FILE_PREFIX.csr" \
  -CA "$CA_DIR/ca.crt" \
  -CAkey "$CA_DIR/ca.key" \
  -CAcreateserial \
  -out "$CLIENT_DIR/$FILE_PREFIX.crt" \
  -days 365 \
  -sha256 \
  -extfile "$CLIENT_DIR/$FILE_PREFIX.ext"

# Verify the client certificate
openssl verify -CAfile "$CA_DIR/ca.crt" "$CLIENT_DIR/$FILE_PREFIX.crt"
echo "Signed ✅"

# Create encrypted PEM bundle
openssl rsa -in "$CLIENT_DIR/$FILE_PREFIX.key" -passin pass:"$PASSWORD" \
    | cat "$CLIENT_DIR/$FILE_PREFIX.crt" - > "$CLIENT_DIR/$FILE_PREFIX-bundle.enc.pem"


# Convert to PKCS12
echo "Converting to PKCS12 format..."
openssl pkcs12 -export \
  -out "$CLIENT_DIR/$FILE_PREFIX.enc.p12" \
  -inkey "$CLIENT_DIR/$FILE_PREFIX.key" \
  -in "$CLIENT_DIR/$FILE_PREFIX.crt" \
  -certfile "$CA_DIR/ca.crt" \
  -name "$CERT_USERNAME@$DOMAIN" \
  -passin pass:"$PASSWORD" \
  -passout pass:"$PASSWORD"
echo "Converted to encrypted p12 for macOS ✅"

# Convert to PKCS12 format without encryption
echo "Converting to non-encrypted PKCS12 format..."
openssl pkcs12 -export \
  -out "$CLIENT_DIR/$FILE_PREFIX.p12" \
  -inkey "$CLIENT_DIR/$FILE_PREFIX.key" \
  -in "$CLIENT_DIR/$FILE_PREFIX.crt" \
  -certfile "$CA_DIR/ca.crt" \
  -name "$CERT_USERNAME@$DOMAIN" \
  -passin pass:"$PASSWORD" \
  -passout pass:""
echo "Converted to non-encrypted p12  ✅"

# Clean up intermediate files
rm "$CLIENT_DIR/$FILE_PREFIX.csr" "$CLIENT_DIR/$FILE_PREFIX.ext" "$CA_DIR/ca.srl"
echo
echo

echo "CA certificate:     $CA_DIR/ca.crt"
echo "CA private key:     $CA_DIR/ca.key"
echo "Client certificate: $CLIENT_DIR/$FILE_PREFIX.crt"
echo "Client private key: $CLIENT_DIR/$FILE_PREFIX.key"
echo "Client cert bundle: $CLIENT_DIR/$FILE_PREFIX.p12"
echo "Client cert bundle (encrypted): $CLIENT_DIR/$FILE_PREFIX.enc.p12"
