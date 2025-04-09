# X.509 Certificate Support

This document describes the X.509 certificate functionality implemented in the cryptography system.

## Overview

X.509 is a standard defining the format of public key certificates. These certificates are used in many Internet protocols, including TLS/SSL, which is the basis for HTTPS. The cryptography system now supports X.509 certificates for:

- Generating self-signed certificates
- Creating Certificate Signing Requests (CSRs)
- Importing and verifying certificates
- Certificate chain validation

## Usage

### Command Line Interface

The system provides a command-line interface for X.509 certificate operations:

#### Generate a Self-Signed Certificate

There are two ways to generate a certificate:

**Option 1: Using a key ID from the key storage**

```
python -m src.ui.cli cert generate --key <private_key_id> --common-name example.com --organization "Example Inc." --country US --state California --locality "San Francisco" --valid-days 365 --dns-names www.example.com api.example.com --ip-addresses 192.168.1.1 --output certificate.pem
```

**Option 2: Using a private key file directly (recommended)**

```
python -m src.ui.cli cert generate --key private_key.pem --key-file --common-name example.com --organization "Example Inc." --country US --state California --locality "San Francisco" --valid-days 365 --dns-names www.example.com api.example.com --ip-addresses 192.168.1.1 --output certificate.pem
```

> **Important Note**: When we initially tried to generate certificates using key IDs from the key storage, we encountered issues because the keys weren't properly stored in the key manager. Using the `--key-file` option allows you to directly use a private key file without relying on the key storage system, which is more reliable in many cases.

#### Create a Certificate Signing Request (CSR)

```
python -m src.ui.cli cert csr --key <private_key_id> --common-name example.com --organization "Example Inc." --country US --state California --locality "San Francisco" --dns-names www.example.com api.example.com --output csr.pem
```

#### Import a Certificate

```
python -m src.ui.cli cert import --file certificate.pem --key-id <key_id_base>
```

#### Verify a Certificate

```
python -m src.ui.cli cert verify --cert <certificate_id> --trusted <trusted_cert_id1> <trusted_cert_id2>
```

### API Usage

The system also provides a programmatic API for X.509 certificate operations:

#### Generate a Self-Signed Certificate

```python
from src.core.key_management import KeyManager

# Initialize the key manager
key_manager = KeyManager()

# Generate an RSA key pair
public_key, private_key = key_manager.generate_asymmetric_keypair(
    algorithm='RSA',
    key_size=2048
)

# Get the private key ID
private_key_id = [k for k in key_manager.active_keys.keys() if k.endswith('.private')][0]

# Generate a self-signed certificate
cert_id = key_manager.generate_x509_certificate(
    private_key_id=private_key_id,
    common_name="example.com",
    organization="Example Inc.",
    country="US",
    state="California",
    locality="San Francisco",
    valid_days=365,
    dns_names=["www.example.com", "api.example.com"],
    ip_addresses=["192.168.1.1"]
)

# Get the certificate data
cert_data = key_manager.active_keys[cert_id]['key']

# Save the certificate to a file
with open("certificate.pem", "wb") as f:
    f.write(cert_data)
```

#### Create a Certificate Signing Request (CSR)

```python
# Create a CSR
csr_pem = key_manager.create_certificate_signing_request(
    private_key_id=private_key_id,
    common_name="example.com",
    organization="Example Inc.",
    country="US",
    state="California",
    locality="San Francisco",
    dns_names=["www.example.com", "api.example.com"],
    ip_addresses=["192.168.1.1"]
)

# Save the CSR to a file
with open("csr.pem", "wb") as f:
    f.write(csr_pem)
```

#### Import a Certificate

```python
# Read a certificate file
with open("certificate.pem", "rb") as f:
    cert_data = f.read()

# Import the certificate
cert_id = key_manager.import_certificate(
    certificate_data=cert_data,
    key_id_base=None  # Optional: associate with an existing key pair
)
```

#### Verify a Certificate

```python
# Verify a certificate against a list of trusted certificates
result = key_manager.verify_certificate(
    cert_id=cert_id,
    trusted_cert_ids=[trusted_cert_id1, trusted_cert_id2]
)

# Check the result
if result['valid']:
    print("Certificate is valid")
else:
    print("Certificate is invalid")
    if result['expired']:
        print("Certificate has expired")
    if result['not_yet_valid']:
        print("Certificate is not yet valid")
    if not result['chain_valid']:
        print("Certificate chain is invalid")
```

## Technical Details

### Certificate Generation

The system uses the `cryptography` library to generate X.509 certificates. The certificates include:

- Subject information (common name, organization, country, etc.)
- Validity period
- Subject Alternative Names (DNS names and IP addresses)
- Basic Constraints (CA=True for self-signed certificates)
- Key Usage extensions

### Certificate Storage

Certificates are stored in the key manager alongside other cryptographic keys. Each certificate has:

- A unique ID based on the associated key pair
- Metadata including subject information, validity period, and purpose
- The certificate data in PEM format

### Certificate Verification

The system verifies certificates by:

1. Checking the certificate signature against trusted certificates
2. Validating the certificate chain
3. Checking the validity period (not expired and not yet valid)

## Security Considerations

- Self-signed certificates should only be used for testing or in controlled environments
- For production use, certificates should be signed by a trusted Certificate Authority (CA)
- Certificate revocation checking is not yet implemented but will be added in a future update
- Private keys used for certificate generation should be protected with strong access controls

## Troubleshooting

### Common Issues

#### "Private key with ID not found" Error

If you encounter an error like "Private key with ID test_key.private not found" when trying to generate a certificate, it means the key storage system doesn't have the private key registered. This can happen for several reasons:

1. The key storage hasn't been initialized properly
2. The key wasn't saved to the key storage
3. You're using a different key storage than where the key was saved

**Solution**: Use the `--key-file` option to directly specify a private key file:

```
python -m src.ui.cli cert generate --key your_key.private --key-file --common-name example.com [...other options...] --output certificate.pem
```

#### Key Storage Initialization Issues

If you encounter errors related to key storage initialization, such as "Failed to save key storage: No such file or directory", it might be because the directory for storing keys doesn't exist.

**Solution**: Create the directory manually before initializing the key storage:

```
mkdir -p "C:\Users\YourUsername\.secure_crypto"
python -m src.ui.cli init-storage
```

#### Certificate Generation Success

When certificate generation is successful, you should see output like:

```
Certificate generated successfully.
Certificate saved to: certificate.pem
```

You can verify the certificate content using OpenSSL (if installed):

```
openssl x509 -in certificate.pem -text -noout
```

Or simply open the file to confirm it contains a valid PEM-encoded certificate that starts with "-----BEGIN CERTIFICATE-----" and ends with "-----END CERTIFICATE-----".
