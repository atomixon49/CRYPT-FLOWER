# HSM Support

This document describes the Hardware Security Module (HSM) support in the cryptographic system.

## Overview

The system supports Hardware Security Modules (HSMs) through the PKCS#11 standard. This allows for secure key storage and cryptographic operations using hardware-backed keys, providing an additional layer of security for sensitive operations.

## Requirements

To use HSM support, you need:

1. A PKCS#11-compatible HSM device or software
2. The PKCS#11 library for your HSM
3. The `python-pkcs11` library installed:
   ```
   pip install python-pkcs11
   ```

## Configuration

HSM support is configured through environment variables or the configuration file:

- `HSM_LIBRARY_PATH`: Path to the PKCS#11 library (.so, .dll, .dylib)
- `HSM_TOKEN_LABEL`: Label of the token to use (optional)
- `HSM_PIN`: PIN for the token (optional)

Example:

```bash
export HSM_LIBRARY_PATH=/usr/local/lib/softhsm/libsofthsm2.so
export HSM_TOKEN_LABEL=my_token
export HSM_PIN=1234
```

## API Endpoints

The following API endpoints are available for HSM operations:

- `GET /api/v1/hsm/slots`: List available HSM slots
- `GET /api/v1/hsm/keys`: List keys on the HSM
- `POST /api/v1/hsm/keys`: Generate a key on the HSM
- `POST /api/v1/hsm/encrypt`: Encrypt data using an HSM key
- `POST /api/v1/hsm/decrypt`: Decrypt data using an HSM key
- `POST /api/v1/hsm/sign`: Sign data using an HSM key
- `POST /api/v1/hsm/verify`: Verify a signature using an HSM key
- `DELETE /api/v1/hsm/keys/<key_id>`: Delete a key from the HSM

## Usage Examples

### List HSM Slots

```http
GET /api/v1/hsm/slots
Authorization: Bearer <token>
```

Response:

```json
{
  "slots": [
    {
      "id": 0,
      "description": "SoftHSM slot 0",
      "manufacturer": "SoftHSM",
      "has_token": true,
      "token_label": "my_token",
      "token_model": "SoftHSM v2"
    }
  ]
}
```

### Generate a Key on the HSM

```http
POST /api/v1/hsm/keys
Authorization: Bearer <token>
Content-Type: application/json

{
  "key_type": "RSA",
  "key_size": 2048,
  "key_label": "my_hsm_key",
  "extractable": false
}
```

Response:

```json
{
  "key_id": "hsm:1234567890abcdef",
  "key_type": "RSA",
  "key_label": "my_hsm_key",
  "algorithm": "RSA",
  "extractable": false
}
```

### Encrypt Data Using an HSM Key

```http
POST /api/v1/hsm/encrypt
Authorization: Bearer <token>
Content-Type: application/json

{
  "data": "SGVsbG8gV29ybGQh",
  "key_id": "hsm:1234567890abcdef",
  "algorithm": "AES-GCM"
}
```

Response:

```json
{
  "algorithm": "AES-GCM",
  "ciphertext": "...",
  "iv": "...",
  "tag": "..."
}
```

## Integration with Key Management

HSM-backed keys are integrated with the key management system and can be used like any other key in the system. They are identified by the prefix `hsm:` followed by the HSM key ID.

## Security Considerations

- The HSM PIN is sensitive information and should be protected
- Use hardware HSMs in production for maximum security
- Consider using a key management system that supports key rotation for HSM keys
- Regularly audit HSM key usage through the system's audit logs
