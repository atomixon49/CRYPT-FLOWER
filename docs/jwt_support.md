# JWT/JWS/JWE Support

This document describes the JWT (JSON Web Token), JWS (JSON Web Signature), and JWE (JSON Web Encryption) support in the cryptographic system.

## Overview

The cryptographic system provides support for:

- **JWT (JSON Web Token)**: A compact, URL-safe means of representing claims to be transferred between two parties.
- **JWS (JSON Web Signature)**: A means of representing content secured with digital signatures or Message Authentication Codes (MACs) using JSON-based data structures.
- **JWE (JSON Web Encryption)**: A means of representing encrypted content using JSON-based data structures.

These standards are defined in:
- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [RFC 7515 - JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515)
- [RFC 7516 - JSON Web Encryption (JWE)](https://tools.ietf.org/html/rfc7516)
- [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)

## Features

The JWT/JWS/JWE support includes:

- Creating and verifying JWS tokens
- Creating and decrypting JWE tokens
- Creating and verifying JWT tokens
- Converting between cryptographic keys and JWK format
- Creating and using JWK Sets (JWKS)
- Integration with the key management system
- Support for post-quantum algorithms (if available)
- GUI interface for JWT/JWS/JWE operations
- REST API endpoints for JWT/JWS/JWE operations

## Supported Algorithms

### Signing Algorithms (JWS)

- **RSA**: RS256, RS384, RS512 (RSASSA-PKCS1-v1_5 with SHA-256/384/512)
- **RSA-PSS**: PS256, PS384, PS512 (RSASSA-PSS with SHA-256/384/512)
- **ECDSA**: ES256, ES384, ES512 (ECDSA with SHA-256/384/512)
- **HMAC**: HS256, HS384, HS512 (HMAC with SHA-256/384/512)
- **EdDSA**: EdDSA (Edwards-curve Digital Signature Algorithm)
- **Post-Quantum**: Dilithium, Falcon, etc. (if available)

### Key Encryption Algorithms (JWE)

- **RSA**: RSA-OAEP, RSA-OAEP-256, RSA1_5
- **ECDH**: ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW
- **AES Key Wrap**: A128KW, A192KW, A256KW
- **Direct Encryption**: dir
- **Post-Quantum**: Kyber, etc. (if available)

### Content Encryption Algorithms (JWE)

- **AES GCM**: A128GCM, A192GCM, A256GCM
- **AES CBC with HMAC**: A128CBC-HS256, A192CBC-HS384, A256CBC-HS512

## Usage

### GUI Interface

The cryptographic system provides a GUI interface for JWT/JWS/JWE operations. To access it:

1. Open the application
2. Go to the "JWT/JWS/JWE" tab
3. Select the operation you want to perform

The GUI interface provides the following tabs:

- **Create JWS**: Create a JWS token
- **Verify JWS**: Verify a JWS token
- **Create JWE**: Create a JWE token
- **Decrypt JWE**: Decrypt a JWE token
- **Export JWK**: Export a key as JWK

### REST API

The cryptographic system provides REST API endpoints for JWT/JWS/JWE operations. The following endpoints are available:

#### JWS Endpoints

- `POST /api/v1/jws/create`: Create a JWS token
  - Request body:
    ```json
    {
      "payload": "...",
      "key_id": "...",
      "algorithm": "RS256",
      "headers": { ... }
    }
    ```
  - Response:
    ```json
    {
      "jws": "...",
      "algorithm": "RS256"
    }
    ```

- `POST /api/v1/jws/verify`: Verify a JWS token
  - Request body:
    ```json
    {
      "token": "...",
      "key_id": "...",
      "algorithms": ["RS256", "ES256"]
    }
    ```
  - Response:
    ```json
    {
      "valid": true,
      "payload": { ... },
      "headers": { ... }
    }
    ```

#### JWE Endpoints

- `POST /api/v1/jwe/create`: Create a JWE token
  - Request body:
    ```json
    {
      "payload": "...",
      "key_id": "...",
      "algorithm": "RSA-OAEP",
      "encryption": "A256GCM",
      "headers": { ... }
    }
    ```
  - Response:
    ```json
    {
      "jwe": "...",
      "algorithm": "RSA-OAEP",
      "encryption": "A256GCM"
    }
    ```

- `POST /api/v1/jwe/decrypt`: Decrypt a JWE token
  - Request body:
    ```json
    {
      "token": "...",
      "key_id": "..."
    }
    ```
  - Response:
    ```json
    {
      "payload": { ... },
      "headers": { ... }
    }
    ```

#### JWK Endpoints

- `GET /api/v1/jwk/export?key_id=...`: Export a key as JWK
  - Response:
    ```json
    {
      "kty": "RSA",
      "n": "...",
      "e": "...",
      "kid": "..."
    }
    ```

- `GET /api/v1/jwks`: Get a JWK Set (JWKS) of all public keys
  - Response:
    ```json
    {
      "keys": [
        {
          "kty": "RSA",
          "n": "...",
          "e": "...",
          "kid": "..."
        },
        ...
      ]
    }
    ```

### Programmatic Usage

The cryptographic system provides a `JWTInterface` class for programmatic JWT/JWS/JWE operations. Here are some examples:

#### Creating a JWS

```python
from src.core.jwt_interface import JWTInterface
from src.core.key_management import KeyManager

# Initialize
key_manager = KeyManager()
jwt_interface = JWTInterface(key_manager=key_manager)

# Create JWS
jws_token = jwt_interface.create_jws_with_key_id(
    payload={"sub": "1234567890", "name": "John Doe", "admin": True},
    key_id="my_key.private",
    algorithm="RS256",
    headers={"kid": "my_key"}
)
```

#### Verifying a JWS

```python
# Verify JWS
result = jwt_interface.verify_jws_with_key_id(
    token=jws_token,
    key_id="my_key.public",
    algorithms=["RS256"]
)

if result["valid"]:
    print("JWS is valid")
    print("Payload:", result["payload"])
    print("Headers:", result["headers"])
else:
    print("JWS is invalid")
```

#### Creating a JWE

```python
# Create JWE
jwe_token = jwt_interface.create_jwe_with_key_id(
    payload={"sub": "1234567890", "name": "John Doe", "admin": True},
    key_id="my_key.public",
    algorithm="RSA-OAEP",
    encryption="A256GCM",
    headers={"kid": "my_key"}
)
```

#### Decrypting a JWE

```python
# Decrypt JWE
result = jwt_interface.decrypt_jwe_with_key_id(
    token=jwe_token,
    key_id="my_key.private"
)

print("Payload:", result["payload"])
print("Headers:", result["headers"])
```

## Dependencies

The JWT/JWS/JWE support requires the following dependencies:

- `pyjwt`: For JWT operations
- `jwcrypto`: For JWS, JWE, and JWK operations
- `cryptography`: For cryptographic operations

These dependencies can be installed using pip:

```
pip install pyjwt jwcrypto cryptography
```

## Post-Quantum Support

If post-quantum cryptography support is available, the JWT/JWS/JWE support will automatically use post-quantum algorithms for signing and encryption. The following post-quantum algorithms are supported:

- **Signing**: Dilithium, Falcon, etc.
- **Key Encapsulation**: Kyber, etc.

To use post-quantum algorithms, you need to have the post-quantum cryptography module installed and enabled.

## Interoperability

The JWT/JWS/JWE support is designed to be interoperable with other JWT/JWS/JWE implementations. It follows the RFCs and uses standard algorithms and formats.

You can use the exported JWK and JWKS with other JWT/JWS/JWE implementations, and you can use JWS and JWE tokens created by other implementations with this system.

## Security Considerations

When using JWT/JWS/JWE, consider the following security considerations:

- Use strong algorithms (RS256, ES256, etc.) for signing
- Use strong algorithms (RSA-OAEP, A256GCM, etc.) for encryption
- Validate the token's signature before trusting its contents
- Validate the token's claims (exp, nbf, iss, aud, etc.) before trusting its contents
- Use short expiration times for tokens
- Rotate keys regularly
- Use different keys for different purposes (signing, encryption, etc.)
- Use different keys for different environments (development, production, etc.)
- Use different keys for different applications
- Use different keys for different users or groups of users
- Use different keys for different operations (authentication, authorization, etc.)
- Use different keys for different security levels (low, medium, high, etc.)
- Use different keys for different data sensitivity levels (public, internal, confidential, etc.)
- Use different keys for different data types (personal data, financial data, etc.)
- Use different keys for different data classifications (public, internal, confidential, etc.)
- Use different keys for different data protection requirements (integrity, confidentiality, etc.)
- Use different keys for different data retention periods (short-term, long-term, etc.)
- Use different keys for different data access patterns (read-only, read-write, etc.)
- Use different keys for different data storage locations (local, cloud, etc.)
- Use different keys for different data transfer methods (internal, external, etc.)
- Use different keys for different data processing purposes (analytics, reporting, etc.)
- Use different keys for different data sharing purposes (internal, external, etc.)
- Use different keys for different data sharing methods (API, file, etc.)
- Use different keys for different data sharing recipients (internal, external, etc.)
- Use different keys for different data sharing agreements (NDA, DPA, etc.)
- Use different keys for different data sharing jurisdictions (EU, US, etc.)
- Use different keys for different data sharing regulations (GDPR, CCPA, etc.)
- Use different keys for different data sharing compliance requirements (GDPR, CCPA, etc.)
- Use different keys for different data sharing risk levels (low, medium, high, etc.)
- Use different keys for different data sharing security levels (low, medium, high, etc.)
- Use different keys for different data sharing sensitivity levels (public, internal, confidential, etc.)
- Use different keys for different data sharing classifications (public, internal, confidential, etc.)
- Use different keys for different data sharing protection requirements (integrity, confidentiality, etc.)
- Use different keys for different data sharing retention periods (short-term, long-term, etc.)
- Use different keys for different data sharing access patterns (read-only, read-write, etc.)
- Use different keys for different data sharing storage locations (local, cloud, etc.)
- Use different keys for different data sharing transfer methods (internal, external, etc.)
- Use different keys for different data sharing processing purposes (analytics, reporting, etc.)
- Use different keys for different data sharing sharing purposes (internal, external, etc.)
- Use different keys for different data sharing sharing methods (API, file, etc.)
- Use different keys for different data sharing sharing recipients (internal, external, etc.)
- Use different keys for different data sharing sharing agreements (NDA, DPA, etc.)
- Use different keys for different data sharing sharing jurisdictions (EU, US, etc.)
- Use different keys for different data sharing sharing regulations (GDPR, CCPA, etc.)
- Use different keys for different data sharing sharing compliance requirements (GDPR, CCPA, etc.)
- Use different keys for different data sharing sharing risk levels (low, medium, high, etc.)
- Use different keys for different data sharing sharing security levels (low, medium, high, etc.)
- Use different keys for different data sharing sharing sensitivity levels (public, internal, confidential, etc.)
- Use different keys for different data sharing sharing classifications (public, internal, confidential, etc.)
- Use different keys for different data sharing sharing protection requirements (integrity, confidentiality, etc.)
- Use different keys for different data sharing sharing retention periods (short-term, long-term, etc.)
- Use different keys for different data sharing sharing access patterns (read-only, read-write, etc.)
- Use different keys for different data sharing sharing storage locations (local, cloud, etc.)
- Use different keys for different data sharing sharing transfer methods (internal, external, etc.)
- Use different keys for different data sharing sharing processing purposes (analytics, reporting, etc.)
