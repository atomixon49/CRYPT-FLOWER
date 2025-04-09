# API Documentation

The cryptographic system provides a RESTful API for integrating with external applications. This document describes the available endpoints and how to use them.

## Authentication

All API endpoints require authentication using a JWT token. To authenticate, you need to:

1. Obtain a JWT token by calling the `/api/v1/auth/login` endpoint with your username and password.
2. Include the token in the `Authorization` header of your requests in the format `Bearer <token>`.

Example:

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "password"
}
```

Response:

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 3600
}
```

## Swagger Documentation

The API is documented using Swagger/OpenAPI. You can access the Swagger UI at `/api/docs/` when the API is running.

## Endpoints

### Encryption/Decryption

- `POST /api/v1/encrypt`: Encrypt data
- `POST /api/v1/decrypt`: Decrypt data
- `POST /api/v1/encrypt_file`: Encrypt a file
- `POST /api/v1/decrypt_file`: Decrypt a file

### Signatures

- `POST /api/v1/sign`: Sign data
- `POST /api/v1/verify`: Verify a signature
- `POST /api/v1/sign_file`: Sign a file
- `POST /api/v1/verify_file`: Verify a file signature

### Key Management

- `GET /api/v1/keys`: List all keys
- `POST /api/v1/keys/generate`: Generate a new key
- `GET /api/v1/keys/{key_id}`: Get a key
- `DELETE /api/v1/keys/{key_id}`: Delete a key
- `POST /api/v1/keys/import`: Import a key
- `GET /api/v1/keys/export/{key_id}`: Export a key

### JWT/JWS/JWE

- `POST /api/v1/jws/create`: Create a JWS token
- `POST /api/v1/jws/verify`: Verify a JWS token
- `POST /api/v1/jwe/create`: Create a JWE token
- `POST /api/v1/jwe/decrypt`: Decrypt a JWE token
- `GET /api/v1/jwk/export`: Export a key as JWK
- `GET /api/v1/jwks`: Get a JWK Set (JWKS) of all public keys

## JWS Endpoints

### Create JWS

Creates a JSON Web Signature (JWS) token.

**Endpoint:** `POST /api/v1/jws/create`

**Request:**

```json
{
  "payload": {
    "sub": "1234567890",
    "name": "John Doe",
    "admin": true
  },
  "key_id": "my_key.private",
  "algorithm": "RS256",
  "headers": {
    "kid": "my_key"
  }
}
```

**Response:**

```json
{
  "jws": "eyJhbGciOiJSUzI1NiIsImtpZCI6Im15X2tleSJ9...",
  "algorithm": "RS256"
}
```

### Verify JWS

Verifies a JSON Web Signature (JWS) token.

**Endpoint:** `POST /api/v1/jws/verify`

**Request:**

```json
{
  "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Im15X2tleSJ9...",
  "key_id": "my_key.public",
  "algorithms": ["RS256", "ES256"]
}
```

**Response:**

```json
{
  "valid": true,
  "payload": {
    "sub": "1234567890",
    "name": "John Doe",
    "admin": true
  },
  "headers": {
    "alg": "RS256",
    "kid": "my_key"
  }
}
```

## JWE Endpoints

### Create JWE

Creates a JSON Web Encryption (JWE) token.

**Endpoint:** `POST /api/v1/jwe/create`

**Request:**

```json
{
  "payload": {
    "sub": "1234567890",
    "name": "John Doe",
    "admin": true
  },
  "key_id": "my_key.public",
  "algorithm": "RSA-OAEP",
  "encryption": "A256GCM",
  "headers": {
    "kid": "my_key"
  }
}
```

**Response:**

```json
{
  "jwe": "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00iLCJraWQiOiJteV9rZXkifQ...",
  "algorithm": "RSA-OAEP",
  "encryption": "A256GCM"
}
```

### Decrypt JWE

Decrypts a JSON Web Encryption (JWE) token.

**Endpoint:** `POST /api/v1/jwe/decrypt`

**Request:**

```json
{
  "token": "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00iLCJraWQiOiJteV9rZXkifQ...",
  "key_id": "my_key.private"
}
```

**Response:**

```json
{
  "payload": {
    "sub": "1234567890",
    "name": "John Doe",
    "admin": true
  },
  "headers": {
    "alg": "RSA-OAEP",
    "enc": "A256GCM",
    "kid": "my_key"
  }
}
```

## JWK Endpoints

### Export JWK

Exports a cryptographic key as a JSON Web Key (JWK).

**Endpoint:** `GET /api/v1/jwk/export?key_id=my_key.public`

**Response:**

```json
{
  "kty": "RSA",
  "n": "...",
  "e": "AQAB",
  "kid": "my_key.public"
}
```

### Get JWKS

Gets a JSON Web Key Set (JWKS) containing all public keys.

**Endpoint:** `GET /api/v1/jwks`

**Response:**

```json
{
  "keys": [
    {
      "kty": "RSA",
      "n": "...",
      "e": "AQAB",
      "kid": "my_key.public"
    },
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "...",
      "kid": "my_ec_key.public"
    }
  ]
}
```

## Error Handling

All API endpoints return appropriate HTTP status codes and error messages in case of errors. The error response has the following format:

```json
{
  "error": "Error message"
}
```

Common error codes:

- `400 Bad Request`: The request is invalid
- `401 Unauthorized`: Authentication is required
- `403 Forbidden`: The authenticated user does not have permission to access the resource
- `404 Not Found`: The requested resource was not found
- `500 Internal Server Error`: An error occurred on the server

## Rate Limiting

The API has rate limiting to prevent abuse. If you exceed the rate limit, you will receive a `429 Too Many Requests` response.

## CORS

The API supports Cross-Origin Resource Sharing (CORS), allowing it to be used from web applications hosted on different domains.

## API Versioning

The API is versioned using the URL path. The current version is `v1`, as indicated by the `/api/v1/` prefix in the endpoints.

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
