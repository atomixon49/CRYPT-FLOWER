# Post-Quantum Cryptography Support

This document describes the post-quantum cryptography support in the system.

## Overview

The system supports post-quantum cryptographic algorithms through integration with the liboqs library. These algorithms are designed to be secure against attacks from quantum computers, which could potentially break many of the cryptographic algorithms in use today.

## Supported Algorithms

### Key Encapsulation Mechanisms (KEMs)

- **Kyber**: A lattice-based KEM that is one of the finalists in the NIST Post-Quantum Cryptography standardization process.
  - Kyber512: NIST security level 1 (equivalent to AES-128)
  - Kyber768: NIST security level 3 (equivalent to AES-192)
  - Kyber1024: NIST security level 5 (equivalent to AES-256)

### Digital Signature Algorithms

- **Dilithium**: A lattice-based signature scheme that is one of the finalists in the NIST Post-Quantum Cryptography standardization process.
  - Dilithium2: NIST security level 2
  - Dilithium3: NIST security level 3
  - Dilithium5: NIST security level 5

## Requirements

To use post-quantum cryptography, you need:

1. The liboqs-python library:
   ```
   pip install liboqs
   ```

2. The liboqs C library, which is automatically installed with liboqs-python on most platforms.

## Usage with HSMs

The system supports using post-quantum algorithms with Hardware Security Modules (HSMs) through the PKCS#11 interface. Since most HSMs don't natively support post-quantum algorithms yet, the system uses a hybrid approach:

1. Post-quantum keys are generated using the liboqs library
2. The keys are stored in the HSM as raw data objects
3. Cryptographic operations are performed using the liboqs library
4. The HSM provides secure storage for the keys

## API Usage

### Generating Post-Quantum Keys

```http
POST /api/v1/hsm/keys
Authorization: Bearer <token>
Content-Type: application/json

{
  "key_type": "KYBER",
  "key_size": 768,
  "key_label": "my_pq_key",
  "extractable": false,
  "post_quantum": true
}
```

Response:

```json
{
  "key_id": "hsm:1234567890abcdef",
  "key_type": "KYBER",
  "key_label": "my_pq_key",
  "algorithm": "KYBER768",
  "extractable": false,
  "post_quantum": true
}
```

### Key Encapsulation

```http
POST /api/v1/hsm/encapsulate
Authorization: Bearer <token>
Content-Type: application/json

{
  "key_id": "hsm:1234567890abcdef",
  "algorithm": "KYBER768"
}
```

Response:

```json
{
  "ciphertext": "...",
  "shared_secret_id": "hsm:shared_secret_1234"
}
```

### Digital Signatures

```http
POST /api/v1/hsm/sign
Authorization: Bearer <token>
Content-Type: application/json

{
  "data": "SGVsbG8gV29ybGQh",
  "key_id": "hsm:dilithium_key",
  "algorithm": "DILITHIUM3"
}
```

Response:

```json
{
  "signature": "...",
  "algorithm": "DILITHIUM3"
}
```

## Security Considerations

- Post-quantum algorithms generally have larger key sizes and signature/ciphertext sizes than traditional algorithms
- The security of post-quantum algorithms is still being evaluated by the cryptographic community
- Consider using hybrid approaches that combine traditional and post-quantum algorithms for critical applications
- Keep the system updated to use the latest versions of post-quantum algorithms as they evolve
