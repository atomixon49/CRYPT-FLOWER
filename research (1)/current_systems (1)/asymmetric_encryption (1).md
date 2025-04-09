# Asymmetric Encryption Algorithms

## Overview
Asymmetric encryption (also known as public-key cryptography) uses a pair of keys: a public key for encryption and a private key for decryption. This solves the key distribution problem of symmetric encryption but is typically slower.

## Common Algorithms

### RSA (Rivest-Shamir-Adleman)
- **Key Sizes**: 2048, 3072, or 4096 bits commonly used
- **Security Basis**: Integer factorization problem
- **Strengths**:
  - Well-established and widely implemented
  - Supports both encryption and digital signatures
  - Relatively simple concept
- **Weaknesses**:
  - Slow compared to symmetric algorithms
  - Vulnerable to quantum computing attacks
  - Key sizes must be large for security
  - Implementation vulnerabilities (padding, etc.)

### ECC (Elliptic Curve Cryptography)
- **Key Sizes**: 256-384 bits
- **Security Basis**: Elliptic curve discrete logarithm problem
- **Strengths**:
  - Smaller key sizes for equivalent security
  - Faster than RSA for equivalent security
  - Lower computational requirements
- **Weaknesses**:
  - More complex implementation
  - Some curves potentially compromised
  - Also vulnerable to quantum computing

### Diffie-Hellman Key Exchange
- **Purpose**: Secure key exchange over insecure channel
- **Security Basis**: Discrete logarithm problem
- **Strengths**:
  - Allows secure key agreement without prior shared secrets
  - Foundation for many secure protocols
- **Weaknesses**:
  - Vulnerable to man-in-the-middle attacks without authentication
  - Original version vulnerable to quantum computing

### ElGamal
- **Security Basis**: Discrete logarithm problem
- **Strengths**:
  - Probabilistic encryption (different ciphertexts for same plaintext)
  - Can be adapted to elliptic curves
- **Weaknesses**:
  - Ciphertext size is twice the plaintext size
  - Slower than RSA for some operations

## Post-Quantum Cryptography

### Lattice-Based Cryptography
- **Examples**: NTRU, CRYSTALS-Kyber
- **Security Basis**: Hardness of lattice problems
- **Status**: Promising candidate for quantum-resistant cryptography

### Hash-Based Cryptography
- **Examples**: SPHINCS+
- **Security Basis**: Properties of cryptographic hash functions
- **Status**: Conservative approach with well-understood security properties

### Code-Based Cryptography
- **Examples**: McEliece
- **Security Basis**: Hardness of decoding random linear codes
- **Status**: Long-established but has large key sizes

### Multivariate Cryptography
- **Examples**: Rainbow
- **Security Basis**: Difficulty of solving multivariate polynomial equations
- **Status**: Compact signatures but large key sizes

## Current Best Practices
- Use RSA-3072 or ECC P-384 for most current applications
- Implement proper key validation
- Use established libraries with constant-time implementations
- Begin planning for post-quantum transition
- Use hybrid approaches for critical systems

## Further Research Needed
- Practical implementations of post-quantum algorithms
- Performance optimizations for constrained environments
- Standardization of quantum-resistant algorithms
- Migration strategies from current to post-quantum systems
