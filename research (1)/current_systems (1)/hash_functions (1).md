# Cryptographic Hash Functions

## Overview
Cryptographic hash functions convert data of arbitrary size to a fixed-size output (hash value). They are one-way functions, meaning it should be computationally infeasible to reverse the process or find two different inputs that produce the same output.

## Key Properties
1. **Pre-image resistance**: Given a hash value h, it should be difficult to find any message m such that hash(m) = h
2. **Second pre-image resistance**: Given an input m1, it should be difficult to find another input m2 such that hash(m1) = hash(m2)
3. **Collision resistance**: It should be difficult to find two different messages m1 and m2 such that hash(m1) = hash(m2)

## Common Hash Functions

### MD5 (Message Digest Algorithm 5)
- **Output Size**: 128 bits
- **Status**: Broken, should not be used for security purposes
- **Weaknesses**:
  - Collision attacks are practical
  - Pre-image resistance compromised
  - Too short for modern security requirements

### SHA-1 (Secure Hash Algorithm 1)
- **Output Size**: 160 bits
- **Status**: Deprecated, collision attacks demonstrated
- **Weaknesses**:
  - Practical collision attacks demonstrated (SHAttered attack)
  - No longer considered secure for digital signatures

### SHA-2 Family
- **Variants**: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256
- **Output Sizes**: 224, 256, 384, or 512 bits
- **Status**: Currently secure and widely used
- **Strengths**:
  - Well-analyzed and standardized
  - No practical attacks on full algorithm
- **Weaknesses**:
  - Similar structure to SHA-1 (theoretical concern)
  - Not as fast as some newer hash functions

### SHA-3 Family
- **Variants**: SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256
- **Output Sizes**: Variable (224, 256, 384, 512 bits for standard variants)
- **Status**: Secure, NIST standard
- **Strengths**:
  - Based on different design (sponge construction)
  - Resistant to attacks that work against SHA-2
  - Extendable output functions (SHAKE variants)
- **Weaknesses**:
  - Slower than SHA-2 in some software implementations

### BLAKE2
- **Variants**: BLAKE2s (optimized for 32-bit), BLAKE2b (optimized for 64-bit)
- **Output Sizes**: Variable, up to 256 bits (BLAKE2s) or 512 bits (BLAKE2b)
- **Status**: Secure, widely used
- **Strengths**:
  - Faster than MD5 while being secure
  - Parallelizable
  - Can function as a MAC with a key
- **Weaknesses**:
  - Less standardized than SHA-2/SHA-3

## Applications

### Data Integrity
- File checksums
- Message integrity verification
- Software distribution verification

### Password Storage
- Storing password hashes (with salt and appropriate work factors)
- Key derivation functions (PBKDF2, bcrypt, scrypt, Argon2)

### Digital Signatures
- Hash-then-sign paradigm
- Certificate validation

### Proof of Work
- Blockchain mining
- Spam prevention

## Current Best Practices
- Use SHA-256 or SHA-3 for general purpose applications
- Use BLAKE2 when performance is critical
- For password hashing, use specialized functions (Argon2, bcrypt)
- Always use cryptographically secure hash functions for security applications
- Consider using HMAC construction when using hashes for message authentication

## Further Research Needed
- Quantum resistance of current hash functions
- Optimizations for specific hardware
- Specialized hash functions for constrained environments
