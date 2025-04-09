# Secure Cryptography System

A modern, secure cryptographic system designed to address vulnerabilities in existing cryptographic solutions. This system provides robust encryption and decryption capabilities for both text and PDF files.

## Overview

This project aims to create a comprehensive cryptographic solution that addresses the weaknesses in current systems while providing a user-friendly experience. The system implements state-of-the-art encryption algorithms with proper authentication, secure key management, and support for various file formats.

## Current Features

- Strong encryption using AES-GCM and ChaCha20-Poly1305
- Secure key management
- Digital signatures using RSA-PSS
- Support for text and PDF files
- Command-line interface
- Post-quantum security considerations

## Planned Improvements

Based on our testing and evaluation, we're working on the following improvements:

- **Secure Key Storage**: Persistent key storage between sessions with master password protection
- **Improved Password-Based Encryption**: Better handling of salt and key derivation
- **Cross-Platform File Type Detection**: Reliable file type detection across operating systems
- **Enhanced PDF Support**: Selective encryption of PDF sections and metadata preservation
- **Directory Encryption**: Support for encrypting entire directories while preserving structure
- **Graphical User Interface**: User-friendly GUI for all operations
- **System Integration**: File explorer integration for easy access
- **Post-Quantum Algorithms**: Implementation of quantum-resistant cryptographic algorithms

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd secure-cryptography-system
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Encrypting a File

```
python -m src.main encrypt myfile.txt
```

### Decrypting a File

```
python -m src.main decrypt myfile.txt.encrypted
```

### Encrypting a PDF File

```
python -m src.main encrypt --type pdf document.pdf
```

### Generating a Key Pair for Signatures

```
python -m src.main genkey --output mykey
```

### Signing a File

```
python -m src.main sign --key mykey.private myfile.txt
```

### Verifying a Signature

```
python -m src.main verify --key mykey.public myfile.txt myfile.txt.sig
```

## Security Considerations

This system implements several security best practices:

- Authenticated encryption for all operations
- Secure key generation and management
- Protection against side-channel attacks
- Proper error handling without information leakage
- Consideration for post-quantum security

## Project Structure

- `src/core/`: Core cryptographic functionality
- `src/file_handlers/`: File handling for different file types
- `src/utils/`: Utility functions
- `src/ui/`: User interface components
- `docs/`: Documentation
- `tests/`: Test cases
- `research/`: Research on cryptographic systems and vulnerabilities

## Development

### Running Tests

```
python -m unittest discover tests
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

[MIT License](LICENSE)

## Acknowledgments

This project was developed as part of a comprehensive study of cryptographic systems and their vulnerabilities.
