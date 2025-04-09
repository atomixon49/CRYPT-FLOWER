# Error Tracking

This document tracks errors encountered during the project, their causes, and solutions.

## Error Template
```
### [Error ID]: [Error Title]
- **Date**: [Date encountered]
- **Category**: [Implementation/Design/Security/Other]
- **Description**: [Detailed description of the error]
- **Root Cause**: [Analysis of what caused the error]
- **Solution**: [How the error was resolved]
- **Prevention**: [Steps to prevent similar errors in the future]
```

## Current Errors

### ERR-006: PDF Section Encryption Parameter Mismatch
- **Date**: 2025-04-16
- **Category**: Implementation
- **Description**: Durante las pruebas de la encriptación selectiva de secciones de PDF, se encontró que la función de desencriptación fallaba con un error de tipo `TypeError: EncryptionEngine.decrypt() got an unexpected keyword argument 'ciphertext'`.
- **Root Cause**: La función `decrypt_pages` del `PDFSectionHandler` estaba pasando parámetros con nombre directamente a `EncryptionEngine.decrypt()`, pero esta función espera un diccionario `encryption_result` en lugar de parámetros individuales.
- **Solution**: Se modificó el código para crear un diccionario `encryption_result` con todos los parámetros necesarios y pasarlo a la función `decrypt`.
- **Prevention**: Revisar cuidadosamente las firmas de las funciones antes de llamarlas, especialmente cuando se trabaja con APIs internas.

### ERR-007: PDF Page Replacement Error
- **Date**: 2025-04-16
- **Category**: Implementation
- **Description**: Al intentar reemplazar páginas en un documento PDF durante la desencriptación, se producía un error `AttributeError: __setitem__`.
- **Root Cause**: La biblioteca pypdf ha cambiado su API y ya no permite asignar páginas directamente usando la sintaxis `pdf_writer.pages[index] = page`.
- **Solution**: Se implementó un enfoque alternativo que crea un nuevo `PdfWriter` y copia todas las páginas, reemplazando las páginas encriptadas con sus versiones desencriptadas.
- **Prevention**: Mantenerse actualizado con los cambios en las bibliotecas de terceros y probar exhaustivamente cuando se actualicen las dependencias.

### ERR-008: GUI Key Management Integration Error
- **Date**: 2025-04-17
- **Category**: Implementation
- **Description**: Al intentar generar claves desde la interfaz gráfica, se producía un error porque el ID de la clave no se podía recuperar correctamente después de la generación.
- **Root Cause**: El método para obtener el ID de la clave recién generada no era robusto, especialmente para claves asimétricas donde se generan dos entradas (pública y privada).
- **Solution**: Se mejoró la lógica para recuperar el ID de la clave, utilizando el último elemento de la lista de claves activas para claves simétricas, y para claves asimétricas, extrayendo el ID base de los últimos dos elementos añadidos.
- **Prevention**: Implementar métodos más robustos para rastrear y recuperar identificadores de objetos recién creados.

### ERR-009: PDF Rendering in GUI
- **Date**: 2025-04-17
- **Category**: Implementation
- **Description**: La visualización de miniaturas de páginas PDF en la interfaz gráfica no funcionaba correctamente porque la biblioteca pypdf no proporciona funcionalidad de renderizado directa.
- **Root Cause**: La biblioteca pypdf está diseñada principalmente para manipulación de PDF, no para renderizado visual.
- **Solution**: Se implementó una solución alternativa que utiliza PyQt para dibujar representaciones simples de las páginas cuando no es posible el renderizado directo. Para una implementación completa, se recomienda usar bibliotecas como PyMuPDF (fitz) o poppler-qt5.
- **Prevention**: Investigar y evaluar las capacidades de las bibliotecas antes de integrarlas en funcionalidades que pueden requerir características específicas.

### ERR-012: Post-Quantum Library Dependency
- **Date**: 2025-04-19
- **Category**: Implementation
- **Description**: Al intentar implementar soporte para criptografía post-cuántica, se encontró que la biblioteca `pyoqs` no está disponible directamente a través de pip.
- **Root Cause**: La biblioteca `pyoqs` requiere la compilación de `liboqs` como dependencia, lo que puede ser complicado en algunos sistemas operativos.
- **Solution**: Se optó por utilizar la biblioteca `pqcrypto` como alternativa, que proporciona implementaciones de algoritmos post-cuánticos en Python puro sin dependencias de compilación.
- **Prevention**: Investigar a fondo las dependencias de las bibliotecas antes de integrarlas, especialmente cuando involucran componentes nativos que requieren compilación.

## Resolved Errors

### ERR-010: Directory Handler Parameter Mismatch
- **Date**: 2025-04-18
- **Category**: Implementation
- **Description**: Al implementar la encriptación de directorios, se encontró un error al pasar el parámetro `key_id` a los métodos `encrypt_file` y `decrypt_file` del `TextFileHandler`.
- **Root Cause**: Los métodos `encrypt_file` y `decrypt_file` del `TextFileHandler` no aceptan el parámetro `key_id`, mientras que el `DirectoryHandler` intentaba pasarlo.
- **Solution**: Se modificó el `DirectoryHandler` para llamar a los métodos de encriptación y desencriptación con los parámetros correctos, dependiendo de si se usa contraseña o clave.
- **Prevention**: Revisar cuidadosamente las firmas de los métodos antes de llamarlos, especialmente cuando se integran diferentes componentes del sistema.
- **Status**: Resuelto en la versión 1.5.0

### ERR-011: Directory Decryption Error Handling
- **Date**: 2025-04-18
- **Category**: Implementation
- **Description**: Las pruebas de desencriptación de directorios con claves o contraseñas incorrectas no fallan como se esperaba, lo que indica que el manejo de errores no es adecuado.
- **Root Cause**: El `DirectoryHandler` captura las excepciones durante la desencriptación y continúa con otros archivos, en lugar de propagar el error.
- **Solution**: Se mejoró el manejo de errores para propagar excepciones cuando se usan claves o contraseñas incorrectas, distinguiendo entre errores críticos (como claves incorrectas) y errores no críticos (como problemas con archivos individuales).
- **Prevention**: Diseñar un sistema de manejo de errores que distinga entre errores críticos y no críticos.
- **Status**: Resuelto en la versión 1.5.0

### ERR-003: libmagic Dependency on Windows
- **Date**: 2025-04-08
- **Category**: Implementation
- **Description**: The system depends on python-magic for file type detection, which requires libmagic. This library is not available by default on Windows systems.
- **Root Cause**: Using a library with platform-specific dependencies without proper fallback mechanisms.
- **Solution**: Implemented a cross-platform file type detection system that works on all platforms. The solution includes:
  - Created a new `CrossPlatformFileTypeDetector` class that uses multiple detection methods
  - Used the `filetype` library for signature-based detection
  - Added extension-based detection using Python's standard `mimetypes` module
  - Implemented custom heuristics for text file detection
  - Made python-magic optional and used only if available
  - Added comprehensive tests for different file types
- **Prevention**: Test on all target platforms early in development and choose libraries with good cross-platform support.

### ERR-005: RSA-PKCS1v15 Signature Verification Failure
- **Date**: 2025-04-08
- **Category**: Implementation
- **Description**: Signatures created with the RSA-PKCS1v15 algorithm cannot be verified successfully, even when using the correct key pair.
- **Root Cause**: In the CLI, the algorithm was hardcoded to 'RSA-PSS' during verification, regardless of the algorithm used for signing.
- **Solution**: Modified the CLI to accept an algorithm parameter for verification and use the same algorithm that was used for signing. The solution includes:
  - Added an --algorithm parameter to the verify command
  - Updated the verification process to use the specified algorithm
  - Added comprehensive tests for both RSA-PSS and RSA-PKCS1v15
  - Added integration tests to verify the CLI functionality
- **Prevention**: Implement comprehensive tests for all supported algorithms and verify that they work correctly before releasing.

### ERR-004: Character Encoding Issues
- **Date**: 2025-04-08
- **Category**: Implementation
- **Description**: After decryption, files with non-ASCII characters (like accented letters) have display issues when viewed with standard tools.
- **Root Cause**: The encoding information is not preserved during encryption/decryption, and the system doesn't handle the encoding conversion properly.
- **Solution**: Implemented encoding detection and preservation in the file metadata. The solution includes:
  - Added automatic encoding detection using the chardet library
  - Modified file structure to include encoding information in metadata
  - Updated encryption process to detect and store encoding information
  - Updated decryption process to use the original encoding when possible
  - Added comprehensive tests for different encodings
- **Prevention**: Always consider character encoding when dealing with text files, especially in internationalized applications.

### ERR-002: Salt Management in Password-Based Encryption
- **Date**: 2025-04-08
- **Category**: Design
- **Description**: When using password-based encryption, the user must manually remember and input the salt value during decryption, which is error-prone and user-unfriendly.
- **Root Cause**: The salt is not stored with the encrypted file; instead, it's displayed to the user who must record it separately.
- **Solution**: Implemented storage of salt in the encrypted file's metadata. The solution includes:
  - Modified file structure to include salt in metadata
  - Updated encryption process to store salt automatically
  - Updated decryption process to extract salt from metadata
  - Maintained backward compatibility with files encrypted using the old method
  - Updated CLI to no longer require manual salt input
- **Prevention**: Consider the complete user experience flow, including key/salt management, during the design phase.

### ERR-001: Key Persistence Issue
- **Date**: 2025-04-08
- **Category**: Implementation
- **Description**: Keys generated during encryption are not persisted between program executions, making it impossible to decrypt files using Key IDs after the program is closed and reopened.
- **Root Cause**: Keys are stored only in memory (in the `active_keys` dictionary of the `KeyManager` class) and are not saved to disk or any persistent storage.
- **Solution**: Implemented a secure key storage system that encrypts keys with a master password and stores them in a file. The system includes:
  - Secure key derivation from the master password using PBKDF2
  - Encryption of the key storage using AES-GCM
  - Serialization of binary data for JSON storage
  - Command-line interface for managing the key storage
- **Prevention**: Design key management systems with persistence in mind from the beginning.
