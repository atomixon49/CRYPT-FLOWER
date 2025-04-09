# Registro de Cambios

Todos los cambios notables en este proyecto serán documentados en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/),
y este proyecto adhiere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - 2023-04-08

### Añadido
- Implementación completa de criptografía híbrida
- Soporte para cifrado multi-destinatario
- Funcionalidad de co-firmas
- Sellado de tiempo para datos y firmas
- Interfaz gráfica de usuario básica
- Interfaz de línea de comandos completa
- Manejo de archivos (texto, binario, vacío, grande)
- Preservación de codificación UTF-8

### Pendiente
- Verificación de revocación de certificados (CRL, OCSP)
- Soporte completo para criptografía post-cuántica
- Cifrado de archivos PDF
- Rotación automática de claves

## [0.8.0] - 2023-03-15

### Añadido
- Implementación básica de cifrado/descifrado (AES-GCM, ChaCha20-Poly1305)
- Implementación básica de firmas digitales (RSA-PSS, RSA-PKCS1v15)
- Gestión básica de claves
- Estructura inicial del proyecto
- Pruebas unitarias básicas

### Corregido
- Problemas de importación en módulos principales
- Manejo de errores en cifrado/descifrado

## [0.7.0] - 2023-02-20

### Añadido
- Diseño inicial de la arquitectura
- Investigación de algoritmos criptográficos
- Definición de requisitos del sistema
