# Guía de Usuario del Sistema Criptográfico

## Introducción

Bienvenido a la guía de usuario del Sistema Criptográfico Avanzado. Este sistema proporciona una amplia gama de funcionalidades criptográficas para proteger sus datos, incluyendo cifrado, firmas digitales, gestión de claves, y más.

Esta guía le ayudará a entender cómo utilizar las diferentes características del sistema.

## Instalación

### Requisitos

- Python 3.8 o superior
- Bibliotecas requeridas (ver `requirements.txt`)

### Pasos de Instalación

1. Clone el repositorio:
   ```bash
   git clone https://github.com/atomixon49/CRYPT-FLOWER.git
   cd CRYPT-FLOWER
   ```

2. Cree un entorno virtual (opcional pero recomendado):
   ```bash
   python -m venv venv
   source venv/bin/activate  # En Windows: venv\Scripts\activate
   ```

3. Instale las dependencias:
   ```bash
   pip install -r requirements.txt
   ```

## Uso Básico

### Interfaz de Línea de Comandos (CLI)

El sistema proporciona una interfaz de línea de comandos para realizar operaciones criptográficas.

#### Cifrado y Descifrado

Para cifrar un archivo:
```bash
python -m src.main encrypt --file documento.txt --output documento.encrypted --algorithm AES-GCM
```

Para descifrar un archivo:
```bash
python -m src.main decrypt --file documento.encrypted --output documento.decrypted
```

#### Firmas Digitales

Para firmar un archivo:
```bash
python -m src.main sign --file documento.txt --output documento.sig --key mi_clave.private
```

Para verificar una firma:
```bash
python -m src.main verify --file documento.txt --signature documento.sig --key mi_clave.public
```

### Interfaz Gráfica (GUI)

El sistema también proporciona una interfaz gráfica para facilitar el uso.

Para iniciar la interfaz gráfica:
```bash
python -m src.main --gui
```

## Características Avanzadas

### Cifrado de Secciones de PDF

El sistema permite cifrar secciones específicas (páginas) de archivos PDF, manteniendo el resto del contenido accesible.

#### Usando la Interfaz Gráfica

1. Inicie la interfaz gráfica: `python -m src.main --gui`
2. Vaya a la pestaña "PDF Section Encryption"
3. Haga clic en "Open PDF" para seleccionar un archivo PDF
4. Seleccione las páginas que desea cifrar
5. Elija el método de cifrado (clave o contraseña)
6. Haga clic en "Encrypt Selected Pages"

#### Usando la Línea de Comandos

Para cifrar secciones específicas de un PDF:
```bash
python -m src.main encrypt-pdf-sections --file documento.pdf --pages "1,3-5,7" --algorithm AES-GCM
```

Para descifrar secciones cifradas de un PDF:
```bash
python -m src.main decrypt-pdf-sections --file documento.section-encrypted.pdf
```

### Verificación de Revocación de Certificados

El sistema permite verificar si un certificado X.509 ha sido revocado utilizando CRL (Certificate Revocation List) y OCSP (Online Certificate Status Protocol).

#### Usando la Interfaz Gráfica

1. Inicie la interfaz gráfica: `python -m src.main --gui`
2. Vaya a la pestaña "Certificate Revocation"
3. Seleccione la pestaña "CRL Check" o "OCSP Check" según el método que desee utilizar
4. Seleccione el certificado a verificar y el certificado del emisor
5. Opcionalmente, proporcione un archivo CRL o una URL de OCSP
6. Haga clic en "Check Certificate Revocation"

#### Usando la Línea de Comandos

Para verificar un certificado utilizando CRL:
```bash
python -m src.main cert check-revocation --cert certificado.pem --issuer emisor.pem --method crl
```

Para verificar un certificado utilizando OCSP:
```bash
python -m src.main cert check-revocation --cert certificado.pem --issuer emisor.pem --method ocsp
```

### Rotación Automática de Claves

El sistema incluye funcionalidad para rotar automáticamente las claves criptográficas según políticas definidas.

#### Usando la Interfaz Gráfica

1. Inicie la interfaz gráfica: `python -m src.main --gui`
2. Vaya a la pestaña "Key Rotation"
3. Configure las políticas de rotación para diferentes tipos de claves
4. Habilite o deshabilite la rotación automática
5. Monitoree el estado de rotación de las claves

#### Usando la Línea de Comandos

Para configurar la rotación automática de claves:
```bash
# Esta funcionalidad está disponible principalmente a través de la API y la GUI
```

## Solución de Problemas

### Problemas Comunes

1. **Error al inicializar el almacenamiento de claves**:
   - Asegúrese de haber inicializado el almacenamiento de claves: `python -m src.main init-storage`

2. **Error al cargar un PDF**:
   - Asegúrese de tener instalada la biblioteca PyPDF2: `pip install pypdf2`

3. **Error al verificar un certificado**:
   - Asegúrese de tener instaladas las bibliotecas cryptography y asn1crypto: `pip install cryptography asn1crypto`

### Registro de Errores

El sistema mantiene un registro de errores en el directorio `.secure_crypto` en su directorio de inicio.

## Seguridad

### Mejores Prácticas

1. **Proteja sus claves privadas**: Nunca comparta sus claves privadas y almacénelas en un lugar seguro.

2. **Use contraseñas fuertes**: Si utiliza cifrado basado en contraseñas, asegúrese de usar contraseñas fuertes.

3. **Actualice regularmente**: Mantenga el sistema y sus dependencias actualizadas para beneficiarse de las últimas mejoras de seguridad.

4. **Verifique las firmas**: Siempre verifique las firmas digitales antes de confiar en un archivo.

5. **Utilice la rotación de claves**: Configure la rotación automática de claves para mejorar la seguridad a largo plazo.

## Referencia de Comandos

### Comandos Principales

| Comando | Descripción |
|---------|-------------|
| `encrypt` | Cifra un archivo |
| `decrypt` | Descifra un archivo |
| `sign` | Firma un archivo |
| `verify` | Verifica una firma |
| `genkey` | Genera un par de claves |
| `encrypt-pdf-sections` | Cifra secciones específicas de un PDF |
| `decrypt-pdf-sections` | Descifra secciones específicas de un PDF |
| `encrypt-dir` | Cifra un directorio recursivamente |
| `decrypt-dir` | Descifra un directorio recursivamente |
| `cert` | Operaciones con certificados X.509 |
| `init-storage` | Inicializa el almacenamiento de claves |
| `list-keys` | Lista las claves almacenadas |
| `change-password` | Cambia la contraseña maestra del almacenamiento de claves |

### Subcomandos de Certificados

| Subcomando | Descripción |
|------------|-------------|
| `generate` | Genera un certificado autofirmado |
| `csr` | Crea una solicitud de firma de certificado |
| `import` | Importa un certificado |
| `verify` | Verifica un certificado |
| `check-revocation` | Verifica si un certificado ha sido revocado |

## Apéndice

### Algoritmos Soportados

#### Cifrado Simétrico
- AES-GCM
- ChaCha20-Poly1305

#### Cifrado Asimétrico
- RSA-OAEP
- KYBER512, KYBER768, KYBER1024 (post-cuántico)

#### Firmas Digitales
- RSA-PSS
- RSA-PKCS1v15
- DILITHIUM2, DILITHIUM3, DILITHIUM5 (post-cuántico)

### Formatos de Archivo Soportados

- Archivos de texto
- Archivos binarios
- Archivos PDF
- Directorios completos
