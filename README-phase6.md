# Proyecto de Criptografía - Fase 6

## Características implementadas en la Fase 6

### 1. Encriptación de archivos con múltiples destinatarios

Se ha implementado un sistema de encriptación que permite cifrar archivos para múltiples destinatarios, donde cada destinatario puede descifrar el archivo utilizando su propia clave privada. Características principales:

- **Encriptación híbrida**: Los datos se cifran una sola vez con una clave simétrica aleatoria, y esta clave se cifra por separado para cada destinatario.
- **Soporte para múltiples algoritmos**: Compatible con RSA, ECC y algoritmos post-cuánticos como Kyber.
- **Gestión de destinatarios**: Permite añadir o eliminar destinatarios de un archivo ya cifrado.
- **Interfaz gráfica intuitiva**: Selección visual de destinatarios desde las claves disponibles.
- **Comandos CLI**: Herramientas de línea de comandos para operaciones por lotes.

### 2. Sistema de firmas múltiples (co-firmas)

Se ha desarrollado un sistema de co-firmas que permite que múltiples partes firmen un documento, creando una cadena de firmas que puede ser verificada de forma independiente:

- **Flujo de trabajo configurable**: Permite definir qué firmantes son requeridos para completar el proceso.
- **Verificación independiente**: Cada firma puede ser verificada individualmente.
- **Metadatos de firma**: Incluye información sobre el firmante, fecha y hora, y secuencia de firma.
- **Estado de firma**: Seguimiento del estado del proceso de firma (en progreso, completado).
- **Interfaz gráfica**: Visualización del estado de las firmas y gestión del proceso.

### 3. Marcas de tiempo seguras para firmas

Se ha implementado un sistema de sellado de tiempo para documentos y firmas, que proporciona pruebas de que un documento existía en un momento determinado:

- **Integración con TSA**: Soporte para servicios de Autoridad de Sellado de Tiempo (TSA) externos.
- **Sellado de tiempo local**: Opción para crear sellos de tiempo locales cuando no hay acceso a un TSA.
- **Verificación de sellos**: Herramientas para verificar la autenticidad de los sellos de tiempo.
- **Comandos CLI**: Herramientas de línea de comandos para operaciones de sellado de tiempo.

### 4. Verificación de revocación de certificados

Se ha añadido soporte para verificar el estado de revocación de certificados X.509, utilizando tanto CRL (Certificate Revocation Lists) como OCSP (Online Certificate Status Protocol):

- **Soporte para CRL**: Descarga y verificación de listas de revocación de certificados.
- **Soporte para OCSP**: Consultas en tiempo real del estado de revocación.
- **Caché de CRL**: Sistema de caché para optimizar las verificaciones.
- **Comandos CLI**: Herramientas para verificar el estado de revocación de certificados.

## Instalación de dependencias

Para instalar las dependencias necesarias para la Fase 6:

```bash
pip install -r requirements-phase6.txt
```

## Uso de las nuevas características

### Encriptación con múltiples destinatarios

#### Interfaz gráfica
1. Abra la aplicación y vaya a la pestaña "Multi-Recipient Encryption"
2. Seleccione el archivo a cifrar y el archivo de salida
3. Añada los destinatarios desde la lista de claves disponibles
4. Haga clic en "Encrypt" para cifrar el archivo

#### Línea de comandos
```bash
# Cifrar un archivo para múltiples destinatarios
python -m src.ui.cli multi encrypt --file documento.pdf --recipients "usuario1.public,usuario2.public" --output documento.pdf.encrypted

# Descifrar un archivo como uno de los destinatarios
python -m src.ui.cli multi decrypt --file documento.pdf.encrypted --key usuario1.private --output documento_descifrado.pdf

# Añadir un nuevo destinatario a un archivo ya cifrado
python -m src.ui.cli multi add-recipient --file documento.pdf.encrypted --new-recipient usuario3.public --admin-key usuario1.private

# Listar los destinatarios de un archivo cifrado
python -m src.ui.cli multi list-recipients --file documento.pdf.encrypted
```

### Sistema de co-firmas

#### Interfaz gráfica
1. Abra la aplicación y vaya a la pestaña "Co-Signatures"
2. Seleccione el archivo a firmar y el archivo de firma
3. Seleccione su clave de firma y añada los firmantes requeridos
4. Haga clic en "Create Signature Chain" para iniciar el proceso de firma
5. Para añadir su firma a una cadena existente, cargue el archivo y haga clic en "Sign"

#### Línea de comandos
```bash
# Crear una nueva cadena de firmas
python -m src.ui.cli cosign create --file documento.pdf --key usuario1.private --output documento.pdf.cosig --required-signers "usuario2.public,usuario3.public"

# Añadir una firma a una cadena existente
python -m src.ui.cli cosign sign --file documento.pdf --signature documento.pdf.cosig --key usuario2.private

# Verificar las firmas
python -m src.ui.cli cosign verify --file documento.pdf --signature documento.pdf.cosig --detailed

# Comprobar el estado de las firmas
python -m src.ui.cli cosign status --signature documento.pdf.cosig
```

### Marcas de tiempo seguras

#### Línea de comandos
```bash
# Crear un sello de tiempo para un archivo
python -m src.ui.cli timestamp file --file documento.pdf --output documento.pdf.timestamp --tsa-url "https://freetsa.org/tsr"

# Crear un sello de tiempo para una firma
python -m src.ui.cli timestamp signature --signature documento.pdf.sig --output documento.pdf.sig.timestamp

# Verificar un sello de tiempo
python -m src.ui.cli timestamp verify --file documento.pdf --timestamp documento.pdf.timestamp
```

### Verificación de revocación de certificados

#### Línea de comandos
```bash
# Verificar el estado de revocación de un certificado
python -m src.ui.cli revocation check --cert certificado.pem --issuer emisor.pem --output resultado.json

# Ver información sobre la caché de CRL
python -m src.ui.cli revocation cache-info

# Limpiar la caché de CRL
python -m src.ui.cli revocation clear-cache
```

## Próximos pasos (Fase 7)

En la próxima fase se implementarán:

- Integración con servicios en la nube para almacenamiento seguro
- Soporte para más algoritmos post-cuánticos
- Mejoras en el rendimiento y la escalabilidad
- Integración con sistemas de gestión de identidad
