# Diseño de Encriptación Selectiva de Secciones de PDF

## Objetivo

Permitir a los usuarios encriptar selectivamente secciones específicas de documentos PDF, manteniendo el resto del contenido accesible. Esto es útil para:

- Proteger información sensible dentro de documentos mayormente públicos
- Compartir documentos con diferentes niveles de confidencialidad
- Cumplir con requisitos de privacidad y protección de datos

## Enfoque Técnico

### 1. Identificación de Secciones

Para identificar secciones en un documento PDF, utilizaremos varios métodos:

1. **Basado en Páginas**: Permitir seleccionar páginas específicas para encriptar
2. **Basado en Texto**: Identificar secciones por contenido de texto (por ejemplo, entre dos marcadores)
3. **Basado en Posición**: Identificar secciones por coordenadas en la página

### 2. Métodos de Encriptación

Para cada sección identificada, aplicaremos uno de los siguientes métodos:

1. **Redacción**: Reemplazar completamente el contenido con un rectángulo negro (eliminación permanente)
2. **Encriptación Reversible**: Encriptar el contenido y almacenar la información necesaria para desencriptarlo
3. **Ofuscación Visual**: Aplicar técnicas como pixelado o desenfoque que ocultan visualmente el contenido

### 3. Estructura de Metadatos

Para la encriptación reversible, necesitamos almacenar metadatos sobre las secciones encriptadas:

```json
{
  "encrypted_sections": [
    {
      "type": "page",
      "page_number": 5,
      "algorithm": "AES-GCM",
      "key_id": "key_id_or_null",
      "nonce": "base64_encoded_nonce",
      "tag": "base64_encoded_tag",
      "ciphertext": "base64_encoded_ciphertext"
    },
    {
      "type": "region",
      "page_number": 2,
      "coordinates": [100, 200, 300, 400],  // [x1, y1, x2, y2]
      "algorithm": "AES-GCM",
      "key_id": "key_id_or_null",
      "nonce": "base64_encoded_nonce",
      "tag": "base64_encoded_tag",
      "ciphertext": "base64_encoded_ciphertext"
    }
  ],
  "document_metadata": {
    "original_filename": "document.pdf",
    "encryption_date": "2025-04-15T14:30:00Z",
    "software_version": "1.0.0"
  }
}
```

### 4. Flujo de Trabajo

#### Encriptación
1. El usuario selecciona un documento PDF
2. El sistema analiza el documento y muestra una vista previa
3. El usuario selecciona las secciones a encriptar y el método
4. El sistema procesa el documento, aplicando la encriptación a las secciones seleccionadas
5. Se genera un nuevo documento PDF con las secciones encriptadas y los metadatos necesarios

#### Desencriptación
1. El usuario selecciona un documento PDF con secciones encriptadas
2. El sistema detecta las secciones encriptadas y solicita la clave o contraseña
3. El usuario proporciona la clave o contraseña
4. El sistema desencripta las secciones y genera un nuevo documento PDF completamente accesible

## Consideraciones Técnicas

### Biblioteca PDF

Utilizaremos la biblioteca `pypdf` (anteriormente PyPDF2) para manipular documentos PDF. Esta biblioteca permite:
- Leer y escribir documentos PDF
- Extraer texto y metadatos
- Manipular páginas y contenido
- Añadir anotaciones y formas

### Almacenamiento de Metadatos

Los metadatos de encriptación se almacenarán de dos formas:
1. **Embebidos en el PDF**: Como un objeto de documento XMP (Extensible Metadata Platform)
2. **Archivo Separado**: Como un archivo JSON adjunto para mayor flexibilidad

### Compatibilidad

El sistema debe garantizar que:
- Los PDF con secciones encriptadas sean válidos y se puedan abrir con cualquier visor de PDF
- Las secciones no encriptadas permanezcan accesibles y funcionales
- El formato sea compatible con diferentes versiones de PDF (1.4 a 2.0)

## Interfaz de Usuario

### Interfaz de Línea de Comandos (CLI)

```
# Encriptar secciones de un PDF
python -m src.main encrypt-pdf-sections --file document.pdf --output secured.pdf --pages 5,8-10 --key my_key.private

# Desencriptar secciones de un PDF
python -m src.main decrypt-pdf-sections --file secured.pdf --output full_access.pdf --key my_key.private
```

### Interfaz Gráfica (Futura)

La interfaz gráfica permitirá:
- Vista previa del documento
- Selección visual de regiones a encriptar
- Vista previa de las secciones encriptadas
- Opciones de configuración intuitivas

## Plan de Implementación

1. **Fase 1**: Implementar encriptación basada en páginas completas
2. **Fase 2**: Añadir soporte para encriptación de regiones específicas
3. **Fase 3**: Implementar encriptación basada en contenido de texto
4. **Fase 4**: Desarrollar interfaz gráfica para selección visual

## Limitaciones y Consideraciones de Seguridad

1. **No es DRM**: Este sistema no pretende ser un sistema de gestión de derechos digitales (DRM) infalible
2. **Seguridad Visual vs. Criptográfica**: La redacción y ofuscación visual son permanentes pero no encriptadas
3. **Metadatos**: Los metadatos sobre qué secciones están encriptadas son visibles
4. **Ataques de Fuerza Bruta**: Las secciones encriptadas son vulnerables a ataques de fuerza bruta si se usan contraseñas débiles
