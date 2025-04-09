# Diseño de la Preservación de Codificación de Caracteres

## Problema Actual

Actualmente, cuando se encriptan y desencriptan archivos de texto:
1. Los archivos se leen en modo binario (`rb`)
2. Se encriptan los bytes sin tener en cuenta la codificación original
3. Al desencriptar, se escriben los bytes sin aplicar ninguna codificación específica
4. Esto causa problemas con caracteres no ASCII (como letras acentuadas) que pueden no mostrarse correctamente

## Solución Propuesta

Preservar la información de codificación de caracteres en los metadatos del archivo encriptado, de modo que:
1. Se detecte la codificación del archivo original durante la encriptación
2. Se almacene esta información en los metadatos
3. Se aplique la misma codificación al escribir el archivo desencriptado

## Enfoque Técnico

### Detección de Codificación

Utilizaremos la biblioteca `chardet` para detectar la codificación de los archivos de texto:
1. Leer una muestra del archivo (primeros 1024 bytes)
2. Utilizar `chardet.detect()` para determinar la codificación más probable
3. Si la confianza es alta (>0.7), usar esa codificación
4. Si no, usar UTF-8 como predeterminado

### Estructura de Archivo Encriptado

Modificaremos la estructura de metadatos para incluir la información de codificación:
```json
{
  "metadata": {
    "filename": "original_filename.txt",
    "original_size": 1234,
    "encryption_algorithm": "AES-GCM",
    "encryption_method": "password_based",
    "salt": "base64_encoded_salt",
    "encoding": "utf-8",
    "encoding_confidence": 0.95,
    "user_metadata": {}
  },
  "ciphertext": "base64_encoded_ciphertext",
  "nonce": "base64_encoded_nonce",
  "tag": "base64_encoded_tag"
}
```

### Flujo de Trabajo

#### Encriptación
1. Detectar la codificación del archivo original
2. Leer el archivo en modo binario
3. Encriptar los bytes
4. Almacenar la codificación detectada en los metadatos

#### Desencriptación
1. Desencriptar los bytes
2. Extraer la información de codificación de los metadatos
3. Escribir el archivo usando la codificación especificada

### Consideraciones Especiales

1. **Archivos Binarios vs. Texto**:
   - Solo aplicar detección de codificación a archivos de texto
   - Para archivos binarios, mantener el comportamiento actual

2. **Compatibilidad**:
   - Mantener compatibilidad con archivos encriptados anteriormente
   - Si no hay información de codificación, usar UTF-8 como predeterminado

3. **Manejo de Errores**:
   - Si la codificación especificada causa errores, intentar con UTF-8
   - Proporcionar mensajes de error claros si la codificación falla
