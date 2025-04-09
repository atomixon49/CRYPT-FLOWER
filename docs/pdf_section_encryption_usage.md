# Guía de Uso: Encriptación Selectiva de Secciones de PDF

Esta guía explica cómo utilizar la funcionalidad de encriptación selectiva de secciones de PDF en nuestro sistema criptográfico.

## Introducción

La encriptación selectiva de secciones de PDF permite proteger partes específicas de un documento PDF mientras mantiene el resto accesible. Esto es útil cuando:

- Solo una parte del documento contiene información sensible
- Se necesita compartir un documento con diferentes niveles de confidencialidad
- Se requiere cumplir con requisitos de privacidad y protección de datos

Actualmente, el sistema soporta la encriptación a nivel de páginas completas. En futuras versiones, se añadirá soporte para encriptar regiones específicas dentro de una página.

## Requisitos Previos

- Tener instalado el sistema criptográfico
- Tener instalada la biblioteca pypdf (`pip install pypdf`)
- Tener un archivo PDF que desee encriptar parcialmente

## Encriptación de Secciones de PDF

### Usando la Interfaz de Línea de Comandos

#### Encriptación con Clave

Para encriptar páginas específicas de un PDF utilizando una clave:

1. **Generar una clave** (si aún no tiene una):
   ```
   python -m src.main genkey --output pdf_key
   ```
   Esto generará dos archivos: `pdf_key.private` y `pdf_key.public`

2. **Encriptar las páginas seleccionadas**:
   ```
   python -m src.main encrypt-pdf-sections --file documento.pdf --pages "1,3-5,7" --key pdf_key.private --output documento_parcial.pdf
   ```

   Donde:
   - `--file documento.pdf`: Es el archivo PDF original
   - `--pages "1,3-5,7"`: Especifica las páginas a encriptar (en este caso, páginas 1, 3, 4, 5 y 7)
   - `--key pdf_key.private`: Es la clave privada para encriptar
   - `--output documento_parcial.pdf`: Es el archivo de salida (opcional)

3. **Resultado**:
   - Se generará un archivo PDF con las páginas especificadas encriptadas
   - También se creará un archivo de metadatos (`documento_parcial.pdf.metadata.json`)
   - Las páginas no especificadas permanecerán accesibles normalmente

#### Encriptación con Contraseña

Para encriptar páginas específicas utilizando una contraseña:

```
python -m src.main encrypt-pdf-sections --file documento.pdf --pages "2,6,8-10" --password --output documento_parcial.pdf
```

El sistema le pedirá que ingrese una contraseña. Esta contraseña será necesaria para desencriptar las páginas posteriormente.

### Opciones Adicionales

- **Algoritmo de encriptación**: Puede especificar el algoritmo de encriptación con `--algorithm`:
  ```
  python -m src.main encrypt-pdf-sections --file documento.pdf --pages "1,3" --key pdf_key.private --algorithm ChaCha20-Poly1305
  ```
  Los algoritmos soportados son `AES-GCM` (predeterminado) y `ChaCha20-Poly1305`.

## Desencriptación de Secciones de PDF

### Usando la Interfaz de Línea de Comandos

#### Desencriptación con Clave

Para desencriptar un PDF que tiene secciones encriptadas con una clave:

```
python -m src.main decrypt-pdf-sections --file documento_parcial.pdf --key pdf_key.private --output documento_completo.pdf
```

Donde:
- `--file documento_parcial.pdf`: Es el archivo PDF con secciones encriptadas
- `--key pdf_key.private`: Es la clave privada utilizada para encriptar
- `--output documento_completo.pdf`: Es el archivo de salida desencriptado (opcional)

#### Desencriptación con Contraseña

Para desencriptar un PDF que tiene secciones encriptadas con contraseña:

```
python -m src.main decrypt-pdf-sections --file documento_parcial.pdf --password --output documento_completo.pdf
```

El sistema le pedirá que ingrese la contraseña que utilizó durante la encriptación.

## Ejemplos Prácticos

### Ejemplo 1: Encriptar la primera página de un informe financiero

```
# Generar una clave
python -m src.main genkey --output finanzas_key

# Encriptar solo la primera página
python -m src.main encrypt-pdf-sections --file informe_financiero.pdf --pages "1" --key finanzas_key.private --output informe_financiero_seguro.pdf

# Desencriptar posteriormente
python -m src.main decrypt-pdf-sections --file informe_financiero_seguro.pdf --key finanzas_key.private --output informe_financiero_completo.pdf
```

### Ejemplo 2: Encriptar múltiples secciones de un contrato con contraseña

```
# Encriptar las páginas con información sensible
python -m src.main encrypt-pdf-sections --file contrato.pdf --pages "3-5,8,12-15" --password --output contrato_seguro.pdf

# Desencriptar posteriormente
python -m src.main decrypt-pdf-sections --file contrato_seguro.pdf --password --output contrato_completo.pdf
```

## Solución de Problemas

### Error: "pypdf is required for PDF operations"

Este error indica que la biblioteca pypdf no está instalada. Instálela con:

```
pip install pypdf
```

### Error: "Failed to decrypt page X"

Este error puede ocurrir por varias razones:
- La clave o contraseña proporcionada es incorrecta
- El archivo PDF está dañado
- El archivo no fue encriptado con nuestro sistema

Verifique que está utilizando la misma clave o contraseña que usó para encriptar el archivo.

### Error: "No encryption metadata found in the PDF file"

Este error indica que el archivo PDF no contiene los metadatos necesarios para la desencriptación. Asegúrese de que:
- El archivo fue encriptado con nuestro sistema
- El archivo de metadatos (`archivo.pdf.metadata.json`) está en la misma carpeta que el PDF

## Limitaciones Actuales

- Solo se pueden encriptar páginas completas, no regiones específicas dentro de una página
- No se pueden encriptar anotaciones o formularios de manera independiente
- La encriptación no es compatible con DRM (gestión de derechos digitales)
- Los metadatos sobre qué páginas están encriptadas son visibles

## Próximas Mejoras

- Soporte para encriptar regiones específicas dentro de una página
- Interfaz gráfica para selección visual de áreas a encriptar
- Soporte para encriptar anotaciones y formularios
- Opciones avanzadas de redacción visual
