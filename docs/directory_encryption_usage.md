# Guía de Uso: Encriptación de Directorios

Esta guía explica cómo utilizar la funcionalidad de encriptación de directorios en nuestro sistema criptográfico.

## Introducción

La encriptación de directorios permite proteger todos los archivos dentro de un directorio y sus subdirectorios de manera recursiva, preservando la estructura del directorio original. Esto es útil cuando:

- Necesita proteger un conjunto completo de archivos relacionados
- Quiere mantener la estructura de directorios intacta
- Necesita encriptar/desencriptar múltiples archivos a la vez

## Requisitos Previos

- Tener instalado el sistema criptográfico
- Tener un directorio que desee encriptar

## Encriptación de Directorios

### Usando la Interfaz de Línea de Comandos

#### Encriptación con Clave

Para encriptar un directorio completo utilizando una clave:

1. **Generar una clave** (si aún no tiene una):
   ```
   python -m src.main genkey --output dir_key
   ```
   Esto generará dos archivos: `dir_key.private` y `dir_key.public`

2. **Encriptar el directorio**:
   ```
   python -m src.main encrypt-dir mi_directorio --key dir_key.private --output mi_directorio_encriptado
   ```

   Donde:
   - `mi_directorio`: Es el directorio a encriptar
   - `--key dir_key.private`: Es la clave privada para encriptar
   - `--output mi_directorio_encriptado`: Es el directorio de salida (opcional)

3. **Resultado**:
   - Se generará un directorio con todos los archivos encriptados
   - También se creará un archivo de metadatos (`.metadata.json`) en el directorio de salida
   - La estructura del directorio se mantendrá intacta

#### Encriptación con Contraseña

Para encriptar un directorio utilizando una contraseña:

```
python -m src.main encrypt-dir mi_directorio --password --output mi_directorio_encriptado
```

El sistema le pedirá que ingrese una contraseña. Esta contraseña será necesaria para desencriptar el directorio posteriormente.

### Opciones Adicionales

- **Algoritmo de encriptación**: Puede especificar el algoritmo de encriptación con `--algorithm`:
  ```
  python -m src.main encrypt-dir mi_directorio --key dir_key.private --algorithm ChaCha20-Poly1305
  ```
  Los algoritmos soportados son `AES-GCM` (predeterminado) y `ChaCha20-Poly1305`.

## Desencriptación de Directorios

### Usando la Interfaz de Línea de Comandos

#### Desencriptación con Clave

Para desencriptar un directorio que fue encriptado con una clave:

```
python -m src.main decrypt-dir mi_directorio_encriptado --key dir_key.private --output mi_directorio_desencriptado
```

Donde:
- `mi_directorio_encriptado`: Es el directorio encriptado
- `--key dir_key.private`: Es la clave privada utilizada para encriptar
- `--output mi_directorio_desencriptado`: Es el directorio de salida desencriptado (opcional)

#### Desencriptación con Contraseña

Para desencriptar un directorio que fue encriptado con contraseña:

```
python -m src.main decrypt-dir mi_directorio_encriptado --password --output mi_directorio_desencriptado
```

El sistema le pedirá que ingrese la contraseña que utilizó durante la encriptación.

## Usando la Interfaz Gráfica

### Encriptación de Directorios

1. Inicie la interfaz gráfica:
   ```
   python -m src.main --gui
   ```

2. Vaya a la pestaña "Directory Encryption"

3. Haga clic en "Select Directory" y seleccione el directorio que desea encriptar

4. Seleccione "Encrypt Directory" como operación

5. Elija el método de encriptación:
   - **Key**: Utiliza una clave del gestor de claves
   - **Password**: Utiliza una contraseña que usted proporciona

6. Si elige "Key", seleccione una clave de la lista desplegable

7. Si elige "Password", ingrese y confirme una contraseña

8. Seleccione el algoritmo de encriptación (AES-GCM o ChaCha20-Poly1305)

9. Opcionalmente, especifique un directorio de salida

10. Haga clic en "Encrypt Directory"

11. Se mostrará una barra de progreso durante la encriptación

### Desencriptación de Directorios

1. Inicie la interfaz gráfica:
   ```
   python -m src.main --gui
   ```

2. Vaya a la pestaña "Directory Encryption"

3. Haga clic en "Select Directory" y seleccione el directorio encriptado

4. Seleccione "Decrypt Directory" como operación

5. Elija el método de desencriptación (Key o Password)

6. Si elige "Key", seleccione la clave correcta de la lista desplegable

7. Si elige "Password", ingrese la contraseña

8. Opcionalmente, especifique un directorio de salida

9. Haga clic en "Decrypt Directory"

10. Se mostrará una barra de progreso durante la desencriptación

## Ejemplos Prácticos

### Ejemplo 1: Encriptar un directorio de documentos confidenciales

```
# Generar una clave
python -m src.main genkey --output docs_key

# Encriptar el directorio
python -m src.main encrypt-dir documentos_confidenciales --key docs_key.private --output documentos_confidenciales_encriptados

# Desencriptar posteriormente
python -m src.main decrypt-dir documentos_confidenciales_encriptados --key docs_key.private --output documentos_confidenciales_recuperados
```

### Ejemplo 2: Encriptar un proyecto con contraseña

```
# Encriptar el directorio del proyecto
python -m src.main encrypt-dir mi_proyecto --password --output mi_proyecto_encriptado

# Desencriptar posteriormente
python -m src.main decrypt-dir mi_proyecto_encriptado --password --output mi_proyecto_recuperado
```

## Solución de Problemas

### Error: "Critical error encrypting/decrypting file"

Este error indica que hay un problema crítico con la encriptación o desencriptación, como una contraseña incorrecta o una clave inválida. Verifique que está utilizando la misma clave o contraseña que usó para encriptar el directorio.

### Error: "Error reading key file"

Este error indica que el archivo de clave no se puede leer. Verifique que el archivo existe y que tiene permisos para leerlo.

### Error: "No metadata file found"

Este error indica que el directorio encriptado no contiene el archivo de metadatos necesario para la desencriptación. Asegúrese de que:
- El directorio fue encriptado con nuestro sistema
- El archivo `.metadata.json` está en el directorio encriptado

## Limitaciones Actuales

- No hay soporte para filtrar archivos durante la encriptación (incluir/excluir patrones)
- No hay soporte para encriptar solo archivos modificados desde la última encriptación
- La encriptación de directorios muy grandes puede ser lenta

## Próximas Mejoras

- Soporte para filtrar archivos durante la encriptación
- Encriptación incremental (solo archivos modificados)
- Mejoras de rendimiento para directorios grandes
- Compresión de archivos antes de la encriptación
