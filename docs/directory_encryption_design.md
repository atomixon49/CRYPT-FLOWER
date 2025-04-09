# Diseño de Encriptación de Directorios

## Objetivo

Implementar un sistema para encriptar y desencriptar directorios completos de manera recursiva, preservando la estructura del directorio y proporcionando retroalimentación sobre el progreso.

## Requisitos

1. **Recursividad**: El sistema debe poder encriptar/desencriptar directorios y sus subdirectorios.
2. **Preservación de estructura**: La estructura del directorio debe mantenerse en la versión encriptada.
3. **Seguimiento de progreso**: Debe proporcionar información sobre el progreso de la operación.
4. **Metadatos**: Debe almacenar metadatos sobre los archivos y directorios encriptados.
5. **Compatibilidad**: Debe ser compatible con los sistemas de encriptación existentes.
6. **Interfaz de usuario**: Debe proporcionar tanto CLI como GUI para estas operaciones.

## Diseño de Alto Nivel

### Estructura de Datos

Para preservar la estructura del directorio, utilizaremos un archivo de metadatos JSON que contendrá:

```json
{
  "version": "1.0",
  "encrypted_at": "2025-04-18T12:00:00Z",
  "algorithm": "AES-GCM",
  "directory_structure": {
    "original_path": "/path/to/original",
    "encrypted_path": "/path/to/encrypted",
    "files": [
      {
        "original_path": "file1.txt",
        "encrypted_path": "file1.txt.encrypted",
        "size": 1024,
        "encrypted_size": 1056,
        "key_id": "key123",
        "algorithm": "AES-GCM"
      },
      ...
    ],
    "directories": [
      {
        "original_path": "subdir1",
        "encrypted_path": "subdir1",
        "files": [...],
        "directories": [...]
      },
      ...
    ]
  }
}
```

### Algoritmo de Encriptación

1. **Inicialización**:
   - Crear directorio de destino si no existe
   - Inicializar estructura de metadatos
   - Determinar clave de encriptación (generada o proporcionada)

2. **Encriptación recursiva**:
   - Para cada archivo en el directorio:
     - Encriptar el archivo usando el manejador apropiado
     - Actualizar metadatos con información del archivo
   - Para cada subdirectorio:
     - Crear subdirectorio correspondiente en el destino
     - Llamar recursivamente al algoritmo de encriptación
     - Actualizar metadatos con información del subdirectorio

3. **Finalización**:
   - Guardar archivo de metadatos
   - Retornar estadísticas de la operación

### Algoritmo de Desencriptación

1. **Inicialización**:
   - Verificar existencia del directorio encriptado
   - Cargar archivo de metadatos
   - Determinar clave de desencriptación

2. **Desencriptación recursiva**:
   - Para cada archivo en los metadatos:
     - Desencriptar el archivo usando el manejador apropiado
     - Verificar integridad
   - Para cada subdirectorio en los metadatos:
     - Crear subdirectorio correspondiente en el destino
     - Llamar recursivamente al algoritmo de desencriptación

3. **Finalización**:
   - Retornar estadísticas de la operación

## Seguimiento de Progreso

Para proporcionar retroalimentación sobre el progreso, implementaremos:

1. **Contador de archivos**: Contar el número total de archivos a procesar.
2. **Callback de progreso**: Función que se llama después de procesar cada archivo.
3. **Estimación de tiempo**: Calcular el tiempo estimado restante basado en el progreso actual.

## Manejo de Errores

1. **Errores de acceso**: Manejar errores de permisos de archivos/directorios.
2. **Errores de encriptación/desencriptación**: Registrar errores pero continuar con otros archivos.
3. **Corrupción de metadatos**: Proporcionar opciones para recuperación parcial.

## Consideraciones de Seguridad

1. **Limpieza de memoria**: Asegurar que las claves y datos sensibles se limpien de la memoria.
2. **Verificación de integridad**: Verificar la integridad de los archivos desencriptados.
3. **Protección de metadatos**: Considerar la encriptación del archivo de metadatos.

## Interfaz de Programación

```python
class DirectoryHandler:
    def __init__(self, key_manager, encryption_engine):
        self.key_manager = key_manager
        self.encryption_engine = encryption_engine
        self.file_handlers = {}  # Manejadores para diferentes tipos de archivos
    
    def encrypt_directory(self, input_path, output_path, key=None, key_id=None, 
                         password=None, algorithm='AES-GCM', progress_callback=None):
        """Encripta un directorio recursivamente."""
        pass
    
    def decrypt_directory(self, input_path, output_path, key=None, key_id=None,
                         password=None, progress_callback=None):
        """Desencripta un directorio recursivamente."""
        pass
```

## Interfaz de Línea de Comandos

Extenderemos la CLI existente con nuevos comandos:

```
encrypt-dir --input /path/to/dir --output /path/to/encrypted [--key keyfile | --password] [--algorithm AES-GCM]
decrypt-dir --input /path/to/encrypted --output /path/to/decrypted [--key keyfile | --password]
```

## Interfaz Gráfica

Añadiremos una nueva pestaña a la GUI existente con:

1. Selección de directorio de entrada/salida
2. Opciones de encriptación (clave, contraseña, algoritmo)
3. Barra de progreso
4. Estadísticas de la operación (archivos procesados, tiempo, etc.)

## Plan de Implementación

1. Implementar la clase `DirectoryHandler`
2. Añadir comandos a la CLI
3. Crear pruebas unitarias
4. Implementar la pestaña de GUI
5. Realizar pruebas de integración
6. Documentar la funcionalidad
