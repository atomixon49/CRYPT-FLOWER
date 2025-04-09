# Diseño del Sistema de Almacenamiento Seguro de Claves

## Requisitos

1. **Persistencia**: Las claves deben persistir entre ejecuciones del programa
2. **Seguridad**: Las claves almacenadas deben estar protegidas
3. **Accesibilidad**: El sistema debe permitir recuperar claves por su ID
4. **Protección**: Debe existir una capa adicional de seguridad (contraseña maestra)

## Enfoque

Utilizaremos un archivo JSON encriptado para almacenar las claves. Este archivo:

1. Contendrá todas las claves activas y sus metadatos
2. Estará encriptado con una clave derivada de una contraseña maestra
3. Se cargará al iniciar el programa y se guardará al cerrarlo o cuando se modifique

## Estructura de Datos

```json
{
  "metadata": {
    "version": "1.0",
    "created": "timestamp",
    "last_modified": "timestamp",
    "key_count": 10
  },
  "keys": {
    "key_id_1": {
      "algorithm": "AES",
      "key_size": 256,
      "created": "timestamp",
      "last_used": "timestamp",
      "purpose": "symmetric_encryption",
      "key": "encrypted_key_data"
    },
    "key_id_2": {
      "algorithm": "ChaCha20",
      "key_size": 256,
      "created": "timestamp",
      "last_used": "timestamp",
      "purpose": "symmetric_encryption",
      "key": "encrypted_key_data"
    }
  }
}
```

## Proceso de Encriptación del Almacén

1. El usuario proporciona una contraseña maestra
2. Se deriva una clave de encriptación usando Argon2 con un salt aleatorio
3. El salt se almacena en claro al principio del archivo
4. El resto del archivo (JSON) se encripta con AES-GCM usando la clave derivada

## Flujo de Trabajo

### Inicialización
1. Al iniciar el programa, se verifica si existe el archivo de almacenamiento
2. Si existe, se solicita la contraseña maestra
3. Se deriva la clave y se desencripta el almacén
4. Las claves se cargan en memoria

### Uso
1. Cuando se genera una nueva clave, se almacena en memoria
2. También se añade al almacén persistente y se guarda el archivo

### Cierre
1. Al cerrar el programa, se asegura que todas las claves estén guardadas
2. Se encripta el almacén con la clave derivada de la contraseña maestra

## Consideraciones de Seguridad

1. La contraseña maestra nunca se almacena, solo se usa para derivar la clave
2. Las claves en memoria se borran de forma segura cuando ya no se necesitan
3. Se implementará un mecanismo de bloqueo tras múltiples intentos fallidos
4. Se incluirá una opción para cambiar la contraseña maestra
