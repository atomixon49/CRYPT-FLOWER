# Diseño de la Gestión del Salt

## Problema Actual

Actualmente, cuando se utiliza encriptación basada en contraseñas:
1. Se genera un salt aleatorio durante la encriptación
2. El salt se muestra al usuario, quien debe anotarlo manualmente
3. Durante la desencriptación, el usuario debe proporcionar tanto la contraseña como el salt
4. Este proceso es propenso a errores y poco amigable para el usuario

## Solución Propuesta

Almacenar el salt en los metadatos del archivo encriptado, de modo que:
1. El salt siga siendo único para cada archivo encriptado
2. No sea necesario que el usuario recuerde o proporcione el salt
3. El sistema pueda extraer automáticamente el salt durante la desencriptación

## Enfoque Técnico

### Estructura de Archivo Encriptado

Actualmente, los archivos encriptados tienen esta estructura en formato JSON:
```json
{
  "metadata": {
    "filename": "original_filename.txt",
    "original_size": 1234,
    "encryption_algorithm": "AES-GCM",
    "key_id": "key_id_or_null",
    "user_metadata": {}
  },
  "ciphertext": "base64_encoded_ciphertext",
  "nonce": "base64_encoded_nonce",
  "tag": "base64_encoded_tag"
}
```

Modificaremos esta estructura para incluir el salt:
```json
{
  "metadata": {
    "filename": "original_filename.txt",
    "original_size": 1234,
    "encryption_algorithm": "AES-GCM",
    "key_id": "key_id_or_null",
    "user_metadata": {},
    "encryption_method": "password_based",
    "salt": "base64_encoded_salt"
  },
  "ciphertext": "base64_encoded_ciphertext",
  "nonce": "base64_encoded_nonce",
  "tag": "base64_encoded_tag"
}
```

### Flujo de Trabajo

#### Encriptación
1. El usuario proporciona una contraseña
2. El sistema genera un salt aleatorio
3. Se deriva una clave de la contraseña y el salt
4. Se encripta el archivo con la clave derivada
5. Se almacena el salt en los metadatos del archivo encriptado
6. No se muestra el salt al usuario

#### Desencriptación
1. El usuario proporciona la contraseña
2. El sistema extrae el salt de los metadatos del archivo encriptado
3. Se deriva la misma clave usando la contraseña proporcionada y el salt extraído
4. Se desencripta el archivo con la clave derivada

## Consideraciones de Seguridad

1. **Seguridad del Salt**: Almacenar el salt en el archivo encriptado no compromete la seguridad, ya que:
   - El salt no es secreto en los sistemas criptográficos
   - Su propósito es prevenir ataques de diccionario y tablas rainbow
   - Incluso con el salt conocido, un atacante aún necesita la contraseña

2. **Compatibilidad**: Necesitamos mantener compatibilidad con archivos encriptados anteriormente:
   - Detectar si el salt está en los metadatos
   - Si no está, solicitar al usuario que lo proporcione manualmente
   - Proporcionar una herramienta de migración para actualizar archivos antiguos
