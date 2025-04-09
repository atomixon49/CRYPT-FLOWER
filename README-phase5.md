# Proyecto de Criptografía - Fase 5

## Características implementadas en la Fase 5

### 1. Documentación de la API con OpenAPI/Swagger

Se ha implementado una documentación completa de la API utilizando el estándar OpenAPI 3.0 a través de Flasgger. La documentación incluye:

- Descripción detallada de todos los endpoints
- Esquemas para solicitudes y respuestas
- Ejemplos de uso
- Información sobre autenticación
- Códigos de error y sus descripciones

Para acceder a la documentación, inicie la aplicación y navegue a `/api/docs/`.

### 2. Soporte para PKCS#11 para HSMs

Se ha añadido soporte para Hardware Security Modules (HSMs) a través del estándar PKCS#11, permitiendo:

- Generación de claves en el HSM
- Operaciones criptográficas utilizando claves almacenadas en el HSM
- Integración con algoritmos post-cuánticos
- Gestión de claves HSM a través de la API

Para configurar el soporte HSM, establezca las siguientes variables de entorno:
```
HSM_LIBRARY_PATH=/ruta/a/libreria/pkcs11.so
HSM_TOKEN_LABEL=mi_token
HSM_PIN=1234
```

### 3. Plugins para sistemas de gestión documental

Se han desarrollado plugins para integrar con sistemas de gestión documental:

- **SharePoint**: Integración con Microsoft SharePoint
- **Alfresco**: Integración con Alfresco Content Services
- **WebDAV**: Soporte genérico para sistemas que implementan WebDAV

Los plugins permiten:
- Navegar por documentos en el sistema
- Cifrar y descifrar documentos directamente en el sistema
- Firmar y verificar documentos
- Gestionar metadatos

## Instalación de dependencias

Para instalar las dependencias necesarias para la Fase 5:

```bash
pip install -r requirements-phase5.txt
```

## Uso de las nuevas características

### Documentación Swagger

1. Inicie la aplicación
2. Navegue a `http://localhost:5000/api/docs/`
3. Explore la documentación interactiva

### Operaciones con HSM

```bash
# Listar slots HSM disponibles
curl -X GET "http://localhost:5000/api/v1/hsm/slots" -H "Authorization: Bearer <token>"

# Generar una clave en el HSM
curl -X POST "http://localhost:5000/api/v1/hsm/keys" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "key_type": "RSA",
    "key_size": 2048,
    "key_label": "mi_clave_hsm",
    "extractable": false
  }'
```

### Uso de plugins para sistemas de gestión documental

```bash
# Listar plugins disponibles
curl -X GET "http://localhost:5000/api/v1/plugins" -H "Authorization: Bearer <token>"

# Configurar plugin de SharePoint
curl -X POST "http://localhost:5000/api/v1/plugins/sharepoint/configure" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "site_url": "https://ejemplo.sharepoint.com/sites/misitio",
    "auth_type": "username_password",
    "username": "usuario@ejemplo.com",
    "password": "contraseña"
  }'

# Cifrar un documento en SharePoint
curl -X POST "http://localhost:5000/api/v1/plugins/sharepoint/encrypt" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "document_id": "/sites/misitio/Documentos compartidos/confidencial.docx",
    "key_id": "mi_clave",
    "algorithm": "AES-GCM",
    "metadata": {
      "clasificacion": "confidencial",
      "departamento": "finanzas"
    }
  }'
```

## Próximos pasos (Fase 6)

En la próxima fase se implementarán:

- Mejoras en la interfaz de usuario
- Soporte para más algoritmos criptográficos
- Integración con servicios en la nube
- Mejoras en el rendimiento y la escalabilidad
