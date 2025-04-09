# Política de Seguridad

## Versiones Soportadas

Actualmente estamos proporcionando actualizaciones de seguridad para las siguientes versiones:

| Versión | Soportada          |
| ------- | ------------------ |
| 0.9.x   | :white_check_mark: |
| < 0.9.0 | :x:                |

## Reportar una Vulnerabilidad

Agradecemos los informes de vulnerabilidades de seguridad. Si descubres una vulnerabilidad en nuestro sistema criptográfico, por favor:

1. **No divulgues públicamente la vulnerabilidad** hasta que haya sido abordada.
2. Envía un correo electrónico a [tu-email@ejemplo.com] con detalles sobre la vulnerabilidad.
3. Incluye pasos para reproducir el problema, impacto potencial y, si es posible, una sugerencia para solucionarlo.
4. Espera confirmación de recepción (normalmente dentro de 48 horas).

## Proceso de Respuesta

Nuestro proceso para manejar las vulnerabilidades reportadas es:

1. Confirmaremos la recepción de tu informe dentro de 48 horas.
2. Proporcionaremos una evaluación inicial dentro de 1 semana.
3. Trabajaremos en una solución y te mantendremos informado del progreso.
4. Una vez solucionada, publicaremos un aviso de seguridad y te daremos crédito (a menos que prefieras permanecer anónimo).

## Mejores Prácticas de Seguridad

Este sistema criptográfico implementa las siguientes mejores prácticas:

- **Cifrado autenticado**: Utilizamos AES-GCM y ChaCha20-Poly1305 que proporcionan autenticación e integridad.
- **Algoritmos modernos**: Solo utilizamos algoritmos criptográficos modernos y seguros.
- **Generación segura de claves**: Utilizamos generadores de números aleatorios criptográficamente seguros.
- **Protección contra ataques de canal lateral**: Implementamos contramedidas contra ataques de tiempo y otros canales laterales.
- **Manejo seguro de errores**: Los mensajes de error no revelan información sensible.
- **Preparación post-cuántica**: Diseñado para integrar algoritmos resistentes a ataques cuánticos.

## Auditorías de Seguridad

Este proyecto aún no ha sido auditado por terceros. Planeamos realizar una auditoría de seguridad en el futuro.

## Divulgación Responsable

Creemos en la divulgación responsable de vulnerabilidades. Agradecemos a los investigadores de seguridad que nos ayudan a mejorar la seguridad de nuestro sistema y reconoceremos sus contribuciones (con su permiso).
