# Casos de Uso del Sistema Criptográfico

Este documento describe los casos de uso típicos de nuestro sistema criptográfico, proporcionando ejemplos prácticos de cómo puede utilizarse para resolver problemas de seguridad en diferentes escenarios.

## Caso de Uso 1: Protección de Documentos Confidenciales

### Escenario
Un abogado necesita almacenar y compartir documentos confidenciales con sus clientes de manera segura.

### Solución
1. **Inicializar el almacenamiento de claves**:
   ```
   python -m src.main init-storage
   ```

2. **Generar una clave para documentos legales**:
   ```
   python -m src.main genkey --output legal_docs_key
   ```

3. **Encriptar un documento confidencial**:
   ```
   python -m src.main encrypt --file contrato.pdf --key legal_docs_key.private
   ```

4. **Compartir el documento encriptado y la clave pública**:
   - Enviar `contrato.pdf.encrypted` al cliente
   - Compartir `legal_docs_key.public` para verificación

5. **El cliente puede verificar la autenticidad**:
   ```
   python -m src.main verify --file contrato.pdf --signature contrato.pdf.sig --key legal_docs_key.public
   ```

### Beneficios
- Los documentos confidenciales están protegidos incluso si se accede al sistema de almacenamiento
- La firma digital garantiza la autenticidad e integridad
- El abogado puede demostrar que el documento no ha sido alterado

## Caso de Uso 2: Protección de Datos Personales

### Escenario
Un usuario desea proteger información personal sensible (documentos de identidad, información financiera) en su computadora personal.

### Solución
1. **Encriptar archivos con contraseña**:
   ```
   python -m src.main encrypt --file datos_bancarios.txt --password
   ```

2. **Desencriptar cuando sea necesario**:
   ```
   python -m src.main decrypt --file datos_bancarios.txt.encrypted --password
   ```

### Beneficios
- No es necesario recordar o gestionar claves criptográficas
- El salt se gestiona automáticamente
- La información está protegida incluso si la computadora es robada o comprometida
- La codificación de caracteres se preserva correctamente

## Caso de Uso 3: Compartir Archivos de Manera Segura

### Escenario
Un equipo de desarrollo necesita compartir código fuente y documentación de manera segura entre miembros del equipo.

### Solución
1. **Crear una clave compartida para el equipo**:
   ```
   python -m src.main genkey --output team_key
   ```

2. **Distribuir la clave privada de forma segura a los miembros del equipo**

3. **Encriptar archivos para compartir**:
   ```
   python -m src.main encrypt --file codigo_fuente.zip --key team_key.private
   ```

4. **Firmar los archivos para verificar la autoría**:
   ```
   python -m src.main sign --file codigo_fuente.zip --key personal_key.private
   ```

5. **Compartir los archivos encriptados y firmados**

6. **Los miembros del equipo pueden desencriptar y verificar**:
   ```
   python -m src.main decrypt --file codigo_fuente.zip.encrypted --key team_key.private
   python -m src.main verify --file codigo_fuente.zip --signature codigo_fuente.zip.sig --key personal_key.public
   ```

### Beneficios
- Los archivos están protegidos durante la transmisión
- Se puede verificar quién creó o modificó cada archivo
- Funciona en todas las plataformas que utilizan los miembros del equipo

## Caso de Uso 4: Respaldo Seguro de Datos

### Escenario
Una empresa necesita realizar respaldos seguros de sus datos en servicios de almacenamiento en la nube.

### Solución
1. **Generar una clave de respaldo**:
   ```
   python -m src.main genkey --output backup_key
   ```

2. **Encriptar los archivos de respaldo**:
   ```
   python -m src.main encrypt --file database_dump.sql --key backup_key.private
   ```

3. **Subir los archivos encriptados a la nube**

4. **En caso de necesitar restaurar**:
   ```
   python -m src.main decrypt --file database_dump.sql.encrypted --key backup_key.private
   ```

### Beneficios
- Los datos sensibles están protegidos incluso en servicios de almacenamiento no confiables
- Solo las personas autorizadas con acceso a la clave pueden restaurar los datos
- Se mantiene la integridad de los datos durante el almacenamiento

## Caso de Uso 5: Protección de Comunicaciones

### Escenario
Dos personas necesitan intercambiar mensajes confidenciales.

### Solución
1. **Cada persona genera su par de claves**:
   ```
   python -m src.main genkey --output alice_key
   python -m src.main genkey --output bob_key
   ```

2. **Intercambiar claves públicas**:
   - Alice envía `alice_key.public` a Bob
   - Bob envía `bob_key.public` a Alice

3. **Alice encripta un mensaje para Bob**:
   ```
   python -m src.main encrypt --file mensaje_para_bob.txt --key bob_key.public
   ```

4. **Alice firma el mensaje**:
   ```
   python -m src.main sign --file mensaje_para_bob.txt --key alice_key.private --algorithm RSA-PSS
   ```

5. **Bob verifica y desencripta el mensaje**:
   ```
   python -m src.main verify --file mensaje_para_bob.txt --signature mensaje_para_bob.txt.sig --key alice_key.public --algorithm RSA-PSS
   python -m src.main decrypt --file mensaje_para_bob.txt.encrypted --key bob_key.private
   ```

### Beneficios
- Comunicación segura incluso a través de canales no seguros
- Verificación de la identidad del remitente
- Protección contra interceptación y manipulación

## Caso de Uso 6: Protección de Documentos Multilingües

### Escenario
Una organización internacional necesita proteger documentos en múltiples idiomas con diferentes conjuntos de caracteres.

### Solución
1. **Encriptar documentos en diferentes idiomas**:
   ```
   python -m src.main encrypt --file documento_español.txt --password
   python -m src.main encrypt --file document_français.txt --password
   python -m src.main encrypt --file 中文文档.txt --password
   ```

2. **Desencriptar manteniendo la codificación correcta**:
   ```
   python -m src.main decrypt --file documento_español.txt.encrypted --password
   ```

### Beneficios
- Preservación automática de la codificación de caracteres
- Soporte para múltiples idiomas y conjuntos de caracteres
- Experiencia de usuario consistente independientemente del idioma

## Caso de Uso 7: Verificación de Integridad de Software

### Escenario
Un desarrollador de software necesita distribuir su aplicación y permitir a los usuarios verificar que no ha sido modificada.

### Solución
1. **Generar un par de claves para firmar**:
   ```
   python -m src.main genkey --output software_release_key
   ```

2. **Firmar el paquete de software**:
   ```
   python -m src.main sign --file app_v1.0.zip --key software_release_key.private --algorithm RSA-PKCS1v15
   ```

3. **Distribuir el software, la firma y la clave pública**

4. **Los usuarios verifican la integridad**:
   ```
   python -m src.main verify --file app_v1.0.zip --signature app_v1.0.zip.sig --key software_release_key.public --algorithm RSA-PKCS1v15
   ```

### Beneficios
- Los usuarios pueden verificar que el software no ha sido manipulado
- Soporte para diferentes algoritmos de firma
- Proceso de verificación simple y claro

## Conclusión

Estos casos de uso demuestran la versatilidad y utilidad de nuestro sistema criptográfico en diferentes escenarios. El sistema proporciona:

- **Protección robusta** para datos confidenciales
- **Verificación de autenticidad e integridad** a través de firmas digitales
- **Facilidad de uso** con gestión automática de salt y codificación
- **Flexibilidad** para diferentes necesidades de seguridad
- **Compatibilidad multiplataforma** para entornos heterogéneos

Con estas capacidades, nuestro sistema criptográfico puede satisfacer las necesidades de seguridad de individuos, equipos y organizaciones en una amplia variedad de contextos.
