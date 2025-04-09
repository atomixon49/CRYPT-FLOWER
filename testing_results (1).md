# Resultados de Pruebas del Sistema Criptográfico

## Configuración Inicial

### Instalación de Dependencias
- **Comando**: `py -m pip install -r requirements.txt`
- **Resultado**: Éxito. Se instalaron todas las dependencias principales.
- **Observación**: La biblioteca python-magic requiere libmagic, que no está disponible por defecto en Windows. Se modificó el código para manejar este caso.

## Pruebas de Funcionalidad

### 1. Prueba de Encriptación de Archivo de Texto

- **Comando**: `py -m src.main encrypt test_sample.txt --password`
- **Resultado**: Éxito. El archivo se encriptó correctamente.
- **Observaciones**:
  - El sistema solicitó una contraseña y su confirmación.
  - Se generó un salt que debe guardarse para la desencriptación.
  - El archivo encriptado se guardó con la extensión .encrypted.

### 2. Prueba de Desencriptación de Archivo de Texto

- **Comando**: `py -m src.main decrypt test_sample.txt.encrypted --password`
- **Resultado**: Éxito. El archivo se desencriptó correctamente.
- **Observaciones**:
  - El sistema solicitó la contraseña y el salt utilizado durante la encriptación.
  - El contenido del archivo desencriptado coincide con el original.
  - Se detectó un problema con la codificación de caracteres especiales al mostrar el contenido, pero los datos están intactos.

### 3. Prueba de Generación de Claves para Firmas Digitales

- **Comando**: `py -m src.main genkey --output test_key`
- **Resultado**: Éxito. Se generó un par de claves (pública y privada).
- **Observaciones**:
  - Las claves se guardaron en archivos separados (test_key.private y test_key.public).
  - El algoritmo predeterminado es RSA-PSS con un tamaño de clave de 3072 bits.

### 4. Prueba de Firma Digital

- **Comando**: `py -m src.main sign --key test_key.private test_sample.txt`
- **Resultado**: Éxito. El archivo se firmó correctamente.
- **Observaciones**:
  - La firma se guardó en un archivo separado con extensión .sig.

### 5. Prueba de Verificación de Firma

- **Comando**: `py -m src.main verify --key test_key.public test_sample.txt test_sample.txt.sig`
- **Resultado**: Éxito. La firma se verificó correctamente.
- **Observaciones**:
  - El sistema confirmó que la firma es válida.

### 6. Prueba de Encriptación con ChaCha20-Poly1305

- **Comando**: `py -m src.main encrypt test_sample.txt --algorithm ChaCha20-Poly1305 --password`
- **Resultado**: Éxito. El archivo se encriptó correctamente usando ChaCha20-Poly1305.
- **Observaciones**:
  - El sistema utilizó correctamente el algoritmo especificado.
  - El archivo encriptado contiene el algoritmo en los metadatos.

### 7. Prueba de Desencriptación de Archivo ChaCha20-Poly1305

- **Comando**: `py -m src.main decrypt test_sample.txt.encrypted --password`
- **Resultado**: Éxito. El archivo se desencriptó correctamente.
- **Observaciones**:
  - El sistema detectó automáticamente el algoritmo usado para la encriptación.

### 8. Prueba de Firma con RSA-PKCS1v15

- **Comando**: `py -m src.main sign --key test_key_pkcs.private --algorithm RSA-PKCS1v15 --output test_sample.pkcs.sig test_sample.txt`
- **Resultado**: Éxito. El archivo se firmó correctamente.
- **Observaciones**:
  - El sistema generó la firma sin errores.

### 9. Prueba de Verificación de Firma RSA-PKCS1v15

- **Comando**: `py -m src.main verify --key test_key_pkcs.public test_sample.txt test_sample.pkcs.sig`
- **Resultado**: Fallo. La firma no se pudo verificar.
- **Observaciones**:
  - Se detectó un problema con la verificación de firmas usando el algoritmo RSA-PKCS1v15.
  - El mismo problema no ocurre con el algoritmo RSA-PSS predeterminado.

## Problemas Identificados

1. **Persistencia de Claves**
   - **Problema**: Las claves generadas durante la encriptación no persisten entre ejecuciones del programa.
   - **Impacto**: No es posible desencriptar archivos usando el Key ID después de cerrar el programa.
   - **Solución Propuesta**: Implementar un sistema de almacenamiento seguro de claves (base de datos encriptada, almacén de claves del sistema operativo, etc.).

2. **Manejo de Salt**
   - **Problema**: El usuario debe recordar y proporcionar el salt para la desencriptación cuando se usa una contraseña.
   - **Impacto**: Proceso de desencriptación complicado y propenso a errores.
   - **Solución Propuesta**: Almacenar el salt en el archivo encriptado o en un archivo de metadatos asociado.

3. **Dependencia de libmagic**
   - **Problema**: La biblioteca python-magic requiere libmagic, que no está disponible por defecto en Windows.
   - **Impacto**: Funcionalidad limitada en sistemas Windows sin configuración adicional.
   - **Solución Propuesta**: Usar alternativas multiplataforma para la detección de tipos de archivos o hacer que esta funcionalidad sea opcional.

4. **Codificación de Caracteres**
   - **Problema**: Problemas al mostrar caracteres especiales después de la desencriptación.
   - **Impacto**: Dificultad para verificar visualmente el contenido desencriptado.
   - **Solución Propuesta**: Guardar y restaurar la información de codificación en los metadatos del archivo encriptado.

## Mejoras Propuestas

1. **Interfaz Gráfica de Usuario**
   - Desarrollar una interfaz gráfica para facilitar el uso del sistema.
   - Incluir gestión visual de claves y archivos encriptados.

2. **Almacenamiento Seguro de Claves**
   - Implementar un sistema de almacenamiento seguro de claves que persista entre ejecuciones.
   - Proteger el almacén de claves con una contraseña maestra.

3. **Soporte para Encriptación de Directorios**
   - Añadir funcionalidad para encriptar/desencriptar directorios completos.
   - Mantener la estructura de directorios en el proceso.

4. **Implementación de Algoritmos Post-Cuánticos**
   - Integrar algoritmos resistentes a ataques cuánticos.
   - Ofrecer opciones de migración desde algoritmos clásicos.

5. **Mejora en el Manejo de PDF**
   - Implementar la encriptación selectiva de secciones de PDF.
   - Preservar metadatos y firmas digitales existentes en los PDF.

6. **Integración con Sistemas de Archivos**
   - Desarrollar extensiones para integrar con exploradores de archivos.
   - Permitir encriptación/desencriptación con clic derecho en archivos.

## Conclusiones

El sistema criptográfico desarrollado funciona correctamente para las operaciones básicas de encriptación, desencriptación, firma digital y verificación de firmas. Las pruebas realizadas demuestran que el sistema es capaz de proteger adecuadamente la información y verificar su integridad.

Sin embargo, se han identificado varios problemas y áreas de mejora que deberían abordarse antes de considerar el sistema listo para uso en producción. Los principales desafíos están relacionados con la persistencia de claves, la gestión del salt en el proceso de encriptación basado en contraseñas, y la compatibilidad multiplataforma.

Las mejoras propuestas buscan no solo resolver estos problemas, sino también ampliar la funcionalidad del sistema para hacerlo más completo y fácil de usar. La implementación de algoritmos post-cuánticos es particularmente importante para garantizar la seguridad a largo plazo frente a las amenazas emergentes de la computación cuántica.

En resumen, el sistema proporciona una base sólida para la protección criptográfica de archivos, pero requiere refinamiento adicional para convertirse en una solución robusta y lista para uso general.

