# Análisis del Problema de Verificación de Firmas RSA-PKCS1v15

## Problema Observado

Durante las pruebas del sistema, se detectó que las firmas creadas con el algoritmo RSA-PKCS1v15 no pueden ser verificadas correctamente, incluso cuando se usa el par de claves correcto. Sin embargo, las firmas creadas con el algoritmo RSA-PSS (el predeterminado) funcionan correctamente.

## Posibles Causas

1. **Implementación incorrecta del algoritmo RSA-PKCS1v15**:
   - Puede haber un error en la forma en que se implementa la firma o verificación para este algoritmo específico.
   - Posiblemente se estén utilizando parámetros incorrectos o incompatibles.

2. **Incompatibilidad entre firma y verificación**:
   - Es posible que la firma se esté creando con un conjunto de parámetros, pero la verificación esté utilizando un conjunto diferente.
   - Podría haber una discrepancia en cómo se maneja el algoritmo de hash entre la firma y la verificación.

3. **Problemas con el formato de la firma**:
   - RSA-PKCS1v15 tiene requisitos específicos de formato que podrían no estar siendo manejados correctamente.
   - Podría haber un problema con el padding o la codificación de la firma.

4. **Problemas con la biblioteca criptográfica subyacente**:
   - Podría haber un bug en la biblioteca cryptography que estamos utilizando.
   - Podría haber incompatibilidades entre diferentes versiones de la biblioteca.

## Enfoque para la Depuración

1. **Análisis del código actual**:
   - Examinar detalladamente la implementación de los métodos `_sign_rsa_pkcs1v15` y `_verify_rsa_pkcs1v15`.
   - Comparar con la implementación de RSA-PSS que funciona correctamente.

2. **Verificación de parámetros**:
   - Asegurarse de que los mismos parámetros (especialmente el algoritmo de hash) se utilicen tanto para la firma como para la verificación.
   - Verificar que los parámetros sean compatibles con la especificación PKCS#1 v1.5.

3. **Pruebas aisladas**:
   - Crear pruebas unitarias específicas para RSA-PKCS1v15 que aíslen el problema.
   - Probar con diferentes tamaños de datos y diferentes algoritmos de hash.

4. **Consulta de documentación**:
   - Revisar la documentación de la biblioteca cryptography para asegurarse de que estamos utilizando la API correctamente.
   - Buscar ejemplos de código que utilicen RSA-PKCS1v15 correctamente.

## Solución Propuesta

Una vez identificada la causa exacta del problema, implementaremos una solución que podría incluir:

1. Corregir la implementación de los métodos de firma y verificación.
2. Asegurar la consistencia de parámetros entre firma y verificación.
3. Añadir pruebas exhaustivas para todos los algoritmos de firma soportados.
4. Mejorar el manejo de errores para proporcionar mensajes más claros cuando falla la verificación.
