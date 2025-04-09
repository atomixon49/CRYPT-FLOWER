# Investigación sobre Criptografía Post-Cuántica

## Introducción

La criptografía post-cuántica (PQC) se refiere a algoritmos criptográficos que son resistentes a ataques de computadoras cuánticas. Con el avance en el desarrollo de computadoras cuánticas, muchos de los algoritmos criptográficos actuales (especialmente los basados en factorización de números primos como RSA o en logaritmos discretos como ECC) se volverán vulnerables. Este documento presenta una investigación sobre los algoritmos post-cuánticos más prometedores para su implementación en nuestro sistema criptográfico.

## Algoritmos Post-Cuánticos Principales

El Instituto Nacional de Estándares y Tecnología (NIST) de EE.UU. ha estado liderando un proceso de estandarización para algoritmos post-cuánticos. Después de varias rondas de evaluación, han seleccionado algunos finalistas y alternativas. A continuación, se presentan los más relevantes:

### 1. CRYSTALS-Kyber (Encriptación de Clave Pública)

**Descripción**: Kyber es un mecanismo de encapsulamiento de clave (KEM) basado en problemas de retículos, específicamente en el problema de aprendizaje con errores sobre anillos (Ring-LWE).

**Ventajas**:
- Seleccionado por el NIST como el estándar para encriptación post-cuántica
- Buen equilibrio entre tamaño de clave, tamaño de cifrado y velocidad
- Implementaciones eficientes disponibles
- Bien estudiado y analizado

**Desventajas**:
- Tamaños de clave más grandes que ECC (aunque más pequeños que otros esquemas post-cuánticos)
- Relativamente nuevo comparado con algoritmos clásicos

**Bibliotecas disponibles**:
- liboqs (Open Quantum Safe)
- PQClean
- pqcrypto

### 2. CRYSTALS-Dilithium (Firmas Digitales)

**Descripción**: Dilithium es un esquema de firma digital basado en problemas de retículos, similar a Kyber.

**Ventajas**:
- Seleccionado por el NIST como uno de los estándares para firmas post-cuánticas
- Buen rendimiento general
- Implementaciones eficientes disponibles
- Bien estudiado y analizado

**Desventajas**:
- Firmas relativamente grandes comparadas con ECDSA
- Operaciones de firma más lentas que los esquemas clásicos

**Bibliotecas disponibles**:
- liboqs (Open Quantum Safe)
- PQClean
- pqcrypto

### 3. FALCON (Firmas Digitales)

**Descripción**: FALCON es un esquema de firma digital basado en retículos NTRU.

**Ventajas**:
- Seleccionado por el NIST como uno de los estándares para firmas post-cuánticas
- Firmas más pequeñas que Dilithium
- Verificación rápida

**Desventajas**:
- Implementación más compleja
- Generación de firmas más lenta que Dilithium
- Mayor uso de memoria

**Bibliotecas disponibles**:
- liboqs (Open Quantum Safe)
- PQClean
- Implementación de referencia oficial

### 4. SPHINCS+ (Firmas Digitales)

**Descripción**: SPHINCS+ es un esquema de firma digital basado en funciones hash, lo que lo hace muy diferente de los esquemas basados en retículos.

**Ventajas**:
- Seleccionado por el NIST como uno de los estándares para firmas post-cuánticas
- Seguridad basada en supuestos mínimos (solo requiere funciones hash resistentes a colisiones)
- No depende de estructuras algebraicas complejas

**Desventajas**:
- Firmas muy grandes
- Operaciones de firma lentas
- No es práctico para muchas aplicaciones debido al tamaño de las firmas

**Bibliotecas disponibles**:
- liboqs (Open Quantum Safe)
- PQClean
- Implementación de referencia oficial

## Bibliotecas para Implementación

### 1. liboqs (Open Quantum Safe)

**Descripción**: liboqs es una biblioteca C de código abierto que implementa algoritmos criptográficos resistentes a ataques cuánticos.

**Ventajas**:
- Implementa todos los finalistas del NIST
- Bien mantenida y actualizada
- Tiene envoltorios para varios lenguajes, incluyendo Python (pyoqs)
- Integrada con OpenSSL a través de OQS-OpenSSL

**Desventajas**:
- Puede ser compleja para integrar en sistemas existentes
- Requiere compilación en algunas plataformas

**URL**: https://github.com/open-quantum-safe/liboqs

### 2. PQClean

**Descripción**: PQClean es una colección de implementaciones limpias de algoritmos criptográficos post-cuánticos.

**Ventajas**:
- Código limpio y bien documentado
- Enfoque en la seguridad y la corrección
- Implementaciones de referencia

**Desventajas**:
- Menos enfocado en el rendimiento
- Menos integraciones con otras bibliotecas

**URL**: https://github.com/PQClean/PQClean

### 3. pqcrypto

**Descripción**: pqcrypto es un proyecto que proporciona implementaciones de algoritmos post-cuánticos en Python.

**Ventajas**:
- Fácil de usar en proyectos Python
- No requiere compilación
- API simple

**Desventajas**:
- Menos completo que liboqs
- Puede tener problemas de rendimiento al ser implementado en Python

**URL**: https://github.com/kpdemetriou/pqcrypto

## Recomendaciones para Nuestro Sistema

Basándonos en la investigación realizada, recomendamos las siguientes implementaciones:

### Para Encriptación de Clave Pública:
- **Algoritmo**: CRYSTALS-Kyber
- **Biblioteca**: liboqs con el envoltorio Python pyoqs
- **Justificación**: Kyber es el estándar seleccionado por el NIST, tiene buen rendimiento y tamaños de clave razonables. liboqs proporciona una implementación robusta y bien mantenida.

### Para Firmas Digitales:
- **Algoritmo Principal**: CRYSTALS-Dilithium
- **Algoritmo Alternativo**: FALCON (para casos donde el tamaño de la firma es crítico)
- **Biblioteca**: liboqs con el envoltorio Python pyoqs
- **Justificación**: Dilithium ofrece un buen equilibrio entre tamaño de firma y velocidad. FALCON puede ser una alternativa cuando se requieren firmas más pequeñas.

## Plan de Implementación

1. **Fase 1**: Integrar la biblioteca pyoqs en nuestro sistema
   - Instalar dependencias necesarias
   - Crear wrappers para la API de pyoqs

2. **Fase 2**: Implementar soporte para Kyber
   - Añadir generación de claves Kyber
   - Implementar encriptación/desencriptación con Kyber
   - Crear pruebas unitarias

3. **Fase 3**: Implementar soporte para Dilithium
   - Añadir generación de claves Dilithium
   - Implementar firma/verificación con Dilithium
   - Crear pruebas unitarias

4. **Fase 4**: Actualizar la interfaz de usuario
   - Añadir opciones para algoritmos post-cuánticos en CLI y GUI
   - Actualizar la documentación

## Conclusiones

La implementación de algoritmos post-cuánticos en nuestro sistema criptográfico es una medida proactiva importante para garantizar la seguridad a largo plazo. Aunque estos algoritmos son relativamente nuevos y pueden evolucionar con el tiempo, comenzar a integrarlos ahora nos permitirá estar preparados para la era de la computación cuántica.

Los algoritmos seleccionados (Kyber y Dilithium) representan el estado del arte actual en criptografía post-cuántica y han sido rigurosamente evaluados por la comunidad criptográfica. La biblioteca liboqs proporciona implementaciones robustas y bien mantenidas de estos algoritmos, lo que facilita su integración en nuestro sistema.

## Referencias

1. NIST Post-Quantum Cryptography Standardization: https://csrc.nist.gov/Projects/post-quantum-cryptography
2. CRYSTALS-Kyber: https://pq-crystals.org/kyber/
3. CRYSTALS-Dilithium: https://pq-crystals.org/dilithium/
4. FALCON: https://falcon-sign.info/
5. SPHINCS+: https://sphincs.org/
6. Open Quantum Safe: https://openquantumsafe.org/
