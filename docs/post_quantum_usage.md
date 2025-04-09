# Guía de Uso: Criptografía Post-Cuántica

Esta guía explica cómo utilizar la funcionalidad de criptografía post-cuántica en nuestro sistema criptográfico.

## Introducción

La criptografía post-cuántica (PQC) se refiere a algoritmos criptográficos que son resistentes a ataques de computadoras cuánticas. Con el avance en el desarrollo de computadoras cuánticas, muchos de los algoritmos criptográficos actuales (especialmente los basados en factorización de números primos como RSA o en logaritmos discretos como ECC) se volverán vulnerables. Nuestro sistema ahora incluye soporte para algoritmos post-cuánticos, lo que proporciona seguridad a largo plazo frente a amenazas cuánticas.

## Algoritmos Soportados

### Para Firmas Digitales

- **DILITHIUM2**: Nivel de seguridad NIST 2 (aproximadamente equivalente a AES-128)
- **DILITHIUM3**: Nivel de seguridad NIST 3 (aproximadamente equivalente a AES-192)
- **DILITHIUM5**: Nivel de seguridad NIST 5 (aproximadamente equivalente a AES-256)

### Para Encriptación

- **KYBER512**: Nivel de seguridad NIST 1 (aproximadamente equivalente a AES-128)
- **KYBER768**: Nivel de seguridad NIST 3 (aproximadamente equivalente a AES-192)
- **KYBER1024**: Nivel de seguridad NIST 5 (aproximadamente equivalente a AES-256)

## Requisitos Previos

- Tener instalado el sistema criptográfico
- Tener instalada la biblioteca `pqcrypto` (se puede instalar con `pip install pqcrypto`)

## Uso desde la Línea de Comandos

### Generación de Claves Post-Cuánticas

#### Para Firmas Digitales (Dilithium)

```
python -m src.main genkey --algorithm DILITHIUM3 --output dilithium_key
```

Esto generará dos archivos:
- `dilithium_key.private`: La clave privada para firmar
- `dilithium_key.public`: La clave pública para verificar firmas

#### Para Encriptación (Kyber)

```
python -m src.main genkey --algorithm KYBER768 --output kyber_key
```

Esto generará dos archivos:
- `kyber_key.private`: La clave privada para desencriptar
- `kyber_key.public`: La clave pública para encriptar

### Firma y Verificación con Dilithium

#### Firmar un Archivo

```
python -m src.main sign --key dilithium_key.private myfile.txt
```

Esto generará un archivo de firma `myfile.txt.sig`.

#### Verificar una Firma

```
python -m src.main verify --key dilithium_key.public myfile.txt myfile.txt.sig
```

### Encriptación y Desencriptación con Kyber

Actualmente, la encriptación y desencriptación directa con Kyber desde la línea de comandos no está implementada como un comando separado. Sin embargo, se puede utilizar a través de la API del sistema.

## Uso desde la API

### Generación de Claves

```python
from src.core.key_management import KeyManager

# Inicializar el gestor de claves
key_manager = KeyManager()

# Generar un par de claves Dilithium
public_key, private_key = key_manager.generate_asymmetric_keypair(algorithm="DILITHIUM3")

# Generar un par de claves Kyber
public_key, private_key = key_manager.generate_asymmetric_keypair(algorithm="KYBER768")
```

### Firma y Verificación con Dilithium

```python
from src.core.post_quantum import PostQuantumCrypto

# Inicializar el módulo de criptografía post-cuántica
pq_crypto = PostQuantumCrypto()

# Firmar un mensaje
message = b"Este es un mensaje de prueba"
signature = pq_crypto.sign(message, private_key, algorithm="DILITHIUM3")

# Verificar la firma
is_valid = pq_crypto.verify(message, signature, public_key, algorithm="DILITHIUM3")
```

### Encriptación y Desencriptación con Kyber

```python
from src.core.post_quantum import PostQuantumCrypto

# Inicializar el módulo de criptografía post-cuántica
pq_crypto = PostQuantumCrypto()

# Encriptar datos
message = b"Este es un mensaje secreto"
encrypted_data = pq_crypto.encrypt_with_kem(message, public_key, algorithm="KYBER768")

# Desencriptar datos
decrypted_data = pq_crypto.decrypt_with_kem(encrypted_data, private_key)
```

## Consideraciones de Seguridad

### Tamaños de Clave y Firmas

Los algoritmos post-cuánticos generalmente tienen claves y firmas más grandes que sus contrapartes clásicas:

- **Dilithium2**: Clave pública ~1.3 KB, clave privada ~2.5 KB, firma ~2.4 KB
- **Dilithium3**: Clave pública ~1.9 KB, clave privada ~4.0 KB, firma ~3.3 KB
- **Dilithium5**: Clave pública ~2.6 KB, clave privada ~4.9 KB, firma ~4.6 KB
- **Kyber512**: Clave pública ~0.8 KB, clave privada ~1.6 KB, ciphertext ~0.8 KB
- **Kyber768**: Clave pública ~1.2 KB, clave privada ~2.4 KB, ciphertext ~1.1 KB
- **Kyber1024**: Clave pública ~1.6 KB, clave privada ~3.2 KB, ciphertext ~1.6 KB

### Rendimiento

Los algoritmos post-cuánticos pueden ser más lentos que los algoritmos clásicos, especialmente para la generación de firmas. Sin embargo, la verificación de firmas y la encriptación/desencriptación con Kyber son relativamente eficientes.

### Compatibilidad

Los algoritmos post-cuánticos no son compatibles con los algoritmos clásicos. No se puede verificar una firma Dilithium con una clave RSA, ni desencriptar datos encriptados con Kyber usando una clave RSA.

## Solución de Problemas

### Error: "Post-quantum cryptography is not available"

Este error indica que la biblioteca `pqcrypto` no está instalada o no se pudo cargar. Asegúrese de instalarla con:

```
pip install pqcrypto
```

### Error: "Unsupported post-quantum algorithm"

Este error indica que el algoritmo especificado no está soportado. Asegúrese de usar uno de los algoritmos listados en esta guía.

### Error: "Verification failed"

Este error puede ocurrir si:
- La firma ha sido modificada
- El mensaje ha sido modificado
- Se está utilizando la clave pública incorrecta
- Se está utilizando un algoritmo diferente al utilizado para la firma

## Próximas Mejoras

- Soporte para encriptación y desencriptación directa con Kyber desde la línea de comandos
- Integración con la interfaz gráfica de usuario
- Soporte para más algoritmos post-cuánticos a medida que se estandaricen
- Mejoras de rendimiento para operaciones con claves y firmas grandes
