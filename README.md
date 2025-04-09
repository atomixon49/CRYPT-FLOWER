# Sistema Criptográfico Avanzado

Un sistema criptográfico completo y robusto que aborda los problemas de los sistemas criptográficos actuales, proporcionando seguridad mejorada, flexibilidad y características avanzadas.

## Características

### Funcionalidades Básicas
- ✅ Cifrado/descifrado simétrico (AES-GCM, ChaCha20-Poly1305)
- ✅ Firmas digitales (RSA-PSS, RSA-PKCS1v15)
- ✅ Gestión de claves (generación, almacenamiento, rotación)
- ✅ Manejo de archivos (texto, binario, PDF)

### Características Avanzadas
- ✅ Criptografía híbrida (combinación de algoritmos clásicos y post-cuánticos)
- ✅ Cifrado multi-destinatario (cifrado para múltiples receptores)
- ✅ Co-firmas (cadenas de firmas con múltiples firmantes)
- ✅ Sellado de tiempo (timestamping)
- ✅ Verificación de revocación de certificados (CRL, OCSP)
- ✅ Soporte completo para criptografía post-cuántica

## Ventajas

- **Seguridad mejorada**: Implementación de algoritmos modernos y seguros
- **Preparado para la era post-cuántica**: Diseñado para integrar algoritmos resistentes a ataques cuánticos
- **Flexibilidad**: Soporte para múltiples algoritmos y escenarios de uso
- **Usabilidad**: Interfaz intuitiva tanto en línea de comandos como GUI
- **Extensibilidad**: Arquitectura modular que facilita la adición de nuevas características

## Requisitos

- Python 3.8 o superior
- Bibliotecas requeridas (ver `requirements.txt`)

## Instalación

```bash
# Clonar el repositorio
git clone https://github.com/tu-usuario/sistema-criptografico.git
cd sistema-criptografico

# Crear un entorno virtual (opcional pero recomendado)
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt
```

## Uso

### Encriptación y Desencriptación

```python
from src_crypto.encryption import EncryptionEngine
from src_crypto.key_management import KeyManager

# Inicializar componentes
key_manager = KeyManager()
encryption_engine = EncryptionEngine(key_manager)

# Generar una clave
key = key_manager.generate_key(algorithm='AES')

# Encriptar datos
data = b'Información confidencial'
encryption_result = encryption_engine.encrypt(data, key, algorithm='AES-GCM')

# Desencriptar datos
decrypted_data = encryption_engine.decrypt(encryption_result, key)
print(decrypted_data.decode('utf-8'))  # Información confidencial
```

### Firmas Digitales

```python
from src_crypto.signatures import SignatureEngine

# Inicializar el motor de firmas
signature_engine = SignatureEngine(key_manager)

# Generar un par de claves para firmas
private_key, public_key = key_manager.generate_keypair(algorithm='RSA')

# Firmar datos
data = b'Documento a firmar'
signature = signature_engine.sign(data, private_key, algorithm='RSA-PSS')

# Verificar firma
is_valid = signature_engine.verify(data, signature, public_key, algorithm='RSA-PSS')
print(f'Firma válida: {is_valid}')  # Firma válida: True
```

### Criptografía Post-Cuántica

```python
from src_core.post_quantum import PostQuantumCrypto

# Inicializar el módulo post-cuántico
pq_crypto = PostQuantumCrypto()

# Generar un par de claves para algoritmo Kyber
public_key, private_key = pq_crypto.generate_keypair(algorithm='KYBER768')

# Encapsular una clave compartida
ciphertext, shared_secret = pq_crypto.encapsulate(public_key, algorithm='KYBER768')

# Decapsular la clave compartida
decapsulated_secret = pq_crypto.decapsulate(ciphertext, private_key, algorithm='KYBER768')

# Verificar que ambas claves son iguales
print(shared_secret == decapsulated_secret)  # True
```

### Manejo de Archivos

```python
from src_crypto.key_management import KeyManager
from src_crypto.encryption import EncryptionEngine
from src_file_handlers.text_handler import TextFileHandler

# Inicializar componentes
key_manager = KeyManager()
encryption_engine = EncryptionEngine(key_manager)
text_handler = TextFileHandler(key_manager, encryption_engine)

# Encriptar un archivo de texto
key = key_manager.generate_key(algorithm='AES')
result = text_handler.encrypt_file(
    input_path='documento.txt',
    output_path='documento.encrypted',
    key=key,
    algorithm='AES-GCM'
)

# Desencriptar un archivo
text_handler.decrypt_file(
    input_path='documento.encrypted',
    output_path='documento_desencriptado.txt',
    key=key
)
```

### Interfaz de Línea de Comandos

```bash
# Cifrar un archivo
python -m src_main.main encrypt --file documento.txt --output documento.encrypted --algorithm AES-GCM

# Descifrar un archivo
python -m src_main.main decrypt --file documento.encrypted --output documento.decrypted

# Firmar un archivo
python -m src_main.main sign --file documento.txt --output documento.sig

# Verificar una firma
python -m src_main.main verify --file documento.txt --signature documento.sig
```

### Interfaz Gráfica

```bash
# Iniciar la interfaz gráfica
python -m src_main.main --gui
```

## Estructura del Proyecto

El proyecto CRYPT-FLOWER ha sido reorganizado para mejorar la claridad y mantenibilidad del código. La nueva estructura es la siguiente:

```
src_main/                  # Punto de entrada principal de la aplicación
├── __init__.py           # Inicialización del módulo
└── main.py               # Archivo principal de ejecución

src_core/                  # Componentes principales del núcleo criptográfico
├── cert_revocation.py    # Verificación de revocación de certificados
├── cosign.py             # Funcionalidad de co-firma
├── hsm_key_manager.py    # Gestión de claves en HSM
├── multi_recipient_encryption.py # Encriptación para múltiples destinatarios
├── post_quantum.py       # Soporte básico para criptografía post-cuántica
└── timestamp.py          # Sellado de tiempo

src_crypto/                # Algoritmos y motores de encriptación
├── encryption.py         # Motor principal de encriptación
├── signatures.py         # Motor de firmas digitales
├── key_management.py     # Gestión de claves criptográficas
├── hybrid_crypto.py      # Criptografía híbrida (clásica + post-cuántica)
├── crypto_audit.py       # Auditoría de operaciones criptográficas
├── crypto_benchmark.py   # Benchmarking de algoritmos criptográficos
├── jwt_interface.py      # Interfaz para tokens JWT
├── key_rotation.py       # Rotación automática de claves
├── key_storage.py        # Almacenamiento seguro de claves
├── pkcs11_interface.py   # Interfaz para PKCS#11 (HSM)
├── post_quantum.py       # Implementación avanzada de algoritmos post-cuánticos
└── x509_certificates.py  # Manejo de certificados X.509

src_file_handlers/         # Manejadores de archivos
├── text_handler.py       # Encriptación/desencriptación de archivos de texto
├── pdf_handler.py        # Encriptación/desencriptación de archivos PDF
├── pdf_section_handler.py # Encriptación de secciones específicas de PDF
└── directory_handler.py  # Procesamiento de directorios completos

src_ui/                    # Interfaces de usuario
├── cli/                  # Interfaz de línea de comandos
│   ├── __main__.py        # Punto de entrada para CLI
│   ├── cert_revocation_commands.py # Comandos para revocación de certificados
│   ├── cosign_commands.py  # Comandos para co-firma
│   ├── multi_recipient_commands.py # Comandos para encriptación multi-destinatario
│   └── timestamp_commands.py # Comandos para sellado de tiempo
├── gui/                  # Interfaz gráfica de usuario
│   ├── main_window.py     # Ventana principal de la aplicación
│   ├── run.py             # Inicialización de la GUI
│   └── tabs/              # Pestañas de la interfaz gráfica
│       ├── encryption_tab.py # Pestaña de encriptación
│       ├── signatures_tab.py # Pestaña de firmas
│       ├── key_management_tab.py # Pestaña de gestión de claves
│       ├── audit_tab.py      # Pestaña de auditoría
│       ├── benchmark_tab.py  # Pestaña de benchmarking
│       ├── cert_revocation_tab.py # Pestaña de revocación de certificados
│       ├── cosign_tab.py     # Pestaña de co-firma
│       ├── directory_tab.py  # Pestaña de procesamiento de directorios
│       ├── jwt_tab.py        # Pestaña de tokens JWT
│       ├── key_rotation_tab.py # Pestaña de rotación de claves
│       ├── multi_recipient_tab.py # Pestaña de encriptación multi-destinatario
│       └── pdf_section_tab.py # Pestaña de secciones PDF
└── cli_pdf_sections.py   # CLI para secciones PDF

src_security/              # Pruebas y herramientas de seguridad
├── fuzzing/              # Pruebas de fuzzing
│   ├── fuzz_generator.py  # Generador de datos para fuzzing
│   ├── fuzz_result.py     # Resultados de pruebas de fuzzing
│   └── fuzzing_engine.py  # Motor de fuzzing
├── penetration_tests/    # Pruebas de penetración
│   ├── crypto_attack_simulator.py # Simulador de ataques criptográficos
│   ├── penetration_tester.py # Tester de penetración general
│   └── ui_security_tester.py # Tester de seguridad de UI
├── static_analysis/      # Análisis estático de código
│   ├── analyzer.py        # Analizador de código
│   ├── report.py          # Generador de informes
│   └── rules.py           # Reglas de análisis
├── run_all_tests.py      # Ejecuta todas las pruebas de seguridad
├── run_api_security_tests.py # Pruebas de seguridad para API
├── run_gui_security_tests.py # Pruebas de seguridad para GUI
└── run_security_tests.py # Pruebas de seguridad generales
```

### Descripción de los Componentes Principales

#### src_main
Contiene el punto de entrada principal de la aplicación. Desde aquí se inicializa y coordina el resto de los componentes.

#### src_core
Contiene los componentes fundamentales del núcleo criptográfico, como la verificación de revocación de certificados, co-firma, gestión de claves en HSM, encriptación para múltiples destinatarios, soporte para criptografía post-cuántica y sellado de tiempo.

#### src_crypto
Implementa los algoritmos y motores de encriptación, incluyendo el motor principal de encriptación, firmas digitales, gestión de claves, criptografía híbrida, auditoría, benchmarking, interfaz JWT, rotación de claves, almacenamiento seguro, interfaz PKCS#11 para HSM, algoritmos post-cuánticos avanzados y manejo de certificados X.509.

#### src_file_handlers
Proporciona manejadores para diferentes tipos de archivos, como texto plano, PDF (completo o por secciones) y directorios completos.

#### src_ui
Implementa las interfaces de usuario, tanto la interfaz de línea de comandos (CLI) como la interfaz gráfica (GUI). La GUI está organizada en pestañas para facilitar el acceso a las diferentes funcionalidades.

#### src_security
Contiene herramientas y pruebas de seguridad, incluyendo fuzzing, pruebas de penetración y análisis estático de código.

## Pruebas

El sistema ha sido probado exhaustivamente para garantizar su correcto funcionamiento. Para ejecutar las pruebas:

```bash
# Ejecutar todas las pruebas
python -m unittest discover tests

# Ejecutar pruebas específicas
python -m unittest tests.test_encryption
```

## Seguridad

Este sistema implementa las mejores prácticas de seguridad, incluyendo:

- Cifrado autenticado para todas las operaciones
- Generación segura de claves
- Protección contra ataques de canal lateral
- Manejo adecuado de errores sin filtración de información
- Consideración para seguridad post-cuántica

## Contribuir

Las contribuciones son bienvenidas. Por favor, sigue estos pasos:

1. Haz un fork del repositorio
2. Crea una rama para tu característica (`git checkout -b feature/nueva-caracteristica`)
3. Realiza tus cambios
4. Ejecuta las pruebas
5. Envía un pull request

## Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

## Estado del Proyecto

Este proyecto se encuentra en fase beta. La mayoría de las características están implementadas y probadas, pero algunas funcionalidades avanzadas están aún en desarrollo.

## Próximos Pasos

Aunque el proyecto está completo, siempre hay oportunidades para mejoras futuras:

### Mejoras de Rendimiento:
- Optimización para operaciones con archivos grandes
- Paralelización de operaciones criptográficas

### Características Adicionales:
- Soporte para más algoritmos post-cuánticos
- Integración con servicios de almacenamiento en la nube
- Soporte para hardware criptográfico (HSM, TPM)

### Mejoras de Usabilidad:
- Asistentes paso a paso para operaciones complejas
- Más retroalimentación visual durante operaciones largas

## Contacto

Para preguntas o sugerencias, por favor abre un issue en GitHub o contacta al autor directamente.
