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
- ⏳ Verificación de revocación de certificados (CRL, OCSP)
- ⏳ Soporte completo para criptografía post-cuántica

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

### Interfaz de Línea de Comandos

```bash
# Cifrar un archivo
python -m src.main encrypt --file documento.txt --output documento.encrypted --algorithm AES-GCM

# Descifrar un archivo
python -m src.main decrypt --file documento.encrypted --output documento.decrypted

# Firmar un archivo
python -m src.main sign --file documento.txt --output documento.sig

# Verificar una firma
python -m src.main verify --file documento.txt --signature documento.sig
```

### Interfaz Gráfica

```bash
# Iniciar la interfaz gráfica
python -m src.main --gui
```

## Estructura del Proyecto

```
src/
├── core/                  # Funcionalidad criptográfica principal
│   ├── encryption.py      # Motor de cifrado
│   ├── signatures.py      # Motor de firmas
│   ├── key_management.py  # Gestión de claves
│   ├── hybrid_crypto.py   # Criptografía híbrida
│   └── ...
├── file_handlers/         # Manejadores de archivos
├── ui/                    # Interfaces de usuario
│   ├── cli/               # Interfaz de línea de comandos
│   └── gui/               # Interfaz gráfica
└── utils/                 # Utilidades

tests/                     # Pruebas
├── test_encryption.py
├── test_signatures.py
└── ...

docs/                      # Documentación
```

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

## Contacto

Para preguntas o sugerencias, por favor abre un issue en GitHub o contacta al autor directamente.
