# Guía de Contribución

¡Gracias por tu interés en contribuir a nuestro Sistema Criptográfico Avanzado! Esta guía te ayudará a configurar tu entorno de desarrollo y a entender nuestro proceso de contribución.

## Configuración del Entorno de Desarrollo

1. **Clonar el repositorio**:
   ```bash
   git clone https://github.com/tu-usuario/sistema-criptografico.git
   cd sistema-criptografico
   ```

2. **Crear un entorno virtual**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # En Windows: venv\Scripts\activate
   ```

3. **Instalar dependencias**:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # Dependencias adicionales para desarrollo
   ```

## Proceso de Contribución

1. **Crear una rama**: Crea una rama para tu contribución:
   ```bash
   git checkout -b feature/nombre-de-tu-caracteristica
   ```

2. **Realizar cambios**: Implementa tus cambios siguiendo nuestras convenciones de código.

3. **Ejecutar pruebas**: Asegúrate de que todas las pruebas pasen:
   ```bash
   python -m unittest discover tests
   ```

4. **Añadir pruebas**: Si has añadido una nueva característica, incluye pruebas para ella.

5. **Documentar cambios**: Actualiza la documentación si es necesario.

6. **Enviar un Pull Request**: Envía un PR con una descripción clara de tus cambios.

## Convenciones de Código

- Seguimos [PEP 8](https://www.python.org/dev/peps/pep-0008/) para el estilo de código Python.
- Usamos [Google Style Python Docstrings](https://sphinxcontrib-napoleon.readthedocs.io/en/latest/example_google.html) para la documentación.
- Todas las funciones y clases deben tener docstrings.
- El código debe estar bien comentado, especialmente las partes complejas.

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

## Áreas de Contribución

Estamos especialmente interesados en contribuciones en las siguientes áreas:

1. **Criptografía Post-cuántica**: Implementación y mejora de algoritmos post-cuánticos.
2. **Verificación de Revocación de Certificados**: Mejora de la funcionalidad CRL y OCSP.
3. **Rendimiento**: Optimizaciones para mejorar la velocidad y eficiencia.
4. **Interfaz de Usuario**: Mejoras en la usabilidad de la GUI y CLI.
5. **Documentación**: Mejora de la documentación y ejemplos.
6. **Pruebas**: Ampliación de la cobertura de pruebas.

## Preguntas

Si tienes alguna pregunta o necesitas ayuda, no dudes en abrir un issue o contactar a los mantenedores del proyecto.
