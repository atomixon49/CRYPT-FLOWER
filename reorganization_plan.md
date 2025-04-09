# Plan de Reorganización de Carpetas para CRYPT-FLOWER

## Problema Actual
El proyecto CRYPT-FLOWER tiene varias carpetas duplicadas con nombres como "src", "src (1)", "core", "core (1)", etc. Esto dificulta la navegación y el mantenimiento del código.

## Solución Propuesta
Reorganizar la estructura de carpetas para eliminar las duplicaciones y crear una estructura más clara y descriptiva.

## Nueva Estructura de Carpetas

```
crypt-flower/
├── docs/                      # Documentación del proyecto
├── scripts/                   # Scripts de utilidad
├── src/                       # Código fuente principal
│   ├── api/                   # API REST y endpoints
│   ├── core/                  # Funcionalidad criptográfica principal
│   │   ├── encryption/        # Algoritmos de encriptación
│   │   ├── signatures/        # Algoritmos de firma digital
│   │   ├── key_management/    # Gestión de claves
│   │   ├── post_quantum/      # Criptografía post-cuántica
│   │   ├── hsm/               # Soporte para HSM/TPM
│   │   ├── audit/             # Auditoría y logging
│   │   └── benchmark/         # Benchmarking y rendimiento
│   ├── file_handlers/         # Manejadores de archivos
│   ├── plugins/               # Plugins para sistemas externos
│   ├── ui/                    # Interfaces de usuario
│   │   ├── cli/               # Interfaz de línea de comandos
│   │   └── gui/               # Interfaz gráfica
│   └── utils/                 # Utilidades generales
└── tests/                     # Pruebas
    ├── unit/                  # Pruebas unitarias
    ├── integration/           # Pruebas de integración
    └── security/              # Pruebas de seguridad
```

## Plan de Migración

### Fase 1: Preparación
1. Crear la nueva estructura de carpetas
2. Actualizar el archivo requirements.txt (ya completado)

### Fase 2: Migración de Archivos
1. Mover los archivos de las carpetas duplicadas a la nueva estructura
2. Actualizar las importaciones en los archivos según sea necesario

### Fase 3: Limpieza
1. Eliminar las carpetas duplicadas vacías
2. Eliminar los archivos de requisitos por fases (requirements-phase*.txt)

### Fase 4: Verificación
1. Ejecutar pruebas para asegurar que todo funciona correctamente
2. Actualizar la documentación para reflejar la nueva estructura

## Notas Importantes
- Mantener la compatibilidad con el código existente
- Asegurar que todas las importaciones se actualicen correctamente
- Documentar los cambios para facilitar la transición
