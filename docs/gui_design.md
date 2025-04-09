# Diseño de la Interfaz Gráfica de Usuario

## Objetivos

Crear una interfaz gráfica de usuario (GUI) para el sistema criptográfico que:

1. Sea intuitiva y fácil de usar para usuarios no técnicos
2. Proporcione acceso a todas las funcionalidades principales del sistema
3. Ofrezca retroalimentación visual clara sobre las operaciones
4. Funcione en múltiples plataformas (Windows, macOS, Linux)
5. Mantenga la seguridad y privacidad de los datos del usuario

## Tecnología Seleccionada

Para la implementación de la GUI, utilizaremos **PyQt6** por las siguientes razones:

- **Maduro y estable**: PyQt es una biblioteca madura con amplio soporte
- **Multiplataforma**: Funciona en Windows, macOS y Linux
- **Apariencia nativa**: Se adapta a la apariencia de cada sistema operativo
- **Potente**: Ofrece widgets avanzados y personalización
- **Documentación extensa**: Amplia documentación y comunidad activa

## Estructura de la Aplicación

La aplicación seguirá un diseño de múltiples pestañas para organizar las diferentes funcionalidades:

1. **Pestaña de Encriptación/Desencriptación**
   - Encriptación de archivos completos
   - Desencriptación de archivos
   - Opciones de algoritmo y método (clave o contraseña)

2. **Pestaña de Encriptación Selectiva de PDF**
   - Vista previa del PDF
   - Selección de páginas a encriptar
   - Opciones de encriptación

3. **Pestaña de Firmas Digitales**
   - Firmar archivos
   - Verificar firmas
   - Gestión de claves de firma

4. **Pestaña de Gestión de Claves**
   - Generación de claves
   - Importación/exportación de claves
   - Cambio de contraseña maestra

## Diseño de la Interfaz

### Ventana Principal

La ventana principal contendrá:
- Barra de menú (Archivo, Editar, Herramientas, Ayuda)
- Barra de herramientas con acciones comunes
- Área de pestañas para las diferentes funcionalidades
- Barra de estado para mostrar información y progreso

### Pestaña de Encriptación/Desencriptación

![Diseño de Pestaña de Encriptación](../assets/encryption_tab_design.png)

Componentes:
- Área de arrastrar y soltar archivos
- Botón para seleccionar archivos
- Selector de modo (encriptar/desencriptar)
- Selector de método (clave/contraseña)
- Selector de algoritmo (AES-GCM, ChaCha20-Poly1305)
- Selector de clave (si se usa el método de clave)
- Campo de contraseña (si se usa el método de contraseña)
- Botón de acción (Encriptar/Desencriptar)
- Área de resultados y registro

### Pestaña de Encriptación Selectiva de PDF

![Diseño de Pestaña de PDF](../assets/pdf_tab_design.png)

Componentes:
- Área de vista previa del PDF
- Panel de miniaturas de páginas
- Opciones de selección de páginas
- Selector de método (clave/contraseña)
- Selector de clave o campo de contraseña
- Botones de acción (Encriptar/Desencriptar)
- Indicador de páginas encriptadas

### Pestaña de Firmas Digitales

![Diseño de Pestaña de Firmas](../assets/signatures_tab_design.png)

Componentes:
- Área de selección de archivo
- Selector de par de claves
- Selector de algoritmo de firma
- Botones de acción (Firmar/Verificar)
- Área de resultados de verificación
- Detalles de la firma

### Pestaña de Gestión de Claves

![Diseño de Pestaña de Claves](../assets/keys_tab_design.png)

Componentes:
- Lista de claves disponibles
- Detalles de la clave seleccionada
- Botones de acción (Generar, Importar, Exportar, Eliminar)
- Opciones de cambio de contraseña maestra

## Flujos de Usuario

### Encriptar un Archivo

1. El usuario abre la pestaña de Encriptación/Desencriptación
2. Selecciona "Encriptar" como modo
3. Arrastra un archivo o hace clic en "Seleccionar archivo"
4. Elige el método de encriptación (clave o contraseña)
5. Si elige clave, selecciona una de las claves disponibles
6. Si elige contraseña, ingresa y confirma una contraseña
7. Hace clic en "Encriptar"
8. Se muestra una barra de progreso durante la encriptación
9. Al completarse, se muestra la ubicación del archivo encriptado

### Encriptar Secciones de un PDF

1. El usuario abre la pestaña de Encriptación Selectiva de PDF
2. Arrastra un PDF o hace clic en "Abrir PDF"
3. Se muestra una vista previa del PDF con miniaturas de las páginas
4. El usuario selecciona las páginas que desea encriptar
5. Elige el método de encriptación (clave o contraseña)
6. Hace clic en "Encriptar secciones"
7. Se muestra una barra de progreso durante la encriptación
8. Al completarse, se muestra una vista previa del PDF con las secciones encriptadas

## Consideraciones de Diseño

### Accesibilidad

- Soporte para lectores de pantalla
- Atajos de teclado para todas las acciones
- Tamaño de texto ajustable
- Alto contraste para usuarios con discapacidad visual

### Internacionalización

- Soporte para múltiples idiomas
- Estructura de archivos de traducción
- Manejo adecuado de diferentes conjuntos de caracteres

### Seguridad

- No almacenar contraseñas en memoria más tiempo del necesario
- Limpiar campos de contraseña después de su uso
- Opciones para borrar datos sensibles del historial
- Advertencias claras sobre operaciones potencialmente inseguras

## Plan de Implementación

1. **Fase 1**: Configuración del entorno PyQt y estructura básica
   - Crear la ventana principal y el sistema de pestañas
   - Implementar la navegación básica

2. **Fase 2**: Implementación de la pestaña de Encriptación/Desencriptación
   - Funcionalidad de arrastrar y soltar
   - Integración con el motor de encriptación existente

3. **Fase 3**: Implementación de la pestaña de Gestión de Claves
   - Visualización y gestión de claves
   - Integración con el sistema de almacenamiento de claves

4. **Fase 4**: Implementación de la pestaña de Firmas Digitales
   - Funcionalidad de firma y verificación
   - Visualización de resultados de verificación

5. **Fase 5**: Implementación de la pestaña de Encriptación Selectiva de PDF
   - Vista previa de PDF y selección de páginas
   - Integración con el manejador de secciones de PDF

6. **Fase 6**: Pulido y mejoras finales
   - Mejoras de usabilidad basadas en pruebas
   - Optimizaciones de rendimiento
   - Documentación completa
