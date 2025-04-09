# Guía de Uso de la Interfaz Gráfica

Esta guía explica cómo utilizar la interfaz gráfica de usuario (GUI) del sistema criptográfico.

## Requisitos Previos

- Tener instalado el sistema criptográfico
- Tener instalada la biblioteca PyQt6 (`pip install PyQt6`)
- Tener instaladas todas las dependencias del sistema

## Iniciar la GUI

Hay dos formas de iniciar la interfaz gráfica:

### Método 1: Usando el parámetro --gui

```
python -m src.main --gui
```

### Método 2: Ejecutando directamente el módulo de GUI

```
python -m src.ui.gui.run
```

## Estructura de la Interfaz

La interfaz gráfica está organizada en pestañas, cada una dedicada a una funcionalidad específica:

1. **Encriptación/Desencriptación**: Para encriptar y desencriptar archivos completos
2. **Encriptación Selectiva de PDF**: Para encriptar y desencriptar páginas específicas de archivos PDF
3. **Firmas Digitales**: Para firmar y verificar archivos
4. **Gestión de Claves**: Para gestionar claves criptográficas

## Pestaña de Encriptación/Desencriptación

Esta pestaña permite encriptar y desencriptar archivos completos.

### Encriptar un Archivo

1. Seleccione "Encriptar" como operación
2. Arrastre un archivo a la zona de arrastrar y soltar, o haga clic en "Seleccionar Archivo"
3. Elija el método de encriptación:
   - **Clave**: Utiliza una clave del gestor de claves
   - **Contraseña**: Utiliza una contraseña que usted proporciona
4. Si elige "Clave", seleccione una clave de la lista desplegable
5. Si elige "Contraseña", ingrese y confirme una contraseña
6. Seleccione el algoritmo de encriptación (AES-GCM o ChaCha20-Poly1305)
7. Opcionalmente, especifique una ruta de salida
8. Haga clic en "Encriptar"

### Desencriptar un Archivo

1. Seleccione "Desencriptar" como operación
2. Arrastre un archivo encriptado a la zona de arrastrar y soltar, o haga clic en "Seleccionar Archivo"
3. Elija el método de desencriptación:
   - **Clave**: Utiliza una clave del gestor de claves
   - **Contraseña**: Utiliza una contraseña que usted proporciona
4. Si elige "Clave", seleccione la clave correcta de la lista desplegable
5. Si elige "Contraseña", ingrese la contraseña
6. Opcionalmente, especifique una ruta de salida
7. Haga clic en "Desencriptar"

## Pestaña de Encriptación Selectiva de PDF

Esta pestaña permite encriptar y desencriptar páginas específicas de archivos PDF.

### Encriptar Páginas de un PDF

1. Haga clic en "Abrir PDF" y seleccione un archivo PDF
2. Se mostrarán miniaturas de las páginas del PDF
3. Seleccione las páginas que desea encriptar haciendo clic en ellas
   - También puede usar los botones "Seleccionar Todo", "Seleccionar Ninguna", "Seleccionar Pares" o "Seleccionar Impares"
4. Seleccione "Encriptar Páginas" como operación
5. Elija el método de encriptación (Clave o Contraseña)
6. Si elige "Clave", seleccione una clave de la lista desplegable
7. Si elige "Contraseña", ingrese y confirme una contraseña
8. Seleccione el algoritmo de encriptación
9. Opcionalmente, especifique una ruta de salida
10. Haga clic en "Encriptar Páginas Seleccionadas"

### Desencriptar Páginas de un PDF

1. Haga clic en "Abrir PDF" y seleccione un archivo PDF con páginas encriptadas
2. Se mostrarán miniaturas de las páginas del PDF
3. Seleccione "Desencriptar Páginas" como operación
4. Elija el método de desencriptación (Clave o Contraseña)
5. Si elige "Clave", seleccione la clave correcta de la lista desplegable
6. Si elige "Contraseña", ingrese la contraseña
7. Opcionalmente, especifique una ruta de salida
8. Haga clic en "Desencriptar Páginas Seleccionadas"

## Pestaña de Firmas Digitales

Esta pestaña permite firmar y verificar archivos digitalmente.

### Firmar un Archivo

1. Seleccione "Firmar" como operación
2. Haga clic en "Seleccionar Archivo" y elija el archivo que desea firmar
3. Seleccione el algoritmo de firma (RSA-PSS o RSA-PKCS1v15)
4. Seleccione la clave privada de la lista desplegable
5. Opcionalmente, especifique una ruta de salida para el archivo de firma
6. Haga clic en "Firmar"

### Verificar una Firma

1. Seleccione "Verificar" como operación
2. Haga clic en "Seleccionar Archivo" y elija el archivo original
3. Haga clic en "Examinar..." junto a "Archivo de firma" y seleccione el archivo de firma (.sig)
4. Seleccione el algoritmo de firma (debe ser el mismo que se utilizó para firmar)
5. Seleccione la clave pública correspondiente de la lista desplegable
6. Haga clic en "Verificar"
7. Se mostrará un mensaje indicando si la firma es válida o no

## Pestaña de Gestión de Claves

Esta pestaña permite gestionar claves criptográficas.

### Generar una Nueva Clave

1. Haga clic en "Generar Clave"
2. Seleccione el tipo de clave (Simétrica o Asimétrica)
3. Seleccione el algoritmo (AES o ChaCha20 para claves simétricas)
4. Seleccione el tamaño de la clave (128, 192 o 256 bits)
5. Opcionalmente, ingrese un ID para la clave (o deje en blanco para un ID generado automáticamente)
6. Haga clic en "OK"

### Importar una Clave

1. Haga clic en "Importar Clave"
2. Seleccione el archivo de clave (.key, .private o .public)
3. Opcionalmente, ingrese un ID para la clave
4. La clave se importará y aparecerá en la lista de claves disponibles

### Exportar una Clave

1. Seleccione una clave de la lista
2. Haga clic en "Exportar Clave"
3. Seleccione la ubicación y el nombre del archivo para guardar la clave
4. La clave se guardará en el archivo especificado

### Eliminar una Clave

1. Seleccione una clave de la lista
2. Haga clic en "Eliminar Clave"
3. Confirme la eliminación

### Inicializar el Almacenamiento de Claves

1. Haga clic en "Inicializar Almacenamiento"
2. Confirme la inicialización
3. Ingrese y confirme una contraseña maestra
4. El almacenamiento se inicializará con la contraseña proporcionada

### Cambiar la Contraseña Maestra

1. Haga clic en "Cambiar Contraseña Maestra"
2. Ingrese la contraseña maestra actual
3. Ingrese y confirme la nueva contraseña maestra
4. La contraseña maestra se cambiará

## Consejos y Trucos

- **Arrastrar y Soltar**: Puede arrastrar archivos directamente desde el explorador de archivos a la aplicación.
- **Selección de Páginas**: Haga clic en una página para seleccionarla, haga clic nuevamente para deseleccionarla.
- **Rutas de Salida**: Si no especifica una ruta de salida, se utilizará una ruta predeterminada basada en el archivo de entrada.
- **Verificación de Resultados**: Después de cada operación, se mostrará un resumen en el área de resultados.

## Solución de Problemas

### Error: "PyQt6 is not installed"

Este error indica que la biblioteca PyQt6 no está instalada. Instálela con:

```
pip install PyQt6
```

### Error: "pypdf is required for PDF operations"

Este error indica que la biblioteca pypdf no está instalada. Instálela con:

```
pip install pypdf
```

### Error: "Failed to load PDF"

Este error puede ocurrir por varias razones:
- El archivo PDF está dañado
- El archivo no es un PDF válido
- No tiene permisos para leer el archivo

Verifique que el archivo sea un PDF válido y que tenga permisos para leerlo.

### Error: "No keys available"

Este error indica que no hay claves disponibles en el gestor de claves. Vaya a la pestaña de Gestión de Claves para generar o importar claves.
