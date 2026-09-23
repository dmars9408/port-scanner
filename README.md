# port-scanner
Proyecto en Go para escaner de puertos de red


# PortScanner Go v1.0

PortScanner Go es una herramienta de escaneo de puertos escrita en Go, con interfaz TUI basada en BubbleTea y soporte para ejecución de comandos SSH en sistemas remotos. Es completamente portable, funciona en cualquier Windows 10/11 y no requiere instalación ni dependencias externas.

## Características

- Escaneo rápido de puertos TCP
- Detección de servicios y banners
- Interfaz TUI con navegación por teclado
- SSH integrado con autenticación por usuario y contraseña
- Comandos automáticos según el sistema remoto (Windows / Linux)
- Modo manual para ejecutar cualquier comando
- Tabla de resultados con colores
- Guardado de logs del escaneo
- Binario portable para Windows (.exe)

## Instalación

Descarga el archivo `portscanner.exe` y ejecútalo:

- Con doble click (se abrirá una ventana de consola)
- O desde PowerShell/CMD usando:

.\portscanner.exe


No requiere instalación, variables de entorno ni configuración adicional.

## Uso básico

1. Introduce el host o IP a escanear.
2. Introduce los puertos (ejemplo: `22,80,443` o `1-1024`).
3. Presiona **Enter** para iniciar el escaneo.

En la pantalla de resultados:

- **R** → nuevo escaneo
- **S** → guardar log del escaneo
- **Q** → salir del programa
- **I** → iniciar sesión SSH (si el host lo permite)

## SSH

Una vez conectado por SSH:

- Selecciona comandos automáticos por número.
- Usa modo manual para escribir cualquier comando.
- **B** → volver a la pantalla de resultados.
- **Q** → cerrar sesión SSH y volver a resultados.

## Guardar logs

En la pantalla de resultados, presiona:

**S**

El log se guarda como:

scan-log-YYYYMMDD-HHMMSS.txt


Incluye:
- Host escaneado
- Puertos abiertos/cerrados
- Servicios detectados
- Resumen final

## Compilación (solo para desarrolladores)

Para generar el binario optimizado:

go build -ldflags="-s -w" -o portscanner.exe


Esto produce un ejecutable portable para Windows.

## Licencia

MIT (opcional)
