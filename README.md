# PortScanner Go (v1.1)

Herramienta interactiva de auditoría de red, análisis de puertos y respuesta a incidentes basada en terminal (TUI). Diseñada en **Go** puro, es ligera, multiplataforma y sin dependencias externas del sistema.

Incluye un motor concurrente con control de congestión, *active probing* para reconocimiento de banners HTTP/SSH, evaluación heurística de riesgos y un cliente SSH interactivo adaptativo para gestión remota segura.

---

## Características Principales

* **Motor Concurrente Optimizado (Worker Pool):** Escanea rangos masivos (incluso 1-65535) sin colapsar descriptores de archivo ni disparar caídas por congestión SYN.
* **Banner Grabbing Activo:** Inspección de respuestas pasivas y sondas activas HTTP (`HEAD`) para extraer versiones de servidores (Apache, Nginx, OpenSSH, etc.).
* **Evaluación Heurística de Riesgos:** Clasificación contextual del riesgo (CRITICAL, HIGH, MEDIUM, LOW) según el servicio expuesto y posibles anomalías de latencia (detección de *tarpits* o *honeypots*).
* **Filtro de Puertos en Caliente:** Alterna dinámicamente la visualización entre el universo completo de puertos o únicamente los servicios abiertos.
* **Sesión SSH Segura y Adaptativa:**
  * Reconocimiento de huellas criptográficas y validación estricta contra `~/.ssh/known_hosts` para mitigar ataques Man-in-the-Middle (MitM).
  * Menús de remediación contextualizados para **Linux, Windows, Cisco IOS, JunOS, FortiOS y MikroTik RouterOS**.
  * Modo manual con shell interactivo para comandos ad-hoc.
* **Exportación de Auditoría:** Registro de resultados formateados con timestamps ISO 8601 a disco.

---

## Instalación y Binarios

No requiere instalación de runtimes (como Python o Node.js) ni utilidades de red adicionales en el sistema.

### Descarga directa
Descarga el binario correspondiente a tu sistema operativo desde la sección de **Releases** de este repositorio:

| Sistema Operativo | Arquitectura | Archivo ejecutable |
| :--- | :--- | :--- |
| **Windows** | x86_64 / amd64 | `portscanner-windows-amd64.exe` |
| **Linux** | x86_64 / amd64 | `portscanner-linux-amd64` |
| **macOS** | Apple Silicon (M1/M2/M3/M4) | `portscanner-darwin-arm64` |
| **macOS** | Intel | `portscanner-darwin-amd64` |

### Notas de ejecución en Linux y macOS

1. **Asignar permisos de ejecución:**
   Tanto en Linux como en macOS, el sistema requiere permisos explícitos tras descargar el archivo:
   ```bash
   chmod +x portscanner-linux-amd64   # En Linux
   chmod +x portscanner-darwin-arm64  # En macOS
   ```

2. **Permitir ejecución en macOS (Gatekeeper):**
   Al no contar con una firma digital comercial de Apple, macOS puede bloquear el binario con el mensaje *"no se puede abrir porque el desarrollador no se puede verificar"*. Para desbloquearlo, ejecuta en la terminal:
   ```bash
   xattr -d com.apple.quarantine portscanner-darwin-arm64
   ```

---

## Guía de Uso

1. **Host:** Introduce una dirección IP o nombre de dominio (ej. `192.168.1.1` o `scanme.nmap.org`).
2. **Puertos:** Define la lista o rango a auditar:
   * Puertos específicos: `22,80,443,8080`
   * Rangos: `1-1024`
   * Combinado: `21-25,80,443,3306,8000-8080`
3. Presiona **Enter** para ejecutar el escaneo.

### Atajos en Pantalla de Resultados

| Tecla | Acción |
| :---: | :--- |
| `O` | **Alternar filtro:** Conmuta entre ver todos los puertos o solo los abiertos. |
| `S` | **Guardar log:** Exporta los resultados actuales a un archivo de texto con timestamp. |
| `I` | **Sesión SSH:** Inicia la autenticación remota si se detectó el servicio expuesto. |
| `R` | **Reiniciar:** Regresa al formulario para un nuevo escaneo. |
| `↑` / `↓` | Desplazamiento de línea en la tabla de resultados. |
| `PgUp` / `PgDn` | Desplazamiento rápido de 10 líneas. |
| `Q` / `Esc` | Cerrar la aplicación. |

---

## Sesión SSH y Remediación

Si el objetivo tiene el puerto 22 abierto, puedes presionar `I` para iniciar sesión interactiva:

1. Ingresa usuario y contraseña cuando se solicite en pantalla.
2. El cliente validará la clave del host contra tu `known_hosts` local para prevenir suplantaciones (MitM).
3. El motor detectará el sistema operativo remoto y ofrecerá acciones directas:
   * **Linux/BSD:** Listado de sockets, reglas iptables/pf, detención de servicios.
   * **Cisco/Juniper/MikroTik:** Inspección de configuración, aislamiento de puertos y reglas de ACL.
   * **Opción `0`:** Cambia a **Modo Manual** para ejecutar comandos de consola personalizados.
4. Presiona `B` para regresar a los resultados del escaneo o `Q` para desconectar la sesión.

---

## Compilación desde Código Fuente

Requiere **Go 1.22** o superior.

```bash
# Clonar el repositorio
git clone [https://github.com/tu-usuario/port-scanner.git](https://github.com/tu-usuario/port-scanner.git)
cd port-scanner

# Compilar binario nativo
go build -ldflags="-s -w" -o portscanner ./cmd/scanner
```

---

## Licencia

Distribuido bajo la Licencia MIT. Consulta el archivo `LICENSE` para más información.
