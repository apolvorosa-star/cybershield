# Manual de uso — CyberShield (Orizon Studio)

Guía rápida de operación diaria. Para instalación y detalles técnicos, ver `README.md`.

## 1. Arrancar el panel

```bat
cybershield.bat  →  opción 7
```
o directamente:
```bash
cybershield ui
```

Abre el navegador en `http://127.0.0.1:8321`. La ventana de consola **debe quedar abierta** — si la cierras, el panel muere.

Acceso desde el móvil en tu misma Wi-Fi:
```bash
cybershield ui --host 0.0.0.0
# en el movil: http://IP-DEL-PC:8321   (la IP la ves con: ipconfig)
```

## 2. Guardar una web (ficha de servidor)

En el panel → **Guardar web**:

| Campo | Qué va | Ejemplo |
|---|---|---|
| Nombre | Etiqueta libre | `orizonstudio` |
| URL pública | La web tal cual se ve desde internet | `https://www.orizonstudio.cloud` |
| Acceso | `url` (solo superficie) · `ftp` · `ssh` | `ftp` |
| Host | Servidor FTP/SSH | `ftp.orizonstudio.cloud` |
| Puerto | 21 (FTP) o 22 (SSH) | `21` |
| Usuario | Usuario FTP/SSH | `19510521@aruba.it` |
| Contraseña | Solo para FTP | se guarda cifrada AES-256-GCM |
| Llave SSH | Solo para SSH: ruta a tu llave privada | vacío si usas FTP |
| Docroot remoto | Carpeta remota donde está la web | `/` en Aruba (FTP ya aterriza dentro) |

**Sin acceso al servidor**: deja acceso `url` y solo rellena nombre + URL. Audita lo que ve un atacante desde fuera.

## 3. Auditar

- **Una o varias webs sueltas**: pégalas en "Nueva auditoría", una por línea (URLs, carpetas locales o `.log`), marca "Informe HTML" y pulsa **Auditar**.
- **Webs guardadas**: marca el checkbox de cada ficha → Auditar.
- Los resultados aparecen en vivo: 🛡️ SEGURO / ⚠️ ACCIÓN REQUERIDA / 🚨 AMENAZA DETECTADA, con conteo por gravedad y enlace al informe.

### Qué pasa con FTP/SSH (agente efímero)

1. Se genera un agente PHP único con secreto aleatorio
2. Se sube al servidor (FTP al docroot / SSH a `/tmp`)
3. Se ejecuta firmado con HMAC (ventana de 5 min)
4. Audita código + sistema + malware desde dentro y devuelve JSON
5. **Se autodestruye**; si falla la comunicación, su TTL de 5 min lo borra igualmente

## 4. Avisos al móvil

### ntfy.sh (recomendado, gratis, sin cuenta)

1. Móvil: instala la app **ntfy**
2. Inventa un tópico largo y raro: `cybershield-orizon-x7k9q2`
3. App → `+` → escribe **solo el nombre** del tópico (sin `https://`)
   - "Usar otro servidor" → **NO**
   - "Entrega instantánea en modo Doze" → **SÍ**
4. Panel → Ajustes → TÓPICO NTFY.SH: `https://ntfy.sh/<tu-topico>` → Guardar

### Telegram (opcional)

1. Telegram → habla con `@BotFather` → `/newbot` → copia el **token** → campo TELEGRAM BOT TOKEN
2. Abre tu bot, mándale "hola"
3. Visita `https://api.telegram.org/bot<TU_TOKEN>/getUpdates` → el número de `"chat":{"id":NNN}` → campo TELEGRAM CHAT_ID
4. El chat_id NO es tu número de teléfono

### Webhook (opcional)

URL que recibirá POST JSON `{source, target, status, counts}` — para Discord, Slack, n8n, etc.

## 5. Vigilancia automática (auditoría programada)

`run-saved` audita **todas** las fichas guardadas y dispara alertas. Prográmalo:

**Programador de tareas de Windows** (diario, p.ej. 08:00):
```
Programa:  php
Argumentos: "G:\mis proyectos de programacion\CyberShield\cybershield.php" run-saved
Iniciar en: G:\mis proyectos de programacion\CyberShield
```

Exit codes: `0` todo seguro · `1` hallazgos (alerta enviada) · `2` error de conexión.

## 6. Datos y privacidad

Todo vive solo en tu PC, en `informes/ui/`:

| Fichero | Contenido |
|---|---|
| `webs.json` | Fichas de webs — `pass` cifrado, **no lo subas a ningún sitio** |
| `.master-key` | Clave de cifrado local — si la pierdes, las contraseñas guardadas no se recuperan (habrá que reescribirlas) |
| `settings.json` | Config de notificaciones |
| `alerts.json` | Historial de alertas (botón "Limpiar alertas" en el panel) |
| `job-*` | Auditorías lanzadas desde el panel: `status.json`, `tN.html` informes |

## 7. Problemas frecuentes

| Síntoma | Causa | Solución |
|---|---|---|
| El panel no abre | La consola se cerró | El `php -S` debe quedar corriendo; reabre `cybershield ui` |
| FTP: "el docroot no mapea a la URL" (404) | La carpeta FTP no es la raíz web | Mira en FileZilla dónde está el `index.php` y pon esa ruta |
| FTP: 0 archivos auditados | Docroot apunta a nivel superior | Pon `/` o la subcarpeta concreta |
| SSH: "password no soportado" | OpenSSH de CLI no acepta contraseña | Configura llave SSH (`ssh-keygen` + copiar `id_*.pub` al servidor) |
| El agente "desaparece" sin resultado | El antivirus del hosting lo cuarentena | Revisar logs del hosting; avisar para codificar firmas |
| `run-saved` no encuentra webs | Las fichas se crearon en otro jobsRoot | Las fichas viven en `informes/ui/webs.json` del proyecto |

## 8. Reparar con IA

En cualquier informe del panel verás el botón **🔧 Reparar con IA** junto a los
hallazgos críticos/altos que apuntan a ficheros `.php`.

Flujo (siempre con revisión humana — la IA propone, tú decides):

1. **Reparar** → el panel descarga el fichero afectado del servidor (por FTP,
   o del disco si el objetivo era local) y te muestra el código actual.
2. **Prompt** → despliega «📋 Prompt para IA» y cópialo en tu LLM favorito
   (ChatGPT, Devin, Claude…). Pega el código corregido en el textarea.
   - **IA local gratis (recomendado)**: instala Ollama (ollama.com) o
     LM Studio, descarga un modelo de código (`ollama pull qwen2.5-coder`),
     y en **Ajustes → IA: proveedor** elige el preset — sin API key, tu
     código nunca sale de tu PC.
   - **IA en la nube**: presets OpenAI / DeepSeek / Groq, pon tu API key.
   - El preset autorrellena endpoint y modelo.
3. **Revisa** el código propuesto — no apliques a ciegas.
4. **✅ Aplicar al servidor** → antes de escribir:
   - valida la sintaxis con `php -l` (si no compila, no toca nada),
   - mueve el original a `_cs_cuarentena/` en el servidor,
   - sube el fichero corregido.
5. Re-audita la web para confirmar que el hallazgo desapareció.

Protecciones incorporadas:

- Solo se reparan rutas que resuelven **dentro del docroot** auditado
  (sin `..`, sin escritura arbitraria).
- El `.htaccess` de `_cs_cuarentena/` deniega el acceso web a los backups.
- En local el backup queda como `fichero.php.bak-AAAAMMDD-HHMMSS`.

> FTP va en claro — para producción seria usa SSH cuando el hosting lo permita.
