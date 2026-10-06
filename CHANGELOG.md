# Changelog

## 1.4.0 — 2026-10-06

- **Credenciales cifradas**: las contraseñas de las fichas de servidor se
  guardan con AES-256-GCM (`CredentialStore` + clave maestra local), nunca
  en texto plano. Los valores antiguos en claro siguen funcionando.
- **Agente efimero v2**: auth por firma HMAC SHA-256 (`t` + `sig`, ventana
  de 5 min), caducidad dura por TTL (si el archivo lleva >5 min en el
  servidor se autodestruye aunque nunca se llame) y borrado garantizado por
  `register_shutdown_function` solo tras auth correcta — una peticion
  denegada ya no destruye el agente. El agente tampoco se audita a si mismo.
- **`MalwareScanner`**: webshells (`eval(base64_decode)`, `assert`,
  `gzinflate`, `create_function`, shells conocidas WSO/b374k/r57/c99),
  `exec($_GET)` y llamadas a shell con input, PHP suelto en carpetas de
  subidas (uploads/subidas/media/files/tmp...), `.htaccess` malicioso
  (`auto_prepend_file`, handler PHP en imagenes, `-Indexes` quitado,
  reescritura a shells), `phpinfo()` y permisos `0777`. Integrado en
  `code`, `all`, el agente remoto y `run-saved`.
- **Nuevo comando `run-saved`**: audita todas las webs guardadas en el
  panel de una vez — pensado para cron / Programador de tareas. Descifra
  credenciales solo en memoria, registra alertas y devuelve exit code
  0 (todo seguro) / 1 (hallazgos) / 2 (errores).
- **Notificaciones multicanal**: ntfy.sh + bot de Telegram + webhook
  generico (Discord/Slack/n8n), configurables en Ajustes del panel.
- Los chequeos de carpetas de subidas/skip usan ahora rutas relativas al
  docroot (antes un docroot dentro de `Temp/` o `media/` daba falsos
  positivos).

## 1.3.0 — 2026-10-06

- **Agente remoto autocontenido** (`AgentBuilder` + `RemoteAudit`): un unico
  PHP con token que se sube al servidor, audita su propio docroot (codigo +
  sistema) y se autodestruye. Via SSH (scp+CLI, nada expuesto por HTTP) o
  FTP (subir → ejecutar por HTTPS con token → borrar).
- **Panel**: fichas de webs con credenciales de servidor (URL/FTP/SSH +
  docroot), checkbox para auditar guardadas junto a objetivos sueltos.
- **Alertas**: registro en el panel de todo hallazgo no-SEGURO + push
  opcional al movil via ntfy.sh.
- **Movil**: PWA instalable (manifest + service worker) y `--host 0.0.0.0`
  para acceder desde el telefono en la misma Wi-Fi.
- `--json` tambien en modo `log`.

## 1.2.0 — 2026-10-06

- Nuevo modo `ui`: panel web local (app) para auditar una o varias webs a la
  vez. `cybershield ui` abre el navegador con un dashboard Orizon, cola de
  auditorias en segundo plano e informes HTML descargables.
- Nueva opcion `--json <fichero>`: salida maquina de hallazgos para CI/CD.
- Fix en `web`: no reporta archivos sensibles cuando la respuesta es una
  pagina HTML disfrazada (soft-200 sin falsos positivos).
- `web` sigue el redirect inicial (HTTP→HTTPS) y avisa si falta TLS.
- Licencia del proyecto: Apache 2.0.

## 1.1.0 — 2026-10-06

- Nuevo modo `web <url>`: auditoria remota de superficie. Comprueba por HTTP
  si `.env`, `.git`, `composer.json`, backups SQL y similares son accesibles
  publicamente, y revisa las cabeceras de seguridad. Solo GETs pasivos.
- `sys`/`fix` ahora detectan de verdad las carpetas de subidas (iterador
  en modo SELF_FIRST).
- Los archivos ya en `.cybershield-quarantine/` no se reportan de nuevo
  como expuestos.

## 1.0.0 — 2026-10-06

Primera version publica como paquete Composer (`orizon/cybershield`).

- Analisis estatico OWASP con rastreo de taint: SQLi, XSS, CSRF, LFI, RCE,
  `eval`, `unserialize`, open redirect, uploads sin whitelist, secretos.
- Analisis de access logs (Apache/Nginx): clasificacion de ataques por IP
  y generacion de reglas de bloqueo para `.htaccess`.
- Auditoria de docroot: archivos sensibles expuestos (`.env`, `.sql`, `.git`),
  instaladores olvidados, carpetas de subida sin proteccion, `php.ini`.
- Modo `fix`: `.htaccess` blindado, cuarentena reversible y proteccion de
  carpetas de subida.
- Perfiles: `orizon`, `wordpress`, `generic`.
- Informe tecnico por consola, informe ejecutivo e informe HTML con marca
  Orizon Studio (`--html`).
