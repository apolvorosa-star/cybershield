![CyberShield AI](assets/cover.jpg)

# 🛡️ CyberShield AI — by Orizon Studio

**El antivirus para webs PHP/MySQL que las agencias estaban esperando.**
Hecho en Valencia, para proteger webs de verdad.

[![Latest Version](https://img.shields.io/packagist/v/orizon/cybershield.svg)](https://packagist.org/packages/orizon/cybershield)
[![License](https://img.shields.io/badge/licencia-Apache%202.0-blue)](LICENSE)
[![PHP](https://img.shields.io/badge/php-%3E%3D8.0-777bb3)](https://packagist.org/packages/orizon/cybershield)
[![Hecho en](https://img.shields.io/badge/hecho%20en-Valencia%20%F0%9F%8D%8A-orange)](https://github.com/apolvorosa-star/cybershield)

> Auditoría OWASP (SQLi, XSS, CSRF) + Análisis de logs + Auditoría de servidor + Auditoría remota por URL + Reparación automática + Panel web + Informe PRO con marca Orizon.

## ¿Qué es esto?

No es otro escáner. CyberShield es lo que uso en Orizon Studio para auditar las webs de mis clientes antes de entregarlas, y ahora lo abro para que cualquiera que necesite proteger su web lo pueda usar.

**Si tienes una web en PHP, WordPress, Laravel o a medida, esto te dice en 30 segundos si te pueden hackear.**

Sin dependencias: corre con cualquier PHP 8+, en Windows, Linux o Mac.

## 🚀 Instalación

```bash
# Opción 1 — Como herramienta de tu proyecto
composer require --dev orizon/cybershield
php vendor/bin/cybershield all ./mi-web

# Opción 2 — Global, disponible en cualquier sitio
composer global require orizon/cybershield

# Opción 3 — Sin Composer: clonar y listo (cero dependencias)
git clone https://github.com/apolvorosa-star/cybershield.git
cd cybershield
php cybershield.php all ./mi-web        # Windows: cybershield.bat (menú interactivo)
```

## 🖥️ Panel web (app de escritorio)

```bash
cybershield ui                 # panel en http://127.0.0.1:8321
cybershield ui --host 0.0.0.0  # accesible desde el movil en tu Wi-Fi (⚠️ sin auth, solo LAN de confianza)
```

Panel local con marca Orizon:

- **Auditoría multi-web**: pega URLs, carpetas o logs (uno por línea) y lanza
  la cola. Resultados en vivo por objetivo con informe HTML descargable.
- **Fichas de webs**: guarda cada web con sus datos de servidor (URL + FTP o
  SSH + docroot remoto). Se guardan solo en tu PC (`informes/ui/webs.json`).
- **Agente remoto**: con FTP o SSH, CyberShield sube un `cybershield-agent.php`
  autocontenido y protegido por token, ejecuta la auditoría *dentro* del
  servidor real (código + docroot) y lo borra al terminar.
  - **FTP**: para hosting compartido — sube el agente al docroot y lo ejecuta
    vía `https://tuweb/agent.php?token=...`
  - **SSH**: `scp` a `/tmp` + ejecución por CLI — nada expuesto por HTTP
    (requiere llave SSH; OpenSSH no acepta contraseña por línea de comandos)
- **Alertas**: si una auditoría encuentra algo (no-SEGURO), queda registrado
  en el panel y puede enviarte **push al móvil con ntfy.sh** (gratis, sin
  cuenta: creas un tópico, te suscribes desde la app del móvil, listo).
- **PWA**: instalable en el móvil ("Añadir a pantalla de inicio"). Por HTTPS
  (túnel) o localhost se instala como app nativa.

### Ver tus webs desde el móvil

```bash
cybershield ui --host 0.0.0.0        # luego: http://IP-DE-TU-PC:8321 en el movil
```

O expón `http://127.0.0.1:8321` por tu túnel (cloudflared, ngrok…) para
acceder desde cualquier sitio con HTTPS y tener la PWA instalable.

## ⚡ Los 7 modos

```bash
cybershield code <dir>          → Revisa tu código: SQLi, XSS, CSRF, eval, secretos...
cybershield sys  <docroot>      → .env, .git, backups e instaladores expuestos
cybershield all  <dir>          → code + sys + informe ejecutivo
cybershield web  <https://...>  → Auditoria REMOTA: lo que un atacante vería desde fuera
cybershield log  <access.log>   → IPs atacantes + reglas de bloqueo listas
cybershield fix  <docroot>      → ¡REPARA! .htaccess blindado + cuarentena + uploads
cybershield ui                  → Panel web para auditar varias webs con un clic
```

| Modo | Qué hace |
|---|---|
| **Código** `code` | Análisis estático OWASP con rastreo de taint: inyección SQL, XSS, CSRF, sanitización, control de acceso, `eval`, includes dinámicos, `unserialize`, subidas, secretos hardcodeados |
| **Servidor** `sys` | `.env`, `.sql`, `.git`, `install.php` expuestos; carpetas de subida sin protección; `php.ini` inseguro |
| **Remoto** `web` | Comprueba por HTTP si `.env`, `.git`, `composer.json`, backups y `phpinfo.php` son accesibles desde Internet + cabeceras de seguridad (solo GETs pasivos, sin exploits) |
| **Incidentes** `log` | Access logs de Apache/Nginx: SQLi, traversal, RCE, fuerza bruta y scanners → gravedad + lista de IPs a bloquear (`--block`) |
| **Todo** `all` | `code` + `sys` + informe ejecutivo |
| **Reparar** `fix` | `.htaccess` blindado, cuarentena reversible en `.cybershield-quarantine/` y uploads sin ejecución PHP |
| **Panel** `ui` | App web local: cola de auditorías multi-web, fichas de servidor (FTP/SSH), agente remoto, alertas, historial |

## 🧠 Perfiles

El perfil define qué funciones se consideran saneo/CSRF/permisos en cada stack:

- `orizon` — OrizonCMS: `e()`, `orizon_can()`, PDO *(defecto)*
- `wordpress` — `$wpdb->prepare()`, `esc_*()`, nonces, `current_user_can()`
- `generic` — PHP puro: solo funciones nativas

```bash
php vendor/bin/cybershield code ./mi-proyecto --profile wordpress --html informe.html
```

## 📊 Salida

- **Informe técnico**: archivo:línea, riesgo en 2 frases, fix listo para copiar
- **Informe ejecutivo**: formato 🛡️ Estado / 📊 Resumen / 🔧 Acción / 💡 Recomendación
- **HTML** (`--html`): informe oscuro profesional con marca Orizon, listo para enviar al cliente
- **JSON** (`--json`): salida máquina para CI/CD o integraciones

## 🛡️ Lista blanca de cuarentena

El modo `fix` respeta exclusiones en `whitelist.txt` (copia `whitelist.dist.txt`
como plantilla) o `.cybershield-whitelist` dentro del docroot auditado.

## Seguridad y límites

Herramienta **exclusivamente defensiva**: análisis estático, logs, exposición de
archivos y comprobaciones HTTP pasivas. No genera exploits ni ejecuta ataques.
El escáner es la primera pasada — confirma los hallazgos antes de declarar una
vulnerabilidad. Audita solo sistemas tuyos o con permiso del propietario.

## 💼 ¿Para quién es?

- **Agencias web** que quieren entregar webs seguras y cobrar la auditoría
- **Freelancers** hartos de que les hackeen WordPress
- **Pymes** que quieren saber si su web es segura

## 💰 Visión Orizon Studio

Este es el paso 1. La visión es grande:

1. **Hoy:** herramienta gratuita y open-source para la comunidad
2. **Próximamente:** CyberShield PRO — auditoría diaria automática
3. **Futuro:** suite completa Orizon Security

> "Siempre mi ambición es de negocio y ganar dinero y crecer como los grandes" — Orizon Studio

## 🤝 ¿Quieres que te auditemos tu web?

Si no quieres instalar nada, en Orizon Studio auditamos tu web y te entregamos
el informe PRO con sello y plan de corrección.

**Contacto:** Orizon Studio — Valencia · Instagram: [@orizonstudio2026](https://instagram.com/orizonstudio2026)

## Licencia

[Apache 2.0](LICENSE) — úsalo, modifícalo, gana dinero con él. Solo mantén el crédito a Orizon Studio.

---

*Hecho con ❤️ y muchas noches sin dormir en Valencia. Si te sirve, deja una ⭐ en GitHub y nos ayudas a crecer.*
