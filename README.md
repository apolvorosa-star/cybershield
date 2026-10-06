![CyberShield AI](assets/cover.jpg)

# CyberShield AI — Orizon Studio

Auditor de ciberseguridad **defensivo** para PHP/MySQL. Sin dependencias: corre con cualquier PHP 8+.

[![Latest Version](https://img.shields.io/packagist/v/orizon/cybershield.svg)](https://packagist.org/packages/orizon/cybershield)
[![License](https://img.shields.io/packagist/l/orizon/cybershield.svg)](LICENSE)
[![PHP](https://img.shields.io/packagist/php-v/orizon/cybershield.svg)](https://packagist.org/packages/orizon/cybershield)

![Orizon Studio](assets/logo.jpg)

## Instalación

```bash
composer require --dev orizon/cybershield
```

O de forma global, disponible en cualquier proyecto:

```bash
composer global require orizon/cybershield
```

También funciona **sin Composer**: clona el repo y ejecuta `php cybershield.php ...`
(o `cybershield.bat` en Windows/XAMPP) — la herramienta no tiene dependencias.

## Uso

```bash
php vendor/bin/cybershield all  ./mi-web
php vendor/bin/cybershield code ./mi-web --profile wordpress --html informe.html
php vendor/bin/cybershield log  /var/log/apache2/access.log --block bloquear.txt
php vendor/bin/cybershield sys  ./mi-web --ini /etc/php/8.3/apache2/php.ini
php vendor/bin/cybershield fix  ./mi-web --yes
php vendor/bin/cybershield web  https://mi-dominio.com
```

| Modo | Comando | Qué hace |
|---|---|---|
| **Código** | `code` | Análisis estático OWASP con rastreo de taint: inyección SQL, XSS, CSRF, sanitización, control de acceso, `eval`, includes dinámicos, `unserialize`, subidas, secretos hardcodeados |
| **Incidentes** | `log` | Procesa access logs de Apache/Nginx: detecta SQLi, traversal, RCE, fuerza bruta y scanners → gravedad + reglas de bloqueo de IP listas para `.htaccess` |
| **Servidor** | `sys` | `.env`, `.sql`, `.git`, `install.php` expuestos; carpetas de subida sin protección; `php.ini` inseguro |
| **Todo** | `all` | `code` + `sys` + informe ejecutivo |
| **Reparar** | `fix` | `.htaccess` blindado, cuarentena reversible (`.cybershield-quarantine/`) y uploads sin ejecución PHP |
| **Remoto** | `web` | Auditoría desde fuera contra una URL pública: `.env`, `.git`, `*.sql` y backups accesibles por HTTP + cabeceras de seguridad (solo GETs de lectura, sin exploits) |

## Perfiles

El perfil define qué funciones se consideran saneo/CSRF/permisos en cada stack:

- `orizon` — OrizonCMS: `e()`, `orizon_can()`, PDO, CSRF propio *(defecto)*
- `wordpress` — `$wpdb->prepare()`, `esc_*()`, nonces, `current_user_can()`
- `generic` — PHP puro: solo funciones nativas

## Salida

- **Informe técnico**: archivo:línea, riesgo en 2 frases, fix listo para copiar
- **Informe ejecutivo**: formato 🛡️ Estado / 📊 Resumen / 🔧 Acción / 💡 Recomendación
- **HTML** (`--html`): informe con marca Orizon para entregar al cliente

## Lista blanca de cuarentena

El modo `fix` respeta exclusiones definidas en:

1. `whitelist.txt` en la raíz del paquete (copia `whitelist.dist.txt` como plantilla)
2. `.cybershield-whitelist` en el docroot auditado

Formato: una ruta relativa por línea, comodines `*` admitidos, o
`C:/ruta/al/docroot|ruta/relativa` para limitarla a un proyecto.

## En Windows / XAMPP

`cybershield.bat` (incluido en el repo) resuelve el PHP de XAMPP solo y ofrece
un menú interactivo con doble clic. Ideal para auditorías programadas con el
Programador de tareas.

## Seguridad y límites

Herramienta **exclusivamente defensiva**: audita código estático, logs y
exposición de archivos. No genera exploits ni ejecuta ataques. El escáner es
la primera pasada — confirma los hallazgos a mano antes de declarar una
vulnerabilidad.

## Licencia

MIT © Orizon Studio

---

*Orizon Studio — herramientas defensivas. Nunca uses esta herramienta para atacar sistemas que no sean tuyos.*
