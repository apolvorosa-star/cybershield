# Changelog

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
