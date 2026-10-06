# 🛡️ CyberShield AI — by Orizon Studio

**El antivirus para webs PHP/MySQL que las agencias estaban esperando.**
Hecho en Valencia, para proteger webs de verdad.

> Auditoría OWASP (SQLi, XSS, CSRF) + Análisis de logs + Auditoría de servidor + Reparación automática + Informe PRO con marca Orizon.

[Estado](https://img.shields.io/badge/estado-experimento%20avanzado-yellow)
[Hecho en](https://img.shields.io/badge/hecho%20en-Valencia%20%F0%9F%8D%8A-orange)
[Orizon Studio](https://img.shields.io/badge/by-Orizon%20Studio-6366f1)

### ¿Qué es esto?

No es otro escáner. CyberShield es lo que uso en Orizon Studio para auditar las webs de mis clientes antes de entregarlas.

Lo tenía en mi PC en `G:/mis proyectos de programacion/CyberShield` y ahora lo abro para que cualquiera que necesite proteger su web lo pueda usar.

**Si tienes una web en PHP, WordPress, Laravel o a medida, esto te dice en 30 segundos si te pueden hackear.**

### 🚀 ¿Qué hace?

```
cybershield code <dir>   → Revisa tu código buscando inyecciones, XSS, CSRF...
cybershield log <access.log> → Lee tu log y te da la lista de IPs atacantes
cybershield sys <docroot>    → Revisa si dejaste phpMyAdmin, backups, .env expuestos
cybershield all <dir>    → Todo lo anterior + informe HTML ejecutivo
cybershield fix <docroot>    → ¡REPARA! Te pone .htaccess blindado y protege uploads
```

### 📊 Informe de ejemplo

Genera un informe HTML oscuro, profesional, listo para enviar a tu cliente:
`informe-ejemplo.html` → Estado: SEGURO / VULNERABLE, con archivo, línea, riesgo y fix recomendado.

Ideal para agencias: le pasas el PDF a tu cliente y justificas tu trabajo.

### ⚡ Instalación rápida

```bash
# Opción 1 - Clonar
git clone https://github.com/OrizonStudio/CyberShield.git
cd CyberShield
php cybershield.php all ./mi-web --html informe.html --profile orizon

# Opción 2 - Próximamente en Composer
composer require orizon/cybershield
```

### 🧠 Perfiles

- `orizon` → Mis webs a medida (por defecto)
- `wordpress` → WordPress / WooCommerce
- `generic` → Cualquier PHP

```bash
php cybershield.php code ./mi-proyecto --profile wordpress --html reporte.html
```

### 🛠️ Estructura

```
assets/       → Recursos
core/         → TaintScanner, LogAnalyzer, SystemAudit, Report, Repair
informes/     → Informes generados
profiles/     → Reglas por stack (orizon, wp, generic)
tools/        → Utilidades
cybershield.php → Motor principal
whitelist.txt → Falsos positivos que tú controlas
```

### 💼 ¿Para quién es?

- **Agencias web** que quieren entregar webs seguras y cobrar la auditoría.
- **Freelancers** que están hartos de que les hackeen WordPress.
- **Pymes** que quieren saber si su web de abogados, tienda, etc. es segura.

### 💰 Visión Orizon Studio

Este es el paso 1. La visión es grande:

1.  **Hoy:** Herramienta gratuita y open-source para la comunidad.
2.  **Próximamente:** CyberShield PRO — Auditoría diaria automática por 19€/mes. Tú duermes, yo vigilo tu web.
3.  **Futuro:** Suite completa Orizon Security.

> "Siempre mi ambición es de negocio y ganar dinero y crecer como los grandes" — Pedro, Orizon Studio

### 🤝 ¿Quieres que te audite tu web?

Si no quieres instalar nada, escríbeme. En Orizon Studio auditamos tu web por 49€ y te entregamos el informe PRO con sello y plan de corrección.

**Contacto:** Orizon Studio — Valencia
Instagram: @orizonstudio2026

---
Hecho con ❤️ y muchas noches sin dormir en Valencia. Si te sirve, deja una ⭐ en GitHub y me ayudas a crecer.

### Licencia

Apache 2.0 — Úsalo, modifícalo, gana dinero con él. Solo mantén el crédito a Orizon Studio.
