<?php
/**
 * CyberShield - Report
 * Genera el informe tecnico (archivo:linea + riesgo + fix),
 * el informe ejecutivo para el dueno de la web y la version HTML
 * con la marca Orizon Studio.
 */

namespace Orizon\CyberShield;

class Report
{
    private const SEV_LABEL = [
        'critical' => 'CRITICA',
        'high' => 'ALTA',
        'medium' => 'MEDIA',
        'low' => 'BAJA',
        'info' => 'INFO',
    ];

    private const SEV_ICON = [
        'critical' => '🔴', 'high' => '🟠', 'medium' => '🟡',
        'low' => '🔵', 'info' => '⚪',
    ];

    public static function counts(array $findings): array
    {
        $c = array_fill_keys(array_keys(self::SEV_LABEL), 0);
        foreach ($findings as $f) $c[$f['severity']]++;
        return $c;
    }

    public static function globalStatus(array $findings): string
    {
        $c = self::counts($findings);
        if ($c['critical'] > 0) return 'AMENAZA DETECTADA';
        if ($c['high'] + $c['medium'] > 0) return 'ACCION REQUERIDA';
        return 'SEGURO';
    }

    // ---- Informe tecnico (consola) ----
    public static function text(array $findings, string $target): string
    {
        $c = self::counts($findings);
        $out = "\n════════════════════════════════════════════════════════════\n";
        $out .= "  INFORME TECNICO CYBERSHIELD  —  $target\n";
        $out .= "════════════════════════════════════════════════════════════\n";
        $out .= sprintf("  Hallazgos: 🔴%d  🟠%d  🟡%d  🔵%d  ⚪%d\n\n",
            $c['critical'], $c['high'], $c['medium'], $c['low'], $c['info']);

        if (!$findings) {
            $out .= "  Sin hallazgos. Codigo limpio segun las reglas activas.\n";
            return $out;
        }

        $byFile = [];
        foreach ($findings as $f) $byFile[$f['file']][] = $f;

        foreach ($byFile as $file => $items) {
            $short = strlen($file) > 70 ? '…' . substr($file, -68) : $file;
            $out .= "── $short ──\n";
            foreach ($items as $f) {
                $sev = self::SEV_ICON[$f['severity']] . ' ' . self::SEV_LABEL[$f['severity']];
                $loc = $f['line'] > 0 ? "L{$f['line']}" : 'archivo';
                $out .= "  $sev [$loc] {$f['rule']}\n";
                $out .= "     Codigo: {$f['code']}\n";
                $out .= "     Riesgo: {$f['risk']}\n";
                $out .= "     Fix:    {$f['fix']}\n\n";
            }
        }
        return $out;
    }

    // ---- Informe ejecutivo para el cliente ----
    public static function executive(array $findings, array $context = []): string
    {
        $status = self::globalStatus($findings);
        $c = self::counts($findings);
        $files = $context['files'] ?? 0;
        $extra = $context['extra'] ?? '';

        $out = "\n╔══════════════════════════════════════════════════════════╗\n";
        $out .= "║            INFORME EJECUTIVO — CYBERSHIELD AI            ║\n";
        $out .= "╚══════════════════════════════════════════════════════════╝\n\n";
        $out .= "🛡️  Estado del Sistema: {$status}\n\n";
        $out .= "📊 Resumen de Actividad: ";
        $out .= "Analizados {$files} elementos. ";
        $out .= "Hallados {$c['critical']} problemas criticos, {$c['high']} altos, {$c['medium']} medios y {$c['low']} menores.";
        if ($extra !== '') $out .= " $extra";
        $out .= "\n\n";

        if ($status === 'SEGURO') {
            $out .= "🔧 Accion Automatizada Aplicada: Ninguna necesaria. El sistema ha superado la auditoria.\n\n";
        } else {
            $top = array_slice($findings, 0, 3);
            $out .= "🔧 Accion Automatizada Aplicada: Auditoria completada. Prioridades:\n";
            foreach ($top as $f) {
                $loc = basename($f['file']) . ($f['line'] ? ":{$f['line']}" : '');
                $out .= "   • " . self::SEV_LABEL[$f['severity']] . " en {$loc} — {$f['risk']}\n";
            }
            $out .= "\n";
        }

        $out .= "💡 Recomendacion: ";
        if ($status === 'SEGURO') {
            $out .= "Repite la auditoria tras cada cambio de codigo y revisa los logs del servidor semanalmente.\n";
        } elseif ($c['critical'] > 0) {
            $out .= "Corrige los puntos CRITICOS hoy mismo: son explotables por cualquier atacante sin conocimientos avanzados.\n";
        } else {
            $out .= "Planifica la correccion de los puntos ALTOS esta semana. Ninguno es explotacion inmediata, pero acumulan riesgo.\n";
        }
        return $out;
    }

    // ---- Informe de logs (consola) ----
    public static function logReport(array $r): string
    {
        if (isset($r['error'])) return "ERROR: {$r['error']}\n";
        $out = "\n════════════════════════════════════════════════════════════\n";
        $out .= "  ANALISIS DE INCIDENTES — {$r['file']}\n";
        $out .= "════════════════════════════════════════════════════════════\n";
        $out .= "  Lineas analizadas: {$r['lines']}\n\n";

        $labels = [
            'sqli' => 'Inyeccion SQL', 'traversal' => 'Path Traversal',
            'rce' => 'Ejecucion remota', 'xss' => 'XSS',
            'scanner' => 'Sondeo de archivos', 'bruteforce' => 'Fuerza bruta',
            'bad_ua' => 'User-Agent de ataque',
        ];
        $out .= "  Intentos detectados por categoria:\n";
        foreach ($labels as $k => $lbl) {
            $n = $r['totals'][$k] ?? 0;
            if ($n > 0) $out .= sprintf("   • %-26s %d\n", $lbl, $n);
        }
        $out .= "\n  IPs sospechosas (top 15):\n";
        $shown = 0;
        foreach ($r['ips'] as $ip => $info) {
            if (!empty($info['attacks']) && $shown < 15) {
                $sev = self::SEV_ICON[$info['severity']] . ' ' . self::SEV_LABEL[$info['severity']];
                $out .= "   $sev  $ip  ({$info['count']} peticiones)\n";
                foreach ($info['attacks'] as $k => $n) {
                    $out .= "       - {$labels[$k]}: $n\n";
                }
                foreach (array_slice($info['samples'], 0, 2) as $s) {
                    $out .= "       » $s\n";
                }
                $shown++;
            }
        }
        if ($r['blocklist']) {
            $out .= "\n  🔧 ACCION RECOMENDADA — bloquear estas IPs:\n";
            $out .= "  ── .htaccess (Apache 2.4) ──\n";
            foreach (explode("\n", trim($r['htaccess'])) as $l) $out .= "  $l\n";
        }
        return $out;
    }

    // ---- Informe HTML (marca Orizon) ----
    public static function html(array $findings, string $target, string $outFile, array $context = []): void
    {
        $c = self::counts($findings);
        $status = self::globalStatus($findings);
        $statusColor = $status === 'SEGURO' ? '#22c55e' : ($status === 'ACCION REQUERIDA' ? '#f59e0b' : '#ef4444');
        $logo = dirname(__DIR__) . '/assets/logo.jpg';
        $logoData = is_file($logo) ? 'data:image/jpeg;base64,' . base64_encode(file_get_contents($logo)) : '';
        $date = date('d/m/Y H:i');
        $files = $context['files'] ?? 0;

        $rows = '';
        $bySev = ['critical' => '#ef4444', 'high' => '#f97316', 'medium' => '#eab308', 'low' => '#3b82f6', 'info' => '#94a3b8'];
        foreach ($findings as $f) {
            $sc = $bySev[$f['severity']];
            $loc = htmlspecialchars(basename(dirname($f['file'])) . '/' . basename($f['file']));
            $line = $f['line'] > 0 ? ':' . $f['line'] : '';
            $rows .= "<tr><td><span class='sev' style='background:$sc'>" . self::SEV_LABEL[$f['severity']] . "</span></td>"
                . "<td class='mono'>$loc$line</td><td class='mono'>" . htmlspecialchars(substr($f['code'], 0, 100)) . "</td>"
                . "<td>{$f['risk']}</td><td class='fix'>{$f['fix']}</td></tr>";
        }
        if (!$findings) $rows = "<tr><td colspan='5' class='ok'>Sin hallazgos — codigo limpio segun las reglas activas.</td></tr>";

        $html = <<<HTML
<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><title>CyberShield — Informe de Auditoria</title>
<style>
body{background:#0a0e1a;color:#e2e8f0;font-family:Segoe UI,Arial,sans-serif;margin:0;padding:30px}
.card{max-width:1200px;margin:auto;background:#0f172a;border:1px solid #1e293b;border-radius:16px;overflow:hidden}
.head{padding:28px 32px;display:flex;align-items:center;gap:20px;background:linear-gradient(135deg,#0a0e1a,#1e1b4b);border-bottom:1px solid #312e81}
.head img{width:72px;height:72px;border-radius:12px;object-fit:cover}
h1{margin:0;font-size:24px;letter-spacing:1px}
.sub{color:#818cf8;font-size:13px;letter-spacing:2px;text-transform:uppercase}
.meta{padding:16px 32px;color:#94a3b8;font-size:13px;border-bottom:1px solid #1e293b}
.status{margin:24px 32px;padding:18px 24px;border-radius:12px;background:{$statusColor}18;border:1px solid $statusColor;font-size:18px;font-weight:700}
.status small{display:block;font-weight:400;color:#94a3b8;font-size:13px;margin-top:4px}
table{width:calc(100% - 64px);margin:0 32px 32px;border-collapse:collapse;font-size:12.5px}
th{text-align:left;padding:10px;background:#1e293b;color:#94a3b8;font-size:11px;text-transform:uppercase}
td{padding:10px;border-bottom:1px solid #1e293b;vertical-align:top}
.sev{padding:3px 8px;border-radius:6px;color:#000;font-weight:700;font-size:10.5px;white-space:nowrap}
.mono{font-family:Consolas,monospace;color:#a5b4fc;font-size:11.5px}
.fix{color:#86efac;font-size:11.5px}
.ok{text-align:center;color:#22c55e;padding:30px;font-size:15px}
.foot{padding:16px 32px;color:#475569;font-size:11px;border-top:1px solid #1e293b;text-align:center}
</style></head><body><div class="card">
<div class="head"><img src="$logoData" alt="Orizon Studio"><div><h1>CyberShield AI — Informe de Auditoria de Seguridad</h1><div class="sub">Orizon Studio · Defensive Security</div></div></div>
<div class="meta">Objetivo: <b>$target</b> &nbsp;·&nbsp; Fecha: $date &nbsp;·&nbsp; Archivos analizados: $files &nbsp;·&nbsp; Hallazgos: {$c['critical']}🔴 {$c['high']}🟠 {$c['medium']}🟡 {$c['low']}🔵 {$c['info']}⚪</div>
<div class="status">🛡️ Estado del Sistema: $status<small>Generado por CyberShield AI — auditoria estatica OWASP (SQLi, XSS, CSRF, sanitizacion, control de acceso)</small></div>
<table><tr><th>Sev.</th><th>Archivo</th><th>Codigo</th><th>Riesgo</th><th>Fix recomendado</th></tr>$rows</table>
<div class="foot">Orizon Studio — CyberShield AI · Informe confidencial para uso interno</div>
</div></body></html>
HTML;
        file_put_contents($outFile, $html);
    }
}
