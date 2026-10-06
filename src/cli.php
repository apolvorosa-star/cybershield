<?php
/**
 * CyberShield AI — Orizon Studio
 * Auditor de seguridad para PHP/MySQL: codigo, logs y servidor.
 *
 * Uso:
 *   cybershield code <dir> [--profile orizon|wordpress|generic] [--html salida.html]
 *   cybershield log  <access.log> [--block blocklist.txt]
 *   cybershield sys  <docroot> [--ini php.ini]
 *   cybershield all  <dir> [--profile orizon] [--html salida.html]
 *   cybershield fix  <docroot> [--yes]
 */

namespace Orizon\CyberShield;

// ── Autoload: Composer si existe, si no, require manual ──
// 1) repo clonado con "composer install": <root>/vendor/autoload.php
// 2) instalado como dependencia:         vendor/orizon/cybershield/src -> vendor/autoload.php
$autoloadFound = false;
foreach ([
    dirname(__DIR__) . '/vendor/autoload.php',
    dirname(__DIR__, 3) . '/autoload.php',
] as $autoload) {
    if (is_file($autoload)) {
        require_once $autoload;
        $autoloadFound = true;
        break;
    }
}
if (!$autoloadFound) {
    foreach (glob(__DIR__ . '/*.php') ?: [] as $classFile) {
        if (basename($classFile) !== 'cli.php') require_once $classFile;
    }
}

// ── Banner ──────────────────────────────────────────────
$banner = <<<B
   ____      _               ____  _     _      _     _
  / ___|   _| |__   ___ _ _/ ___|| |__ (_) ___| | __| |
 | |  | | | | '_ \ / _ \ '__\___ \| '_ \| |/ _ \ |/ _` |
 | |__| |_| | |_) |  __/ |   ___) | | | | |  __/ | (_| |
  \____\__, |_.__/ \___|_|  |____/|_| |_|_|\___|_|\__,_|
       |___/  AI — Auditor de Ciberseguridad · Orizon Studio

B;
echo $banner;

// ── Parseo de argumentos ────────────────────────────────
$args = $_SERVER['argv'];
array_shift($args);
$mode = array_shift($args) ?? '';
$target = array_shift($args) ?? '';
$opts = [];
for ($i = 0; $i < count($args); $i++) {
    if (strpos($args[$i], '--') === 0) {
        $k = substr($args[$i], 2);
        $opts[$k] = ($i + 1 < count($args) && strpos($args[$i + 1], '--') !== 0) ? $args[++$i] : true;
    }
}

if (!$mode || !$target || in_array($mode, ['help', '-h', '--help'], true)) {
    echo "Uso:\n";
    echo "  cybershield code <dir>        Auditoria de codigo (OWASP: SQLi, XSS, CSRF, saneo, permisos)\n";
    echo "  cybershield log  <access.log> Analisis de incidentes + reglas de bloqueo de IP\n";
    echo "  cybershield sys  <docroot>    Auditoria del servidor (exposicion, instaladores, php.ini)\n";
    echo "  cybershield all  <dir>        Todo lo anterior + informe ejecutivo\n";
    echo "  cybershield fix  <docroot>    REPARA: .htaccess blindado + cuarentena + uploads protegidos\n\n";
    echo "Opciones:\n";
    echo "  --profile orizon|wordpress|generic   Stack del proyecto (defecto: orizon)\n";
    echo "  --html <fichero.html>                Informe HTML con marca Orizon\n";
    echo "  --block <fichero.txt>                En modo log: guarda las IPs a bloquear\n";
    echo "  --ini <php.ini>                      En modo sys: audita tambien php.ini\n";
    echo "  --yes                                En modo fix: aplica todo sin confirmar\n";
    exit($mode === 'help' || $mode === '-h' || $mode === '--help' ? 0 : 1);
}

$profileName = $opts['profile'] ?? 'orizon';
if ($profileName === 'wp') $profileName = 'wordpress';
$profileFile = dirname(__DIR__) . "/profiles/$profileName.php";
if (!is_file($profileFile)) {
    fwrite(STDERR, "Perfil '$profileName' no existe. Usa: orizon, wordpress, generic\n");
    exit(1);
}
$profile = require $profileFile;

$allFindings = [];

switch ($mode) {

    case 'code':
        if (!is_dir($target)) { fwrite(STDERR, "No es un directorio: $target\n"); exit(1); }
        $scanner = new TaintScanner($profile);
        $res = $scanner->scanDir($target);
        echo "Perfil: {$profile['name']} — {$res['files']} archivos PHP analizados\n";
        echo Report::text($res['findings'], $target);
        echo Report::executive($res['findings'], ['files' => $res['files']]);
        $allFindings = $res['findings'];
        break;

    case 'log':
        if (!is_file($target)) { fwrite(STDERR, "No es un fichero: $target\n"); exit(1); }
        $analyzer = new LogAnalyzer();
        $r = $analyzer->analyze($target);
        echo Report::logReport($r);
        if (isset($opts['block']) && !empty($r['blocklist'])) {
            file_put_contents($opts['block'], implode("\n", $r['blocklist']) . "\n");
            echo "\n  Lista de bloqueo guardada en {$opts['block']}\n";
        }
        exit(0);

    case 'fix':
        if (!is_dir($target)) { fwrite(STDERR, "No es un directorio: $target\n"); exit(1); }
        echo "  MODO REPARACION — se aplicaran correcciones reversibles.\n";
        echo "  Todo lo movido va a .cybershield-quarantine/ (recuperable).\n\n";
        $repair = new Repair($target, isset($opts['yes']));
        $actions = $repair->run();
        echo "\n  ── Resumen de acciones ──\n";
        if (!$actions) { echo "  Nada que reparar o todo rechazado.\n"; }
        foreach ($actions as $a) echo "  ✅ $a\n";
        echo "\n  Nota: los fallos de CODIGO (XSS/SQLi/CSRF) no se reparan\n";
        echo "  automaticamente — corrigelos uno a uno con el fix del informe.\n";
        exit(0);

    case 'sys':
        if (!is_dir($target)) { fwrite(STDERR, "No es un directorio: $target\n"); exit(1); }
        $audit = new SystemAudit();
        $findings = $audit->audit($target, $opts['ini'] ?? null);
        echo Report::text($findings, $target);
        echo Report::executive($findings, ['files' => 'todo el docroot']);
        $allFindings = $findings;
        break;

    case 'all':
        if (!is_dir($target)) { fwrite(STDERR, "No es un directorio: $target\n"); exit(1); }
        $scanner = new TaintScanner($profile);
        $res = $scanner->scanDir($target);
        $audit = new SystemAudit();
        $sys = $audit->audit($target, $opts['ini'] ?? null);
        $allFindings = array_merge($res['findings'], $sys);
        echo "Perfil: {$profile['name']} — {$res['files']} archivos PHP + auditoria de docroot\n";
        echo Report::text($allFindings, $target);
        echo Report::executive($allFindings, ['files' => $res['files']]);
        break;

    default:
        fwrite(STDERR, "Modo desconocido: $mode. Usa 'cybershield help'.\n");
        exit(1);
}

if (isset($opts['html'])) {
    Report::html($allFindings, $target, $opts['html'], ['files' => 'ver informe']);
    echo "\nInforme HTML guardado en: {$opts['html']}\n";
}
