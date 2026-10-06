<?php
/**
 * CyberShield - AgentBuilder
 *
 * Genera un UNICO archivo PHP autocontenido (cybershield-agent.php) que se
 * sube a un servidor remoto (por FTP o SSH), se ejecuta una vez y se borra.
 *
 * Incluye dentro: TaintScanner + SystemAudit + MalwareScanner + perfiles
 * + runtime efimero:
 *   - Caducidad dura: si el archivo lleva >5 min en el servidor, se borra solo
 *   - Auth HMAC: t(timestamp) + sig(hash_hmac(ts, secreto)) — sin replay
 *   - register_shutdown_function: autodestruccion garantizada tras responder
 *   - set_time_limit(120): margen para webs grandes
 */

namespace Orizon\CyberShield;

class AgentBuilder
{
    /** Devuelve el codigo fuente del agente con el secreto ya incrustado. */
    public static function code(string $secret): string
    {
        $root = dirname(__DIR__);
        $code = "<?php\n"
            . "/**\n * CyberShield Agent — Orizon Studio\n"
            . " * Agente EFIMERO: caduca a los 5 min y se autodestruye tras\n"
            . " * responder. Auth: ?t=<timestamp>&sig=<hmac-sha256(ts,secret)>\n"
            . " * GENERADO — no editar. Compilado desde src/.\n */\n\n";

        foreach (['TaintScanner', 'SystemAudit', 'MalwareScanner'] as $class) {
            $src = file_get_contents("$root/src/$class.php");
            $src = preg_replace('/^<\?php\s*/', '', $src);
            $src = str_replace("namespace Orizon\\CyberShield;\n", '', $src);
            $code .= "namespace Orizon\\CyberShield {\n$src\n}\n\n";
        }

        $profiles = [];
        foreach (glob("$root/profiles/*.php") ?: [] as $pf) {
            $profiles[basename($pf, '.php')] = require $pf;
        }

        $code .= "namespace Orizon\\CyberShield {\n\n"
            . '$PROFILES = ' . var_export($profiles, true) . ";\n"
            . '$AGENT_SECRET = ' . var_export($secret, true) . ";\n\n"
            . self::runtime() . "\n}\n";

        return $code;
    }

    private static function runtime(): string
    {
        return <<<'PHP'
// ---- ciclo de vida efimero ----
// 1. Caducidad dura: si lleva >5 min en el servidor, se borra y no ejecuta
if (time() - (int) @filemtime(__FILE__) > 300) {
    @unlink(__FILE__);
    exit('cybershield-agent: caducado');
}
// 3. Margen de ejecucion para docroots grandes
if (function_exists('set_time_limit')) @set_time_limit(120);

$isCli    = PHP_SAPI === 'cli';
$t        = $isCli ? ($argv[1] ?? '') : ($_GET['t'] ?? '');
$sig      = $isCli ? ($argv[2] ?? '') : ($_GET['sig'] ?? '');
$docroot  = $isCli ? ($argv[3] ?? dirname(__FILE__)) : dirname(__FILE__);
$profile  = $isCli ? ($argv[4] ?? 'orizon') : ($_GET['profile'] ?? 'orizon');
if (isset($_GET['keep']) || in_array('--keep', $argv ?? [], true)) $GLOBALS['CYSHIELD_KEEP'] = 1;

// Auth HMAC: firma del timestamp con el secreto embebido, ventana de 5 min
$ok = is_numeric($t) && abs(time() - (int) $t) <= 300
    && hash_equals(hash_hmac('sha256', (string) $t, $AGENT_SECRET), (string) $sig);
if (!$ok) {
    if (!$isCli) http_response_code(403);
    exit('cybershield-agent: acceso denegado');
}
if (!is_dir($docroot)) {
    if (!$isCli) http_response_code(400);
    exit('cybershield-agent: docroot no existe');
}

// 2. Autodestruccion garantizada SOLO tras auth correcta:
// una peticion denegada no debe borrar el agente (el TTL ya lo cubre)
register_shutdown_function(function () {
    if (empty($GLOBALS['CYSHIELD_KEEP'])) @unlink(__FILE__);
});

$prof = $PROFILES[$profile] ?? $PROFILES['orizon'];
$scanner = new TaintScanner($prof);
$res = $scanner->scanDir($docroot);
$sys = (new SystemAudit())->audit($docroot);
$mal = (new MalwareScanner())->scanDir($docroot);
$all = array_merge($res['findings'], $sys, $mal);
// El agente no se audita a si mismo (sus firmas dispararian sobre su propio codigo)
$all = array_values(array_filter($all, fn($f) => $f['file'] !== __FILE__));

$counts = array_fill_keys(['critical', 'high', 'medium', 'low', 'info'], 0);
foreach ($all as $f) $counts[$f['severity']]++;
$status = $counts['critical'] > 0 ? 'AMENAZA DETECTADA'
        : ($counts['high'] + $counts['medium'] > 0 ? 'ACCION REQUERIDA' : 'SEGURO');

if (!$isCli) header('Content-Type: application/json; charset=utf-8');
echo json_encode([
    'agent'    => 'cybershield',
    'docroot'  => $docroot,
    'files'    => $res['files'],
    'counts'   => $counts,
    'status'   => $status,
    'findings' => $all,
], JSON_UNESCAPED_UNICODE);
PHP;
    }
}
