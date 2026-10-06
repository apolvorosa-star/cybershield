<?php
/**
 * CyberShield - AgentBuilder
 *
 * Genera un UNICO archivo PHP autocontenido (cybershield-agent.php) que se
 * sube a un servidor remoto (por FTP o SSH), se ejecuta una vez y se borra.
 *
 * Incluye dentro: TaintScanner + SystemAudit + perfiles + runtime con token.
 * Asi la auditoria de codigo corre DENTRO del servidor real.
 */

namespace Orizon\CyberShield;

class AgentBuilder
{
    /** Devuelve el codigo fuente del agente con el token ya incrustado. */
    public static function code(string $token): string
    {
        $root = dirname(__DIR__);
        $code = "<?php\n"
            . "/**\n * CyberShield Agent — Orizon Studio\n"
            . " * Agente temporal: se sube al servidor, audita su propio docroot\n"
            . " * y se autodestruye. Requiere ?token= (HTTP) o argv[1] (CLI).\n"
            . " * GENERADO — no editar. Compilado desde src/.\n */\n\n";

        foreach (['TaintScanner', 'SystemAudit'] as $class) {
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
            . '$AGENT_TOKEN = ' . var_export($token, true) . ";\n\n"
            . self::runtime() . "\n}\n";

        return $code;
    }

    private static function runtime(): string
    {
        return <<<'PHP'
// ---- runtime del agente ----
$isCli = PHP_SAPI === 'cli';
$token   = $isCli ? ($argv[1] ?? '') : ($_GET['token'] ?? '');
$docroot = $isCli ? ($argv[2] ?? dirname(__FILE__)) : dirname(__FILE__);
$profile = $isCli ? ($argv[3] ?? 'orizon') : ($_GET['profile'] ?? 'orizon');

if (!is_string($token) || !hash_equals($AGENT_TOKEN, $token)) {
    if (!$isCli) http_response_code(403);
    exit('cybershield-agent: acceso denegado');
}
if (!is_dir($docroot)) {
    if (!$isCli) http_response_code(400);
    exit('cybershield-agent: docroot no existe');
}

$prof = $PROFILES[$profile] ?? $PROFILES['orizon'];
$scanner = new TaintScanner($prof);
$res  = $scanner->scanDir($docroot);
$sys  = (new SystemAudit())->audit($docroot);
$all  = array_merge($res['findings'], $sys);

$counts = array_fill_keys(['critical', 'high', 'medium', 'low', 'info'], 0);
foreach ($all as $f) $counts[$f['severity']]++;
$status = $counts['critical'] > 0 ? 'AMENAZA DETECTADA'
        : ($counts['high'] + $counts['medium'] > 0 ? 'ACCION REQUERIDA' : 'SEGURO');

if (!$isCli) header('Content-Type: application/json; charset=utf-8');
echo json_encode([
    'agent'   => 'cybershield',
    'docroot' => $docroot,
    'files'   => $res['files'],
    'counts'  => $counts,
    'status'  => $status,
    'findings'=> $all,
], JSON_UNESCAPED_UNICODE);

// Autodestruccion via HTTP (salvo &keep=1). Por CLI lo borra quien lo llamo.
if (!$isCli && !isset($_GET['keep'])) @unlink(__FILE__);
PHP;
    }
}
