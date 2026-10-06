<?php
/**
 * CyberShield - TaintScanner
 *
 * Analisis estatico de codigo PHP con rastreo de "taint":
 * las variables que reciben datos de $_GET/$_POST/$_REQUEST/$_COOKIE/
 * $_FILES/php://input quedan marcadas como contaminadas y se persiguen
 * hasta los sumideros peligrosos (SQL, salida HTML, exec, include...).
 *
 * El perfil (profiles/*.php) define que funciones sanea, verifican
 * CSRF y controlan acceso en cada stack (OrizonCMS, WordPress, generico).
 */

namespace Orizon\CyberShield;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

class TaintScanner
{
    private array $profile;
    private array $findings = [];
    private int $filesScanned = 0;

    private const SUPERGLOBALS = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES', '$_SERVER', '$_ENV'];
    private const SEVERITY_ORDER = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4];

    public function __construct(array $profile)
    {
        $this->profile = $profile;
    }

    public function scanDir(string $dir): array
    {
        $this->findings = [];
        $this->filesScanned = 0;
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
        $dir = rtrim($dir, '\\/');
        foreach ($it as $f) {
            if ($f->isFile() && strtolower($f->getExtension()) === 'php') {
                $path = $f->getPathname();
                $rel = '/' . str_replace('\\', '/', substr($path, strlen($dir) + 1)) . '/';
                if (preg_match('#/(vendor|node_modules|\.git|dist|bin|assets)/#i', $rel)) continue;
                $this->scanFile($path);
                $this->filesScanned++;
            }
        }
        usort($this->findings, fn($a, $b) => self::SEVERITY_ORDER[$a['severity']] <=> self::SEVERITY_ORDER[$b['severity']]);
        return ['findings' => $this->findings, 'files' => $this->filesScanned];
    }

    private function add(string $rule, string $severity, string $file, int $line, string $code, string $risk, string $fix): void
    {
        $code = trim($code);
        if (mb_strlen($code) > 140) $code = mb_substr($code, 0, 140) . '…';
        foreach ($this->findings as $f) {
            if ($f['rule'] === $rule && $f['file'] === $file && $f['line'] === $line) return;
        }
        $this->findings[] = compact('rule', 'severity', 'file', 'line', 'code', 'risk', 'fix');
    }

    private function isTaintedExpr(string $expr, array $tainted): bool
    {
        foreach (self::SUPERGLOBALS as $sg) {
            if (strpos($expr, $sg) !== false && $sg !== '$_SERVER') return true;
        }
        if (strpos($expr, 'php://input') !== false) return true;
        foreach ($tainted as $var) {
            if (preg_match('/\$' . preg_quote($var, '/') . '\b/', $expr)) return true;
        }
        return false;
    }

    private function isSanitized(string $expr): bool
    {
        foreach ($this->profile['sanitizers'] as $fn) {
            if (preg_match('/\b' . preg_quote($fn, '/') . '\s*\(/i', $expr)) return true;
        }
        if (preg_match('/\((int|float|bool)\)\s*\(?\s*\$/', $expr)) return true;
        return false;
    }

    public function scanFile(string $file): void
    {
        $lines = @file($file, FILE_IGNORE_NEW_LINES);
        if ($lines === false) return;

        $rel = $file;
        $tainted = [];
        $hasPost = false; $hasCsrf = false; $hasAuth = false;
        $hasMutation = false; $hasUpload = false; $hasExtWhitelist = false;
        $hasPrepare = false;

        // ---- Pasada 1: estado del archivo + propagacion de taint ----
        foreach ($lines as $i => $line) {
            $code = preg_replace('~(//|#|/\*).*$~', '', $line) ?? $line;

            if (strpos($code, '$_POST') !== false || strpos($code, '$_REQUEST') !== false) $hasPost = true;
            if (strpos($code, '$_FILES') !== false) $hasUpload = true;
            foreach ($this->profile['nonce_fns'] as $fn) {
                if (stripos($code, $fn) !== false) { $hasCsrf = true; break; }
            }
            foreach ($this->profile['capability_fns'] as $fn) {
                if (stripos($code, $fn) !== false) { $hasAuth = true; break; }
            }
            if (preg_match('/\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+TABLE|mail\s*\(|wp_mail)\b/i', $code)) $hasMutation = true;
            if (preg_match('/(prepare|->prepare)\s*\(/', $code)) $hasPrepare = true;
            if (preg_match('/\b(in_array|pathinfo|mime_content_type|finfo_file)\b/', $code)) $hasExtWhitelist = true;

            // Asignaciones: $x = expr;
            if (preg_match_all('/\$([a-zA-Z_]\w*)\s*=\s*([^;]+);/', $code, $m, PREG_SET_ORDER)) {
                foreach ($m as $as) {
                    $var = $as[1]; $rhs = $as[2];
                    $key = array_search($var, $tainted, true);
                    if ($this->isTaintedExpr($rhs, $tainted) && !$this->isSanitized($rhs)) {
                        if ($key === false) $tainted[] = $var;
                    } else {
                        if ($key !== false) unset($tainted[$key]);
                    }
                }
            }
        }
        $tainted = array_values($tainted);

        // ---- Pasada 2: sumideros ----
        foreach ($lines as $i => $line) {
            $n = $i + 1;
            $code = preg_replace('~(//|#|/\*).*$~', '', $line) ?? $line;
            if (trim($code) === '') continue;

            // 1. SQL Injection
            if (preg_match('/(->query|->exec|->raw|mysqli_query|mysql_query|->execQuery|->queryRaw)\s*\((.*)$/i', $code, $m)) {
                if (strpos($code, 'prepare') === false) {
                    $arg = $m[2];
                    if ($this->isTaintedExpr($arg, $tainted)) {
                        $this->add('sqli', 'critical', $rel, $n, $line,
                            'Consulta SQL construida con datos del visitante sin preparar. Un atacante puede leer o borrar toda la base de datos.',
                            'Usa consultas preparadas: $stmt = $db->prepare("SELECT ... WHERE id=?"); $stmt->execute([$id]);');
                    } elseif (preg_match('/\$[a-zA-Z_]\w*/', $arg) && strpos($arg, "'") === false && strpos($arg, '"') === false) {
                        // variable sola -> puede traer SQL ya construido
                        $this->add('sqli-review', 'medium', $rel, $n, $line,
                            'La consulta ejecuta una variable SQL. Si esa cadena se construyo con datos del usuario en otra parte, es inyectable.',
                            'Verifica el origen de la variable o usa prepare() directamente aqui.');
                    } elseif (preg_match('/["\'].*\$.*["\']|\.\s*\$|\$\s*\./', $arg)) {
                        $this->add('sqli', 'high', $rel, $n, $line,
                            'Consulta SQL con variables interpoladas o concatenadas. Si alguna contiene datos de usuario, es inyeccion SQL.',
                            'Usa $db->prepare() con placeholders ? o :nombre.');
                    }
                }
            }

            // 2. XSS - salida sin escape
            if (preg_match('/\b(echo|print)\b\s+(.+)|<\?=\s*(.+)/', $code, $m)) {
                $out = $m[2] !== '' ? $m[2] : ($m[3] ?? '');
                if ($out !== '' && !$this->isSanitized($out)) {
                    if ($this->isTaintedExpr($out, $tainted)) {
                        // Alto si el dato contaminado se imprime directamente
                        // (echo $v, <?= $v, $v . "x"); medio si va dentro de
                        // una expresion (ternario, comparacion, funcion...).
                        $direct = (bool) preg_match('/^\s*\$_/', $out)
                               || ((bool) preg_match('/^\s*\$|\.\s*\$|\$\s*\./', $out)
                                   && !preg_match('/===|!==|==|\?\s*[\'"]|->|::|\(/', $out));
                        $this->add('xss', $direct ? 'high' : 'medium', $rel, $n, $line,
                            'Se imprime un dato influenciado por el visitante sin escape. Permite inyectar JavaScript que robe sesiones o suplante al usuario.',
                            'Escapa la salida: echo e($var) / htmlspecialchars($var) / esc_html($var)');
                    } elseif (preg_match('/\$[a-zA-Z_]\w*/', $out) && !preg_match('/\b(json_encode|serialize)\b/', $out)) {
                        $this->add('xss-review', 'low', $rel, $n, $line,
                            'Variable impresa sin escape visible. Si su valor viene de base de datos o usuario, puede llevar HTML/JS.',
                            'Envuelve con e() o htmlspecialchars() salvo que ya venga escapada.');
                    }
                }
            }

            // 3. Ejecucion de comandos
            if (preg_match('/(?<![->:\w])(exec|shell_exec|system|passthru|popen|proc_open)\s*\((.*)/i', $code, $m)) {
                $arg = $m[2];
                if ($this->isTaintedExpr($arg, $tainted)) {
                    $this->add('rce', 'critical', $rel, $n, $line,
                        'Datos del visitante llegan a un comando del sistema. Un atacante puede ejecutar cualquier programa en el servidor.',
                        'Usa escapeshellarg() como minimo; mejor, evita shell y usa librerias PHP.');
                } elseif (preg_match('/\$[a-zA-Z_]\w*/', $arg)) {
                    $this->add('rce-review', 'medium', $rel, $n, $line,
                        'Comando del sistema con variable. Aceptable solo si la variable es interna y fija.',
                        'Verifica el origen; aplica escapeshellarg() si hay cualquier dato variable.');
                }
            }

            // 4. eval / assert
            if (preg_match('/\b(eval|assert)\s*\((.*)/', $code, $m)) {
                $this->add('eval', 'critical', $rel, $n, $line,
                    'eval()/assert() ejecutan texto como codigo PHP. Es la puerta trasera favorita de los hackers.',
                    'Elimina eval(). Reescribe con una estructura de datos o una funcion concreta.');
            }

            // 5. Inclusion dinamica
            if (preg_match('/\b(include|include_once|require|require_once)\b\s*\(?\s*([^;]*\$[^;]*)\s*;?/i', $code, $m)) {
                $arg = $m[2];
                $sev = $this->isTaintedExpr($arg, $tainted) ? 'critical' : 'low';
                $this->add('lfi', $sev, $rel, $n, $line,
                    'Ruta de include/require construida con variable. Permite cargar archivos arbitrarios o codigo remoto.',
                    'Usa una lista blanca: $f = ["a"=>"a.php"][$_GET["p"]] ?? "home.php"; include $f;');
            }

            // 6. unserialize
            if (preg_match('/\bunserialize\s*\((.*)/', $code, $m) && preg_match('/\$/', $m[1])) {
                $this->add('deser', 'high', $rel, $n, $line,
                    'unserialize() sobre datos variables permite inyeccion de objetos y ejecucion remota si hay clases "magicas".',
                    'Usa json_decode(). Si no puedes, al menos unserialize($d, ["allowed_classes"=>false]).');
            }

            // 7. Operaciones de archivo con taint
            if (preg_match('/\b(file_get_contents|file_put_contents|readfile|fopen|unlink|rmdir|copy|rename|file_exists)\s*\((.*)/', $code, $m)) {
                $arg = $m[2];
                if ($this->isTaintedExpr($arg, $tainted)) {
                    $this->add('traversal', 'high', $rel, $n, $line,
                        'Operacion de archivo con ruta influenciada por el usuario. Permite leer/borrar archivos fuera del directorio previsto (../../).',
                        'Valida con basename() + directorio fijo, o realpath() comprobando el prefijo permitido.');
                }
            }

            // 8. Open redirect
            if (preg_match('/header\s*\(\s*[\'"]Location:\s*([^\'"]*)[\'"]\s*(\.\s*(.+))?/i', $code, $m)) {
                $base = $m[1] ?? '';
                $arg = $m[3] ?? $code;
                $isExternal = (bool) preg_match('#^https?://#i', $base);
                if ($this->isTaintedExpr($arg, $tainted)) {
                    $this->add('redirect', $isExternal ? 'medium' : 'low', $rel, $n, $line,
                        'Redireccion a una URL dada por el usuario. Usable para phishing ("parece tu web pero es otra").',
                        'Valida contra lista blanca de rutas internas o parse_url() con host propio.');
                }
            }

            // 9. extract() sobre entrada
            if (preg_match('/\bextract\s*\((\s*\$_(GET|POST|REQUEST|COOKIE))/i', $code)) {
                $this->add('extract', 'high', $rel, $n, $line,
                    'extract() sobre datos del usuario crea variables arbitrarias y puede sobrescribir las internas.',
                    'Elimina extract(); asigna los campos necesarios uno a uno.');
            }

            // 10. preg_replace /e
            if (preg_match('/preg_replace\s*\(\s*[\'"][^\'"]*[a-zA-Z]*e[a-zA-Z]*[\'"]/', $code)) {
                $this->add('preg-e', 'high', $rel, $n, $line,
                    'Modificador /e en preg_replace ejecuta el reemplazo como codigo PHP.',
                    'Usa preg_replace_callback() en su lugar.');
            }

            // 11. parse_str sobre entrada
            if (preg_match('/\b(parse_str|mb_parse_str)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i', $code)) {
                $this->add('parse-str', 'medium', $rel, $n, $line,
                    'parse_str() sobre la URL crea variables masivamente; puede sobrescribir valores internos.',
                    'Usa el segundo argumento: parse_str($q, $out); y lee solo $out.');
            }

            // 12. Secretos en codigo
            if (preg_match('/(password|passwd|api_key|apikey|secret|private_key|access_token)\s*[\'"]?\s*[=:]\s*[\'"]([^\'"]{8,})[\'"]/i', $code, $m)) {
                $val = strtolower($m[2]);
                if (!preg_match('/(xxx|your_|change|example|ejemplo|placeholder|\*\*\*|TODO)/i', $m[2])) {
                    $this->add('secret', 'medium', $rel, $n, $line,
                        'Posible credencial escrita directamente en el codigo. Si el repo se filtra, la clave queda comprometida.',
                        'Muevela a .env / config.php fuera del docroot y leela con getenv().');
                }
            }

            // 13. phpinfo / debug
            if (preg_match('/\bphpinfo\s*\(/', $code)) {
                $this->add('phpinfo', 'low', $rel, $n, $line,
                    'phpinfo() expone rutas, versiones y modulos del servidor a cualquiera que lo visite.',
                    'Elimina este archivo en produccion.');
            }
            if (preg_match('/(ini_set\s*\(\s*[\'"]display_errors[\'"]\s*,\s*[\'"]?1|error_reporting\s*\(\s*E_ALL\s*\))/', $code)) {
                $this->add('debug', 'low', $rel, $n, $line,
                    'Errores visibles en pantalla: filtran rutas del servidor y fragmentos de codigo a los atacantes.',
                    'En produccion: display_errors=0, log_errors=1.');
            }
        }

        // ---- Chequeos a nivel de archivo ----
        if ($hasPost && $hasMutation && !$hasCsrf) {
            $this->add('csrf', 'high', $rel, 1, basename($rel),
                'El archivo modifica datos via POST sin verificacion CSRF visible. Otra web podria forzar acciones en nombre del admin logueado.',
                'Verifica un token: csrf_verify($_POST["csrf"]) en cada accion, y emite el token en el formulario.');
        }
        $isAdminArea = (bool) preg_match('#[\\\\/]admin[\\\\/]|admin_|_admin#i', $rel);
        if ($isAdminArea && $hasMutation && !$hasAuth) {
            $this->add('access', 'high', $rel, 1, basename($rel),
                'Acciones administrativas sin control de permisos visible. Cualquier visitante podria ejecutarlas.',
                'Exige orizon_can()/current_user_can()/Auth::requireAdmin() al inicio del handler.');
        }
        if ($hasUpload && !$hasExtWhitelist) {
            $this->add('upload', 'medium', $rel, 1, basename($rel),
                'El archivo gestiona subidas sin whitelist de extension/MIME visible. Podrian subir un .php ejecutable.',
                'Valida extension con lista blanca, comprueba MIME real (finfo) y sirve desde carpeta sin ejecucion PHP.');
        }
    }
}
