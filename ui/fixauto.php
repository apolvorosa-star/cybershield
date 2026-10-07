<?php
/**
 * CyberShield UI — reparacion automatica con IA.
 * Lanzado por worker.php:  php worker.php fixauto <jobDir> <targetIdx>
 *
 * Recorre los hallazgos critical/high que apuntan a .php y por cada uno:
 *   descarga → IA propone → php -l → backup en _cs_cuarentena/ → sube
 *   → post-check HTTP de la web (si peta, restaura automaticamente)
 * Progreso en <jobDir>/fixstatus-<i>.json para que el panel lo pinte en vivo.
 */

use Orizon\CyberShield\AiFixer;
use Orizon\CyberShield\CredentialStore;
use Orizon\CyberShield\Notifier;
use Orizon\CyberShield\RemoteAudit;
use Orizon\CyberShield\RemoteFixer;
use Orizon\CyberShield\Whitelist;

$jobDir = $argv[2] ?? '';
$ti     = (int) ($argv[3] ?? 0);
if (!is_dir($jobDir)) exit(1);

$jobsRoot = dirname($jobDir);
$fxFile   = "$jobDir/fixstatus-$ti.json";
$job      = json_decode((string) @file_get_contents("$jobDir/job.json"), true);
$res      = json_decode((string) @file_get_contents("$jobDir/t$ti.json"), true);
$settings = json_decode((string) @file_get_contents("$jobsRoot/settings.json"), true) ?: [];
if (!$job || !$res) exit(1);

CredentialStore::init($jobsRoot);
$t    = $job['targets'][$ti] ?? [];
$conn = $t['conn'] ?? null;
if ($conn && !empty($conn['pass'])) {
    $conn['pass'] = CredentialStore::decrypt((string) $conn['pass']);
}
$drDisk = $res['docroot'] ?? null;
$siteUrl = rtrim((string) ($res['target'] ?? ''), '/');

// ── Lista blanca compartida: whitelist.txt/.dist locales +
//    .cybershield-whitelist del docroot remoto (los ficheros listados
//    NO se auto-reparan ni van a cuarentena).
$wlRules = Whitelist::rules($conn);
$isWhitelisted = fn(string $rpath): bool => Whitelist::check($wlRules, $rpath, $conn, $siteUrl);

$state = ['state' => 'running', 'target' => $res['target'] ?? '', 'results' => []];
// Re-runs incrementales: los hallazgos ya reparados no se reprocesan
$prev = json_decode((string) @file_get_contents($fxFile), true);
$doneOk = [];
foreach (($prev['results'] ?? []) as $r) {
    if (($r['result'] ?? '') === 'ok') $doneOk[(int) $r['n']] = $r;
}
$save = function () use ($fxFile, &$state): void {
    file_put_contents($fxFile, json_encode($state, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
};
$done = function (string $msg) use (&$state, $save, $settings, $res): void {
    $state['state'] = 'done';
    $ok = count(array_filter($state['results'], fn($r) => $r['result'] === 'ok'));
    $state['summary'] = "$ok/" . count($state['results']) . " parches aplicados. $msg";
    $save();
    if ($ok > 0) Notifier::alert($settings, (string) ($res['target'] ?? ''), "WEB REPARADA ($ok parches)", []);
};

$lint = function (string $code): ?string {
    $tmp = tempnam(sys_get_temp_dir(), 'csfix') . '.php';
    file_put_contents($tmp, $code);
    exec(sprintf('"%s" -l %s 2>&1', PHP_BINARY, escapeshellarg($tmp)), $o, $rc);
    @unlink($tmp);
    return $rc === 0 ? null : implode("\n", $o);
};

// ── 0. Fixes rapidos sin IA (htaccess, cuarentena de dumps, uploads) ──
//    Van primero: son idempotentes y resuelven los .env/.sql expuestos
//    aunque la IA luego falle. Solo sobre objetivos FTP.
if ($conn) {
    $state['results'][] = ['n' => -1, 'rule' => '⚡ fix rapido', 'file' => '', 'result' => 'running', 'note' => 'htaccess + cuarentena + uploads'];
    $save();
    $quick = RemoteFixer::quickFixes($conn, $siteUrl);
    $logL  = [];
    foreach ($quick as $q) {
        $logL[] = ($q['ok'] ? '[ok] ' : '[!!] ') . $q['accion'] . ' — ' . $q['detalle'];
        $state['results'][] = [
            'n' => -1, 'rule' => '⚡ ' . $q['accion'], 'file' => '',
            'result' => $q['ok'] ? 'ok' : 'skip', 'note' => $q['detalle'],
        ];
    }
    @file_put_contents("$jobDir/quickfix-$ti.log", implode("\n", $logL) . "\n");
    $state['results'] = array_values(array_filter(
        $state['results'],
        fn($r) => !(($r['n'] ?? 0) === -1 && ($r['result'] ?? '') === 'running')
    ));
    $save();
}

// Copias locales de todo lo descargado (auditable despues)
$backupDir = "$jobDir/backups-t$ti";
if (!is_dir($backupDir)) @mkdir($backupDir, 0777, true);

foreach (($res['findings'] ?? []) as $n => $f) {
    if (!in_array($f['severity'] ?? '', ['critical', 'high'], true)) continue;
    $file = (string) ($f['file'] ?? '');
    if (!str_ends_with(strtolower($file), '.php')) continue;

    if (isset($doneOk[$n])) { $state['results'][] = $doneOk[$n]; $save(); continue; }

    $row = ['n' => $n, 'rule' => $f['rule'] ?? '', 'file' => $file, 'result' => 'running'];
    $state['results'][] = $row; $idx = array_key_last($state['results']); $save();

    $fail = function (string $why) use (&$state, $idx, $save): void {
        $state['results'][$idx]['result'] = 'skip';
        $state['results'][$idx]['note']   = $why;
        $save();
    };

    // 1. Resolver ruta remota/local
    if ($conn) {
        $rpath = RemoteAudit::resolveRemotePath($conn, $file, $drDisk);
        if ($rpath === null) { $fail('ruta fuera del docroot'); continue; }
        $kind = 'ftp';
    } else { $rpath = $file; $kind = 'local'; }

    // 1b. Whitelist + ficheros protegidos (secretos/config nunca se reescriben)
    if ($isWhitelisted((string) $rpath)) { $fail('en whitelist — protegido, no se toca'); continue; }
    if (Whitelist::isProtectedName((string) $rpath)) { $fail('fichero protegido (.env/config) — se protege por .htaccess, no se reescribe'); continue; }
    if (stripos(str_replace('\\', '/', (string) $rpath), '/_cs_cuarentena/') !== false
        || stripos(basename(dirname((string) $rpath)), '_cs_cuarentena') === 0) {
        $fail('ya esta en cuarentena — no se parchea'); continue;
    }

    // 2. Descargar (+ copia local auditable)
    $code = $kind === 'ftp' ? RemoteAudit::ftpDownload($conn, $rpath) : @file_get_contents($rpath);
    if ($code === null || $code === false || $code === '') { $fail('no se pudo leer el fichero'); continue; }
    @file_put_contents("$backupDir/" . basename((string) $rpath) . '.orig', $code);

    // 3. IA propone
    $ai = AiFixer::fix($settings, $f, $code, $file);
    if (!isset($ai['code'])) { $fail('IA: ' . ($ai['error'] ?? 'sin respuesta')); continue; }
    $new = $ai['code'];
    if (!str_starts_with(ltrim($new), '<')) { $fail('la IA no devolvio codigo'); continue; }

    // Si la IA usa helpers CSRF sin definirlos, los inyectamos (idempotente)
    if (preg_match('/csrf_(token|verify)\s*\(/', $new) && !preg_match('/function\s+csrf_(token|verify)/', $new)) {
        $helpers = <<<'PHP'

// --- CyberShield: helpers CSRF ---
if (!function_exists('csrf_token')) {
    function csrf_token(): string {
        if (empty($_SESSION['csrf'])) { $_SESSION['csrf'] = bin2hex(random_bytes(32)); }
        return $_SESSION['csrf'];
    }
    function csrf_verify(string $t): bool {
        return isset($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $t);
    }
}
PHP;
        $new = preg_replace('/\?>\s*$/', '', $new) . $helpers . "\n";
    }

    // 4. Sintaxis
    if (($err = $lint($new)) !== null) { $fail("no compila: " . strtok($err, "\n")); continue; }
    if ($new === $code) { $fail('la IA no propuso cambios'); continue; }

    // 5. Backup + escribir
    if ($kind === 'ftp') {
        $dr  = rtrim((string) ($conn['docroot'] ?? ''), '/');
        $bak = "$dr/_cs_cuarentena/" . basename($rpath) . '.' . date('Ymd-His') . '.bak';
        RemoteAudit::ftpUpload($conn, "$dr/_cs_cuarentena/.htaccess", "Require all denied\nDeny from all\n");
        if (!RemoteAudit::ftpMove($conn, $rpath, $bak)) { $fail('no se pudo hacer backup'); continue; }
        if (!RemoteAudit::ftpUpload($conn, $rpath, $new)) {
            RemoteAudit::ftpMove($conn, $bak, $rpath); // intenta restaurar
            $fail('fallo la subida (restaurado)'); continue;
        }
        // 5b. Verificacion post-subida: lo que quedo debe ser lo que enviamos
        $verify = RemoteAudit::ftpDownload($conn, $rpath);
        if ($verify === null || md5((string) $verify) !== md5($new)) {
            RemoteAudit::ftpMove($conn, $bak, $rpath);
            $fail('verificacion post-subida fallo (fichero vacio/corrupto) — restaurado');
            continue;
        }
        // 6. Post-check: si la web o el fichero parcheado caen, rollback
        $st = $siteUrl !== '' ? RemoteAudit::httpStatus($siteUrl) : 0;
        $fileUrl = $siteUrl . '/' . ltrim(substr($rpath, strlen(rtrim((string) ($conn['docroot'] ?? ''), '/'))), '/');
        $stFile = $siteUrl !== '' ? RemoteAudit::httpStatus($fileUrl) : 0;
        if ($st >= 500 || $stFile >= 500) {
            RemoteAudit::ftpMove($conn, $bak, $rpath); // restaura el original
            $fail('HTTP ' . max($st, $stFile) . ' tras el parche — restaurado');
            continue;
        }
    } else {
        if (!@copy($rpath, $rpath . '.bak-' . date('Ymd-His'))) { $fail('no se pudo hacer backup'); continue; }
        if (file_put_contents($rpath, $new) === false) { $fail('no se pudo escribir'); continue; }
    }

    $state['results'][$idx]['result'] = 'ok';
    $state['results'][$idx]['note']   = 'parche aplicado, backup en cuarentena';
    $save();
    sleep(1); // ritmo amable con la API de IA
}

$done('Re-audita para confirmar.');
exit(0);
