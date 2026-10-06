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

$state = ['state' => 'running', 'target' => $res['target'] ?? '', 'results' => []];
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

foreach (($res['findings'] ?? []) as $n => $f) {
    if (!in_array($f['severity'] ?? '', ['critical', 'high'], true)) continue;
    $file = (string) ($f['file'] ?? '');
    if (!str_ends_with(strtolower($file), '.php')) continue;

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

    // 2. Descargar
    $code = $kind === 'ftp' ? RemoteAudit::ftpDownload($conn, $rpath) : @file_get_contents($rpath);
    if ($code === null || $code === false || $code === '') { $fail('no se pudo leer el fichero'); continue; }

    // 3. IA propone
    $ai = AiFixer::fix($settings, $f, $code, $file);
    if (!isset($ai['code'])) { $fail('IA: ' . ($ai['error'] ?? 'sin respuesta')); continue; }
    $new = $ai['code'];
    if (!str_starts_with(ltrim($new), '<')) { $fail('la IA no devolvio codigo'); continue; }

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
        // 6. Post-check: si la web cae, rollback automatico
        $st = $siteUrl !== '' ? RemoteAudit::httpStatus($siteUrl) : 0;
        if ($st >= 500) {
            RemoteAudit::ftpMove($conn, $bak, $rpath);
            RemoteAudit::ftpUpload($conn, $rpath, RemoteAudit::ftpDownload($conn, $bak) ?: $code);
            $fail("la web devolvio HTTP $st tras el parche — restaurado"); continue;
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
