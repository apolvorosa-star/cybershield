<?php
/**
 * CyberShield UI — panel local (router para "php -S").
 * Formulario multi-web, fichas de servidores (FTP/SSH), cola de
 * auditorias en segundo plano, alertas e informes.
 * Solo escucha en localhost/LAN — es una app local, no un servicio publico.
 */

$root     = dirname(__DIR__);
$jobsRoot = $root . '/informes/ui';
if (!is_dir($jobsRoot) && !@mkdir($jobsRoot, 0777, true)) {
    $jobsRoot = sys_get_temp_dir() . '/cybershield-ui';
    if (!is_dir($jobsRoot)) @mkdir($jobsRoot, 0777, true);
}
$websFile     = $jobsRoot . '/webs.json';
$alertsFile   = $jobsRoot . '/alerts.json';
$settingsFile = $jobsRoot . '/settings.json';

require_once $root . '/src/CredentialStore.php';
require_once $root . '/src/RemoteAudit.php';
require_once $root . '/src/AiFixer.php';
require_once $root . '/src/Whitelist.php';
require_once $root . '/src/RemoteFixer.php';
Orizon\CyberShield\CredentialStore::init($jobsRoot);

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?: '/';

// Estaticos dentro de ui/ se sirven tal cual (manifest, sw.js)
if ($path !== '/' && is_file(__DIR__ . $path)) return false;

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');

$readJson = fn($f, $def = []) => json_decode((string) @file_get_contents($f), true) ?: $def;

$logoFile = $root . '/assets/logo.jpg';
$logo     = is_file($logoFile) ? 'data:image/jpeg;base64,' . base64_encode(file_get_contents($logoFile)) : '';

// ---------- Auth del panel ----------
// La contrasena se crea la primera vez que entras; cookie firmada HMAC
// derivada del hash (cambiar la contrasena invalida todas las sesiones).
$settings  = $readJson($settingsFile);
$passHash  = (string) ($settings['panel_pass'] ?? '');
$cookieTok = (string) ($_COOKIE['cs_auth'] ?? '');
$cookieOk  = $passHash !== '' && hash_equals(hash_hmac('sha256', 'cs-panel', $passHash), $cookieTok);
$loginErr  = '';

if ($path === '/login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $p = (string) ($_POST['pass'] ?? '');
    $ok = false;
    if ($passHash === '') {
        if (strlen($p) >= 6) {
            $settings['panel_pass'] = password_hash($p, PASSWORD_DEFAULT);
            file_put_contents($settingsFile, json_encode($settings, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
            $passHash = $settings['panel_pass'];
            $ok = true;
        } else {
            $loginErr = 'Minimo 6 caracteres.';
        }
    } elseif (password_verify($p, $passHash)) {
        $ok = true;
    } else {
        $loginErr = 'Contrasena incorrecta.';
    }
    if ($ok) {
        setcookie('cs_auth', hash_hmac('sha256', 'cs-panel', $passHash), [
            'expires' => time() + 2592000, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax',
        ]);
        header('Location: /');
        return true;
    }
}
if ($path === '/logout') {
    setcookie('cs_auth', '', time() - 3600, '/');
    header('Location: /login');
    return true;
}
if (!$cookieOk) {
    if ($path !== '/login') { header('Location: /login'); return true; }
    $isSetup = $passHash === '';
    $msg = $loginErr ? "<div style='color:#fca5a5;font-size:13px;margin-bottom:10px'>$loginErr</div>" : '';
    echo "<!DOCTYPE html><html lang='es'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'><title>Acceso · CyberShield</title>
<style>body{background:#0a0e1a;color:#e2e8f0;font-family:'Segoe UI',Arial,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
.card{background:#0f172a;border:1px solid #312e81;border-radius:14px;padding:32px;width:340px}
h1{font-size:18px;margin:0 0 4px}.sub{color:#818cf8;font-size:11px;letter-spacing:2px;text-transform:uppercase;margin-bottom:22px}
input{width:100%;background:#0a0e1a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;padding:11px;padding-right:42px;font-size:14px;box-sizing:border-box}
button{width:100%;background:#6366f1;color:#fff;border:0;border-radius:10px;padding:12px;font-weight:700;cursor:pointer}
.pwrap{position:relative;margin-bottom:14px}
.eye{position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:0;color:#64748b;font-size:17px;cursor:pointer;padding:2px 6px;width:auto}
.eye:hover{color:#a5b4fc}
.note{color:#64748b;font-size:12px;margin-top:14px}</style></head><body>
<form class='card' method='post' action='/login'>
<h1>🛡️ CyberShield AI</h1><div class='sub'>Orizon Studio · Panel</div>
$msg
<div class='pwrap'><input type='password' name='pass' id='pw' placeholder='" . ($isSetup ? 'Crea la contrasena del panel' : 'Contrasena') . "' autofocus required>
<button type='button' class='eye' onclick='var i=document.getElementById(\"pw\");i.type=i.type===\"password\"?\"text\":\"password\";this.textContent=i.type===\"password\"?\"\\u{1F441}\":\"\\u{1F576}\"'>👁</button></div>
<button>" . ($isSetup ? 'Crear y entrar' : 'Entrar') . "</button>"
    . ($isSetup ? "<div class='note'>Primera vez: la contrasena que escribas queda guardada (hash) y sera la del panel.</div>" : '')
    . "</form></body></html>";
    return true;
}

// ---------- API ----------
if ($path === '/api/status') {
    $id = preg_replace('/[^a-zA-Z0-9_-]/', '', $_GET['id'] ?? '');
    $f  = "$jobsRoot/$id/status.json";
    header('Content-Type: application/json; charset=utf-8');
    echo is_file($f) ? file_get_contents($f) : '{"state":"missing","targets":[]}';
    return true;
}

// ---------- Logo (icono PWA) ----------
if ($path === '/logo') {
    $f = $root . '/assets/logo.jpg';
    if (!is_file($f)) { http_response_code(404); return true; }
    header('Content-Type: image/jpeg');
    readfile($f);
    return true;
}

// ---------- Informe / salida ----------
if ($path === '/report') {
    $id   = preg_replace('/[^a-zA-Z0-9_-]/', '', $_GET['id'] ?? '');
    $file = basename($_GET['f'] ?? '');
    $full = "$jobsRoot/$id/$file";
    if (!is_file($full)) { http_response_code(404); echo 'No existe'; return true; }
    $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
    header('Content-Type: ' . ($ext === 'html' ? 'text/html' : 'text/plain') . '; charset=utf-8');
    readfile($full);
    return true;
}

// ---------- Guardar web (ficha de servidor) ----------
if ($path === '/webs/save' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $webs = $readJson($websFile);
    $webs[] = [
        'id'      => bin2hex(random_bytes(4)),
        'name'    => trim((string) ($_POST['name'] ?? '')) ?: ($_POST['url'] ?? 'web'),
        'url'     => trim((string) ($_POST['url'] ?? '')),
        'access'  => in_array($_POST['access'] ?? 'url', ['url', 'ftp', 'ssh'], true) ? $_POST['access'] : 'url',
        'host'    => trim((string) ($_POST['host'] ?? '')),
        'port'    => trim((string) ($_POST['port'] ?? '')),
        'user'    => trim((string) ($_POST['user'] ?? '')),
        'pass'    => Orizon\CyberShield\CredentialStore::encrypt((string) ($_POST['pass'] ?? '')),
        'key'     => trim((string) ($_POST['key'] ?? '')),
        'docroot' => trim((string) ($_POST['docroot'] ?? '')),
    ];
    file_put_contents($websFile, json_encode($webs, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
    header('Location: /?ok=web#webs');
    return true;
}

if ($path === '/webs/del') {
    $id   = $_GET['id'] ?? '';
    $webs = array_values(array_filter($readJson($websFile), fn($w) => $w['id'] !== $id));
    file_put_contents($websFile, json_encode($webs, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
    header('Location: /#webs');
    return true;
}

// ---------- Ajustes ----------
if ($path === '/settings/save' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $prev = $readJson($settingsFile); // preserva panel_pass (no va en el form)
    file_put_contents($settingsFile, json_encode([
        'ntfy'       => trim((string) ($_POST['ntfy'] ?? '')),
        'tg_token'   => trim((string) ($_POST['tg_token'] ?? '')),
        'tg_chat'    => trim((string) ($_POST['tg_chat'] ?? '')),
        'webhook'    => trim((string) ($_POST['webhook'] ?? '')),
        'ai_url'     => trim((string) ($_POST['ai_url'] ?? '')),
        'ai_key'     => trim((string) ($_POST['ai_key'] ?? '')),
        'ai_model'   => trim((string) ($_POST['ai_model'] ?? '')),
        'panel_pass' => $prev['panel_pass'] ?? '',
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
    header('Location: /?ok=ajustes#ajustes');
    return true;
}

// ---------- Alertas ----------
if ($path === '/alerts/clear') {
    file_put_contents($alertsFile, '[]');
    header('Location: /#alertas');
    return true;
}

// ---------- Lanzar auditoria ----------
if ($path === '/run' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $raw     = trim((string) ($_POST['targets'] ?? ''));
    $targets = array_values(array_filter(array_map('trim', preg_split('/[\r\n,;]+/', $raw))));
    $profile = in_array($_POST['profile'] ?? 'orizon', ['orizon', 'wordpress', 'generic'], true)
        ? $_POST['profile'] : 'orizon';
    $wantHtml = isset($_POST['html']);
    $saved    = $_POST['webs'] ?? [];
    if (!is_array($saved)) $saved = [$saved];

    $webs = $readJson($websFile);
    $list = [];

    foreach ($targets as $t) {
        $mode = preg_match('#^https?://#i', $t) ? 'web'
              : (preg_match('/\.log$/i', $t) ? 'log' : 'all');
        $list[] = ['target' => $t, 'mode' => $mode];
    }
    foreach ($saved as $wid) {
        foreach ($webs as $w) {
            if ($w['id'] !== $wid) continue;
            if ($w['access'] === 'url') {
                $list[] = ['target' => $w['url'], 'mode' => 'web'];
            } else {
                $list[] = [
                    'target' => $w['url'] ?: $w['host'],
                    'mode'   => 'agent-' . $w['access'],
                    'conn'   => [
                        'host' => $w['host'], 'port' => $w['port'], 'user' => $w['user'],
                        'pass' => $w['pass'], 'key'  => $w['key'],  'docroot' => $w['docroot'],
                    ],
                ];
            }
        }
    }
    if (!$list) { header('Location: /?err=1'); return true; }

    $id     = date('Ymd-His') . '-' . bin2hex(random_bytes(3));
    $jobDir = "$jobsRoot/$id";
    mkdir($jobDir, 0777, true);
    file_put_contents("$jobDir/job.json", json_encode([
        'id' => $id, 'profile' => $profile, 'html' => $wantHtml, 'targets' => $list,
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
    file_put_contents("$jobDir/status.json", json_encode(['state' => 'queued', 'targets' => []]));

    $worker = $root . '/ui/worker.php';
    $log    = $jobDir . '/worker.log';
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
        pclose(popen('start /B "" ' . escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($worker)
            . ' ' . escapeshellarg($jobDir) . ' > ' . escapeshellarg($log) . ' 2>&1', 'r'));
    } else {
        exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($worker) . ' '
            . escapeshellarg($jobDir) . ' > ' . escapeshellarg($log) . ' 2>&1 &');
    }
    header("Location: /job?id=$id");
    return true;
}

// ---------- Reparar con IA ----------
// Mapea ruta de disco del agente → ruta FTP de la ficha
$resolveRemote = function (array $job, int $i, array $f) use ($jobsRoot): array {
    $t    = $job['targets'][$i] ?? [];
    $conn = $t['conn'] ?? null;
    $file = (string) ($f['file'] ?? '');
    if (!$conn) return ['local', $file]; // objetivo local: la ruta ya es de este PC
    $conn = array_merge($conn, ['pass' => Orizon\CyberShield\CredentialStore::decrypt((string) ($conn['pass'] ?? ''))]);
    // docroot del agente (disco) ↔ docroot FTP de la ficha
    $tj  = json_decode((string) @file_get_contents($jobsRoot . '/' . $job['id'] . "/t$i.json"), true) ?: [];
    $remote = Orizon\CyberShield\RemoteAudit::resolveRemotePath($conn, $file, $tj['docroot'] ?? null);
    if ($remote === null) return ['invalid', ''];
    return ['ftp', $remote, $conn];
};

if ($path === '/fix') {
    $id  = preg_replace('/[^a-zA-Z0-9_-]/', '', $_GET['id'] ?? '');
    $i   = (int) ($_GET['i'] ?? 0);
    $job = json_decode((string) @file_get_contents("$jobsRoot/$id/job.json"), true);
    $res = json_decode((string) @file_get_contents("$jobsRoot/$id/t$i.json"), true);
    if (!$job || !$res) { header('Location: /'); return true; }
    echo head('Reparar', $logo);
    echo "<div class='card'><h2>🔧 Reparar con IA — {$res['target']}</h2>";

    if (!isset($_GET['n'])) {
        // Lista de hallazgos criticos/altos reparables
        $tconn = $job['targets'][$i]['conn'] ?? null;
        $wlRules = Orizon\CyberShield\Whitelist::rules(
            $tconn ? array_merge($tconn, ['pass' => Orizon\CyberShield\CredentialStore::decrypt((string) ($tconn['pass'] ?? ''))]) : null
        );
        $wlCheck = function (string $fpath) use ($wlRules, $job, $i, $res, $resolveRemote): bool {
            [$k, $rp, $c] = $resolveRemote($job, $i, ['file' => $fpath]);
            if ($k === 'invalid') return true; // fuera de docroot = bloqueado igualmente
            return Orizon\CyberShield\Whitelist::check($wlRules, (string) $rp, $c ?: null, (string) ($res['target'] ?? ''))
                || Orizon\CyberShield\Whitelist::isProtectedName((string) $rp);
        };
        $rows = '';
        foreach ($res['findings'] as $n => $f) {
            if (!in_array($f['severity'], ['critical', 'high'], true)) continue;
            $isPhp = str_ends_with(strtolower((string) $f['file']), '.php');
            $prot = $isPhp && $wlCheck((string) $f['file']);
            $btn = !$isPhp
                ? "<span class='muted'>manual</span>"
                : ($prot
                    ? "<span class='muted' title='En whitelist o fichero protegido'>🛡 protegido</span>"
                    : "<a class='btn sm' href='/fix?id=$id&i=$i&n=$n'>Reparar</a>");
            $sev = $f['severity'] === 'critical' ? '🔴' : '🟠';
            $rel = basename((string) $f['file']);
            $rows .= "<div class='job'><div>$sev <b>{$f['rule']}</b> <span class='ur'>$rel:{$f['line']}</span>"
                . "<div class='muted'>" . htmlspecialchars(substr((string) ($f['desc'] ?? ''), 0, 120)) . "</div></div>$btn</div>";
        }
        $aiOk = !empty($settings['ai_url']) || !empty($settings['ai_key']);
        $autoBtn = $aiOk
            ? "<form method='post' action='/fix/auto' onsubmit=\"return confirm('La IA reparara TODOS los hallazgos de la lista uno a uno. Cada fichero se respalda en _cs_cuarentena/ y si la web falla se restaura solo. ¿Continuar?')\">"
              . "<input type='hidden' name='id' value='$id'><input type='hidden' name='i' value='$i'>"
              . "<button class='btn'>⚡ Reparar TODO con IA</button></form>"
            : "<div class='muted'>⚡ Reparacion automatica: configura una IA en <a href='/'>Ajustes</a> (preset Ollama = gratis y local).</div>";
        // Fixes rapidos sin IA (solo objetivos con FTP): .htaccess anti-.env/.sql,
        // cuarentena de dumps sueltos y uploads sin ejecucion
        $quickBtn = '';
        if ($tconn) {
            $quickBtn = "<form method='post' action='/fix/quick' onsubmit=\"return confirm('Se aplicaran fixes rapidos SIN IA en el servidor: .htaccess de seguridad, cuarentena de .sql/.bak/.zip sueltos y proteccion de uploads. Respeta la whitelist. ¿Continuar?')\">"
                . "<input type='hidden' name='id' value='$id'><input type='hidden' name='i' value='$i'>"
                . "<button class='btn sm'>🛡 Fixes rapidos sin IA</button></form>";
        }
        echo "<div class='row' style='margin-bottom:14px'>$autoBtn $quickBtn</div>";
        echo $rows ?: "<div class='muted'>Sin hallazgos criticos/altos reparables con IA.</div>";
        echo "<div class='links' style='margin-top:14px'><a href='/job?id=$id'>← volver a la auditoria</a></div></div></body></html>";
        return true;
    }

    // Pantalla de reparacion de un hallazgo
    $n = (int) $_GET['n'];
    $f = $res['findings'][$n] ?? null;
    if (!$f) { echo "Hallazgo no existe.</div>"; return true; }
    [$kind, $rpath, $conn] = $resolveRemote($job, $i, $f);
    if ($kind === 'invalid') {
        echo "<div class='alert'>Ruta fuera del docroot — reparacion bloqueada.</div></div></body></html>";
        return true;
    }
    $code = $kind === 'ftp'
        ? Orizon\CyberShield\RemoteAudit::ftpDownload($conn, $rpath)
        : @file_get_contents($rpath);
    if ($code === null || $code === false || $code === '') {
        echo "<div class='muted'>No se pudo leer <b>" . htmlspecialchars($rpath) . "</b> ($kind). ¿Fichero borrado o FTP inaccesible?</div></div></body></html>";
        return true;
    }

    $proposal = '';
    $note = '';
    if (!empty($settings['ai_key']) || !empty($settings['ai_url'])) {
        $ai = Orizon\CyberShield\AiFixer::fix($settings, $f, $code, (string) $f['file']);
        if (isset($ai['code'])) $proposal = $ai['code'];
        else $note = "<div class='alert'>⚠️ " . htmlspecialchars($ai['error']) . "</div>";
    } else {
        $note = "<div class='muted'>Sin IA configurada: copia el prompt, pegalo en tu IA (ChatGPT, Ollama, Devin…) y pega el codigo corregido abajo. Puedes configurar una IA local gratis en Ajustes.</div>";
    }
    $prompt = htmlspecialchars(Orizon\CyberShield\AiFixer::buildPrompt($f, $code, (string) $f['file']));
    $codeH  = htmlspecialchars($code);
    $propH  = htmlspecialchars($proposal);
    $propTag = $proposal !== '' ? ' (propuesto por IA — revisalo)' : '';
    $fDesc   = htmlspecialchars((string) ($f['desc'] ?? $f['risk'] ?? ''));
    echo <<<HTML
<div class='muted'>{$f['severity']} · {$f['rule']} · <b>{$f['file']}:{$f['line']}</b></div>
<div class='muted' style='margin-top:4px'>{$fDesc}</div>
$note
<details style='margin:12px 0'><summary style='cursor:pointer;color:#a5b4fc'>📋 Prompt para IA (clic para ver/copiar)</summary>
<textarea readonly onclick='this.select()' style='min-height:200px'>$prompt</textarea></details>
<details><summary style='cursor:pointer;color:#a5b4fc'>📄 Codigo actual</summary>
<textarea readonly style='min-height:200px'>$codeH</textarea></details>
<form method='post' action='/fix/apply' style='margin-top:14px'>
<input type='hidden' name='id' value='$id'><input type='hidden' name='i' value='$i'><input type='hidden' name='n' value='$n'>
<label class='f'>Codigo corregido$propTag</label>
<textarea name='code' style='min-height:280px' required>$propH</textarea>
<div class='row'><button class='btn'>✅ Aplicar al servidor</button>
<a href='/fix?id=$id&i=$i' style='color:#94a3b8;font-size:13px'>cancelar</a></div>
<div class='note'>Se hace backup del original en _cs_cuarentena/ antes de escribir.</div>
</form>
</div></body></html>
HTML;
    return true;
}

if ($path === '/fix/apply' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $id   = preg_replace('/[^a-zA-Z0-9_-]/', '', $_POST['id'] ?? '');
    $i    = (int) ($_POST['i'] ?? 0);
    $n    = (int) ($_POST['n'] ?? 0);
    $code = (string) ($_POST['code'] ?? '');
    $job  = json_decode((string) @file_get_contents("$jobsRoot/$id/job.json"), true);
    $res  = json_decode((string) @file_get_contents("$jobsRoot/$id/t$i.json"), true);
    $f    = $res['findings'][$n] ?? null;
    echo head('Aplicar fix', $logo);
    echo "<div class='card'>";
    if (!$job || !$res || !$f || !str_starts_with(ltrim($code), '<')) {
        echo "Datos invalidos.</div></body></html>";
        return true;
    }
    // Sintaxis PHP obligatoria antes de tocar el servidor
    if (str_ends_with(strtolower((string) $f['file']), '.php')) {
        $tmp = tempnam(sys_get_temp_dir(), 'csfix') . '.php';
        file_put_contents($tmp, $code);
        exec(sprintf('"%s" -l %s 2>&1', PHP_BINARY, escapeshellarg($tmp)), $lintOut, $lintRc);
        @unlink($tmp);
        if ($lintRc !== 0) {
            echo "<div class='alert'>❌ El codigo propuesto no compila (php -l):<br><pre style='white-space:pre-wrap'>"
                . htmlspecialchars(implode("\n", $lintOut)) . "</pre>No se ha tocado el servidor.</div></body></html>";
            return true;
        }
    }
    [$kind, $rpath, $conn] = $resolveRemote($job, $i, $f);
    if ($kind === 'invalid') {
        echo "<div class='alert'>Ruta fuera del docroot — reparacion bloqueada.</div></div></body></html>";
        return true;
    }
    // Whitelist + ficheros protegidos: nunca se reescriben
    $wlRules = Orizon\CyberShield\Whitelist::rules($conn ?: null);
    if (Orizon\CyberShield\Whitelist::check($wlRules, (string) $rpath, $conn ?: null, (string) ($res['target'] ?? ''))
        || Orizon\CyberShield\Whitelist::isProtectedName((string) $rpath)) {
        echo "<div class='alert'>🛡 <b>" . htmlspecialchars(basename((string) $rpath)) . "</b> esta en la whitelist o es un fichero protegido (.env/config) — no se reescribe. Los .env se protegen con el .htaccess de los fixes rapidos.</div></div></body></html>";
        return true;
    }
    if ($kind === 'ftp') {
        $bak  = ($conn['docroot'] ?? '') . '/_cs_cuarentena/' . basename($rpath) . '.' . date('Ymd-His') . '.bak';
        Orizon\CyberShield\RemoteAudit::ftpUpload($conn, ($conn['docroot'] ?? '') . '/_cs_cuarentena/.htaccess', "Require all denied\nDeny from all\n");
        $moved = Orizon\CyberShield\RemoteAudit::ftpMove($conn, $rpath, $bak);
        $ok    = $moved && Orizon\CyberShield\RemoteAudit::ftpUpload($conn, $rpath, $code);
    } else {
        $moved = @copy($rpath, $rpath . '.bak-' . date('Ymd-His'));
        $ok    = $moved && file_put_contents($rpath, $code) !== false;
    }
    $base = htmlspecialchars(basename($rpath));
    echo $ok
        ? "<div style='color:#86efac;font-size:16px'>✅ <b>Web reparada</b> — se corrigio <b>$base</b>.<br><span class='muted' style='font-size:12px'>Original guardado en _cs_cuarentena/ · Re-audita para confirmar que el hallazgo desaparecio.</span><br><br><a class='btn sm' href='/fix?id=$id&i=$i'>← seguir reparando</a> <a class='btn sm' href='/'>🔁 re-auditar</a></div>"
        : "<div class='alert'>❌ No se pudo aplicar ($kind: " . htmlspecialchars($rpath) . ")</div>";
    echo "</div></body></html>";
    return true;
}

// ---------- Reparacion automatica con IA (lote) ----------
if ($path === '/fix/auto' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $id  = preg_replace('/[^a-zA-Z0-9_-]/', '', $_POST['id'] ?? '');
    $i   = (int) ($_POST['i'] ?? 0);
    $dir = "$jobsRoot/$id";
    if (!is_dir($dir)) { header('Location: /'); return true; }
    $worker = $root . '/ui/worker.php';
    $log    = "$dir/fixauto.log";
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
        pclose(popen('start /B "" ' . escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($worker)
            . ' fixauto ' . escapeshellarg($dir) . ' ' . $i
            . ' > ' . escapeshellarg($log) . ' 2>&1', 'r'));
    } else {
        exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($worker)
            . ' fixauto ' . escapeshellarg($dir) . ' ' . $i
            . ' > ' . escapeshellarg($log) . ' 2>&1 &');
    }
    header("Location: /fix/auto?id=$id&i=$i");
    return true;
}

// ---------- Fixes rapidos sin IA (FTP): htaccess + cuarentena + uploads ----------
if ($path === '/fix/quick' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $id  = preg_replace('/[^a-zA-Z0-9_-]/', '', $_POST['id'] ?? '');
    $i   = (int) ($_POST['i'] ?? 0);
    $job = json_decode((string) @file_get_contents("$jobsRoot/$id/job.json"), true);
    $res = json_decode((string) @file_get_contents("$jobsRoot/$id/t$i.json"), true);
    echo head('Fixes rapidos', $logo);
    echo "<div class='card'><h2>🛡 Fixes rapidos sin IA</h2>";
    $conn = $job['targets'][$i]['conn'] ?? null;
    if (!$job || !$res || !$conn) {
        echo "<div class='alert'>Este objetivo no tiene conexion FTP configurada — los fixes rapidos solo aplican a servidores remotos.</div>";
    } else {
        $conn['pass'] = Orizon\CyberShield\CredentialStore::decrypt((string) ($conn['pass'] ?? ''));
        $actions = Orizon\CyberShield\RemoteFixer::quickFixes($conn, (string) ($res['target'] ?? ''));
        $lines = [];
        echo "<table style='width:100%;border-collapse:collapse;font-size:13px'>";
        foreach ($actions as $a) {
            $ico = $a['ok'] ? '✅' : '❌';
            echo "<tr style='border-top:1px solid #1e293b'><td style='padding:7px 4px'>$ico</td>"
                . "<td style='padding:7px 4px'><b>" . htmlspecialchars($a['accion']) . "</b></td>"
                . "<td class='muted' style='padding:7px 4px'>" . htmlspecialchars($a['detalle']) . "</td></tr>";
            $lines[] = ($a['ok'] ? '[ok] ' : '[!!] ') . $a['accion'] . ' — ' . $a['detalle'];
        }
        echo "</table>";
        @file_put_contents("$jobsRoot/$id/quickfix-$i.log", implode("\n", $lines) . "\n");
        echo "<div class='links' style='margin-top:14px'><a href='/fix?id=$id&i=$i'>← hallazgos</a>"
            . "<a href='/'>🔁 re-auditar para verificar</a></div>";
    }
    echo "</div></body></html>";
    return true;
}

// ---------- Probar conexion IA ----------
if ($path === '/aitest' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $t0 = microtime(true);
    $r  = Orizon\CyberShield\AiFixer::fix($settings,
        ['rule' => 'csrf', 'line' => 1, 'desc' => 'Test de conexion'],
        "<?php\n\$_GET['x'] = 1;\necho 'ok';", 'test.php');
    $secs = round(microtime(true) - $t0, 1);
    echo head('Test IA', $logo) . "<div class='card'><h2>🔬 Prueba de IA</h2>";
    if (isset($r['code'])) {
        echo "<div style='color:#86efac'>✅ La IA respondio en {$secs}s — endpoint y modelo funcionan.<br>"
            . "<span class='muted'>" . htmlspecialchars((string) ($settings['ai_url'] ?: 'api.openai.com')) . " · modelo " . htmlspecialchars((string) ($settings['ai_model'] ?: 'gpt-4o-mini')) . "</span></div>";
    } else {
        echo "<div class='alert'>❌ " . htmlspecialchars((string) $r['error']) . "<br><br>"
            . "<span class='muted'>Si usas Ollama: arrancalo con <code>ollama serve</code> y baja un modelo con <code>ollama pull qwen2.5-coder</code>.</span></div>";
    }
    echo "<div class='row'><a class='btn sm' href='/'>← volver</a></div></div></body></html>";
    return true;
}

if ($path === '/fix/auto') {
    $id  = preg_replace('/[^a-zA-Z0-9_-]/', '', $_GET['id'] ?? '');
    $i   = (int) ($_GET['i'] ?? 0);
    $fx  = json_decode((string) @file_get_contents("$jobsRoot/$id/fixstatus-$i.json"), true)
        ?: ['state' => 'queued', 'results' => []];
    $running = ($fx['state'] ?? '') !== 'done';
    if ($running) header('Refresh: 5');
    echo head('Reparando con IA', $logo);
    echo "<div class='card'><h2>⚡ Reparacion automatica — " . htmlspecialchars((string) ($fx['target'] ?? '')) . "</h2>";
    echo $running
        ? "<div class='muted'>La IA esta reparando hallazgos uno a uno — esta pagina se actualiza sola. Puedes cerrar y volver.</div>"
        : "<div style='color:#86efac;font-size:15px'>✅ <b>" . htmlspecialchars((string) ($fx['summary'] ?? 'Terminado')) . "</b></div>";
    echo "<table style='width:100%;margin-top:14px;border-collapse:collapse;font-size:13px'>";
    foreach (($fx['results'] ?? []) as $r) {
        $ico = ['ok' => '✅', 'skip' => '⏭️', 'running' => '⏳'][$r['result']] ?? '•';
        echo "<tr style='border-top:1px solid #1e293b'><td style='padding:7px 4px'>$ico</td>"
            . "<td style='padding:7px 4px'><b>" . htmlspecialchars((string) $r['rule']) . "</b> "
            . htmlspecialchars(basename((string) $r['file'])) . "</td>"
            . "<td class='muted' style='padding:7px 4px'>" . htmlspecialchars((string) ($r['note'] ?? '')) . "</td></tr>";
    }
    echo "</table>";
    if (!$running) {
        echo "<div class='row'><a class='btn sm' href='/fix?id=$id&i=$i'>← hallazgos</a>"
            . "<a class='btn sm' href='/'>🔁 re-auditar</a></div>";
    }
    echo "</div></body></html>";
    return true;
}

// ---------- Vistas ----------

function head(string $title, string $logo): string
{
    return <<<HTML
<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#0a0e1a">
<link rel="manifest" href="/manifest.webmanifest">
<title>$title · CyberShield</title>
<style>
*{box-sizing:border-box}body{background:#0a0e1a;color:#e2e8f0;font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:24px}
.wrap{max-width:1100px;margin:auto}
.head{display:flex;align-items:center;gap:16px;padding:20px 24px;background:linear-gradient(135deg,#0a0e1a,#1e1b4b);border:1px solid #312e81;border-radius:14px;margin-bottom:20px}
.head img{width:56px;height:56px;border-radius:10px;object-fit:cover}
h1{margin:0;font-size:20px;letter-spacing:1px}.sub{color:#818cf8;font-size:11px;letter-spacing:2px;text-transform:uppercase}
.card{background:#0f172a;border:1px solid #1e293b;border-radius:14px;padding:22px;margin-bottom:18px}
h2{margin:0 0 14px;font-size:15px;color:#a5b4fc;text-transform:uppercase;letter-spacing:1px}
textarea,input[type=text],input[type=password],select{width:100%;background:#0a0e1a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;padding:9px 11px;font-size:13px}
textarea{min-height:96px;font-family:Consolas,monospace;resize:vertical}
.row{display:flex;gap:14px;align-items:center;margin-top:14px;flex-wrap:wrap}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin-top:10px}
.btn{background:#6366f1;color:#fff;border:0;border-radius:10px;padding:11px 26px;font-size:14px;font-weight:700;cursor:pointer;letter-spacing:.5px}
.btn:hover{background:#818cf8}
.btn.sm{padding:7px 14px;font-size:12.5px}
label.chk{display:flex;gap:8px;align-items:center;color:#94a3b8;font-size:13px;cursor:pointer}
label.f{display:block;color:#94a3b8;font-size:11px;text-transform:uppercase;letter-spacing:1px}
.job{border:1px solid #1e293b;border-radius:10px;padding:12px 16px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;gap:12px}
.job a{color:#a5b4fc;text-decoration:none}.job a:hover{text-decoration:underline}
.muted{color:#64748b;font-size:12px}
.web{border:1px solid #1e293b;border-radius:10px;padding:12px 14px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
.web .nm{font-weight:700}.web .ur{color:#94a3b8;font-size:12px;font-family:Consolas,monospace}
.tcard{border:1px solid #1e293b;border-radius:12px;padding:16px;margin-bottom:12px;background:#0a0e1a}
.tcard .tgt{font-family:Consolas,monospace;color:#a5b4fc;font-size:13px;word-break:break-all}
.badge{display:inline-block;padding:3px 10px;border-radius:6px;font-size:11px;font-weight:700;text-transform:uppercase}
.b-web{background:#312e81;color:#c7d2fe}.b-all{background:#134e4a;color:#99f6e4}.b-log{background:#713f12;color:#fde68a}
.b-code{background:#1e3a5f;color:#93c5fd}.b-sys{background:#3b0764;color:#d8b4fe}
.b-agent-ssh,.b-agent-ftp{background:#7c2d12;color:#fdba74}
.st-queued{color:#94a3b8}.st-running{color:#f59e0b}.st-done{color:#22c55e}.st-error{color:#ef4444}
.pills{font-size:15px;letter-spacing:1px;margin-top:8px}
.status-big{font-weight:700;margin-top:6px}
.links{margin-top:10px}.links a{color:#86efac;font-size:12.5px;margin-right:14px;text-decoration:none}.links a:hover{text-decoration:underline}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#f59e0b;margin-right:6px;animation:p 1s infinite}
@keyframes p{50%{opacity:.3}}
.ok{color:#22c55e}.warn{color:#f59e0b}.bad{color:#ef4444}
.alert{border:1px solid #7f1d1d;background:#1a0f14;border-radius:10px;padding:10px 14px;margin-bottom:8px;font-size:13px}
.del{color:#f87171;font-size:12px;text-decoration:none}.del:hover{text-decoration:underline}
.note{color:#64748b;font-size:11.5px;margin-top:4px}
</style></head><body><div class="wrap">
<div class="head"><img src="$logo" alt=""><div><h1>🛡️ CyberShield AI</h1><div class="sub">Orizon Studio · Panel de Auditoria</div></div></div>
HTML;
}

// ---------- Pagina de job ----------
if ($path === '/job') {
    $id  = preg_replace('/[^a-zA-Z0-9_-]/', '', $_GET['id'] ?? '');
    $job = is_file("$jobsRoot/$id/job.json")
        ? json_decode((string) file_get_contents("$jobsRoot/$id/job.json"), true) : null;
    echo head('Auditoria', $logo);
    if (!$job) { echo "<div class='card'>Job no encontrado. <a href='/' style='color:#a5b4fc'>Volver</a></div></div></body></html>"; return true; }
    echo "<div class='card'><h2>Auditoria en curso</h2><div class='muted'>Job $id · " . count($job['targets']) . " objetivo(s)</div><div id='targets' style='margin-top:16px'></div>";
    echo "<div style='margin-top:14px'><a href='/' style='color:#a5b4fc;font-size:13px'>← Nueva auditoria</a></div></div>";
    echo <<<HTML
<script>
const id = "$id";
const sev = ['critical','high','medium','low','info'];
const icon = {critical:'🔴',high:'🟠',medium:'🟡',low:'🔵',info:'⚪'};
const stName = {queued:'En cola',running:'Auditando…',done:'Listo',error:'Error'};
const stCls = {queued:'st-queued',running:'st-running',done:'st-done',error:'st-error'};
function render(s){
  const el = document.getElementById('targets');
  el.innerHTML = (s.targets||[]).map((t,idx)=>{
    let pills='',big='',links='',note='';
    if(t.counts){pills='<div class="pills">'+sev.map(k=>icon[k]+' '+(t.counts[k]||0)).join(' &nbsp;')+'</div>';}
    if(t.status){const cls=t.status==='SEGURO'?'ok':(t.status==='AMENAZA DETECTADA'?'bad':'warn');
      big='<div class="status-big '+cls+'">🛡️ '+t.status+'</div>';}
    if(t.note)note='<div class="note">'+t.note+'</div>';
    if(t.html)links+='<a href="/report?id='+id+'&f='+t.html+'" target="_blank">📄 Informe HTML</a>';
    if(t.txt)links+='<a href="/report?id='+id+'&f='+t.txt+'" target="_blank">🖥️ Salida consola</a>';
    if(t.state==='done'&&t.counts&&(t.counts.critical+t.counts.high)>0)links+='<a href="/fix?id='+id+'&i='+idx+'">🔧 Reparar con IA</a>';
    const run=t.state==='running'?'<span class="dot"></span>':'';
    return '<div class="tcard"><div style="display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap">'
      +'<div><span class="badge b-'+t.mode+'">'+t.mode+'</span> <span class="tgt">'+t.target+'</span></div>'
      +'<span class="'+stCls[t.state]+'">'+run+stName[t.state]+'</span></div>'
      +pills+big+note+(links?'<div class="links">'+links+'</div>':'')+'</div>';
  }).join('');
}
async function poll(){
  try{const r=await fetch('/api/status?id='+id);const s=await r.json();render(s);
    if(s.state!=='done')setTimeout(poll,1500);}catch(e){setTimeout(poll,2500);}
}
poll();
</script></div></body></html>
HTML;
    return true;
}

// ---------- Dashboard ----------
$webs     = $readJson($websFile);
$alerts   = array_reverse($readJson($alertsFile));
$settings = $readJson($settingsFile);

$websHtml = '';
foreach ($webs as $w) {
    $acc = strtoupper($w['access']);
    $websHtml .= "<div class='web'><label class='chk'><input type='checkbox' name='webs[]' value='{$w['id']}' checked>"
        . "<span><span class='nm'>{$w['name']}</span> <span class='ur'>{$w['url']}</span> "
        . "<span class='badge b-" . ($w['access'] === 'url' ? 'web' : 'agent-ssh') . "'>$acc</span></span></label>"
        . "<a class='del' href='/webs/del?id={$w['id']}'>borrar</a></div>";
}
if (!$websHtml) $websHtml = "<div class='muted'>Sin webs guardadas. Anade una abajo con sus datos de servidor.</div>";

$alertsHtml = '';
foreach (array_slice($alerts, 0, 10) as $a) {
    $c = $a['counts'] ?? [];
    $alertsHtml .= "<div class='alert'>⚠️ <b>{$a['status']}</b> — {$a['target']} "
        . "<span class='muted'>{$a['time']} · 🔴{$c['critical']} 🟠{$c['high']} 🟡{$c['medium']}</span></div>";
}
if ($alertsHtml) $alertsHtml .= "<a class='del' href='/alerts/clear'>limpiar alertas</a>";
else $alertsHtml = "<div class='muted'>Sin alertas. Cuando una auditoria encuentre algo sospechoso, aparecera aqui.</div>";

$jobs = array_values(array_filter(scandir($jobsRoot) ?: [], fn($d) => $d[0] !== '.' && is_dir("$jobsRoot/$d")));
rsort($jobs);
$jobsHtml = '';
foreach (array_slice($jobs, 0, 20) as $d) {
    $st = is_file("$jobsRoot/$d/status.json") ? json_decode((string) file_get_contents("$jobsRoot/$d/status.json"), true) : null;
    $n  = count($st['targets'] ?? []);
    $state = $st['state'] ?? '?';
    $cls = $state === 'done' ? 'ok' : ($state === 'running' || $state === 'queued' ? 'warn' : 'bad');
    $jobsHtml .= "<div class='job'><div><a href='/job?id=$d'>$d</a> <span class='muted'>· $n objetivo(s)</span></div><span class='$cls'>$state</span></div>";
}
if (!$jobsHtml) $jobsHtml = "<div class='muted'>Sin auditorias todavia.</div>";

$err  = isset($_GET['err']) ? "<div class='card' style='border-color:#ef4444;color:#fca5a5'>Marca o escribe al menos una web a auditar.</div>" : '';
$ok   = match ($_GET['ok'] ?? '') {
    'web'     => "<div class='card' style='border-color:#22c55e;color:#86efac'>✅ Web guardada. Ya la tienes arriba en \"Webs guardadas\", lista para auditar.</div>",
    'ajustes' => "<div class='card' style='border-color:#22c55e;color:#86efac'>✅ Ajustes guardados.</div>",
    default   => '',
};
$ntfy = htmlspecialchars($settings['ntfy'] ?? '');
$tgT  = htmlspecialchars($settings['tg_token'] ?? '');
$tgC  = htmlspecialchars($settings['tg_chat'] ?? '');
$whk  = htmlspecialchars($settings['webhook'] ?? '');
$aiU  = htmlspecialchars($settings['ai_url'] ?? '');
$aiK  = htmlspecialchars($settings['ai_key'] ?? '');
$aiM  = htmlspecialchars($settings['ai_model'] ?? '');

echo head('Panel', $logo);
echo <<<HTML
$err
$ok
<div class="card" id="alertas">
  <h2>🔔 Alertas</h2>$alertsHtml
</div>

<div class="card">
  <h2>Nueva auditoria</h2>
  <form method="post" action="/run">
    <div class="muted" style="margin-bottom:8px">Webs guardadas (usa los datos del servidor para auditar DENTRO):</div>
    $websHtml
    <div class="muted" style="margin:14px 0 8px">O pega objetivos sueltos (uno por linea):</div>
    <textarea name="targets" placeholder="https://mi-dominio.com
C:\xampp\htdocs\mi-web
/var/log/apache2/access.log"></textarea>
    <div class="row">
      <label class="chk" style="color:#94a3b8">Perfil <select name="profile" style="width:auto">
        <option value="orizon">orizon</option>
        <option value="wordpress">wordpress</option>
        <option value="generic">generic</option>
      </select></label>
      <label class="chk"><input type="checkbox" name="html" checked> Informe HTML</label>
      <button class="btn" type="submit">🛡️ Auditar</button>
    </div>
  </form>
</div>

<div class="card" id="webs">
  <h2>➕ Guardar web (con datos del servidor)</h2>
  <form method="post" action="/webs/save">
    <div class="grid">
      <div><label class="f">Nombre</label><input type="text" name="name" placeholder="Web del cliente"></div>
      <div><label class="f">URL publica</label><input type="text" name="url" placeholder="https://midominio.com"></div>
      <div><label class="f">Acceso</label><select name="access">
        <option value="url">Solo URL (auditoria remota de superficie)</option>
        <option value="ftp">FTP (sube agente → audita dentro → borra)</option>
        <option value="ssh">SSH (agente por CLI, necesita llave)</option>
      </select></div>
      <div><label class="f">Host servidor</label><input type="text" name="host" placeholder="ftp.midominio.com"></div>
      <div><label class="f">Puerto</label><input type="text" name="port" placeholder="21 o 22"></div>
      <div><label class="f">Usuario</label><input type="text" name="user"></div>
      <div><label class="f">Contraseña (FTP)</label><input type="password" name="pass"></div>
      <div><label class="f">Llave SSH (ruta local)</label><input type="text" name="key" placeholder="C:\Users\yo\.ssh\id_ed25519"></div>
      <div><label class="f">Docroot remoto</label><input type="text" name="docroot" placeholder="/public_html o /var/www/html"></div>
    </div>
    <div class="row"><button class="btn sm" type="submit">Guardar web</button></div>
    <div class="note">Los datos se guardan solo en tu PC (informes/ui/webs.json). El agente subido se borra solo tras auditar.</div>
  </form>
</div>

<div class="card" id="ajustes">
  <h2>⚙️ Avisos al movil (opcional)</h2>
  <form method="post" action="/settings/save">
    <div class="grid">
      <div><label class="f">Topico ntfy.sh</label><input type="text" name="ntfy" value="$ntfy" placeholder="https://ntfy.sh/tu-topico-secreto"></div>
      <div><label class="f">Telegram bot token</label><input type="text" name="tg_token" value="$tgT" placeholder="123456:ABC-DEF..."></div>
      <div><label class="f">Telegram chat_id</label><input type="text" name="tg_chat" value="$tgC" placeholder="123456789"></div>
      <div><label class="f">Webhook (JSON POST)</label><input type="text" name="webhook" value="$whk" placeholder="https://tu-n8n/webhook/..."></div>
      <div><label class="f">IA: proveedor (autorrellena)</label><select onchange="aip(this.value)">
        <option value="">— elegir —</option><option value="openai">OpenAI</option>
        <option value="deepseek">DeepSeek</option><option value="groq">Groq</option>
        <option value="ollama">Ollama (local, gratis)</option><option value="lmstudio">LM Studio (local, gratis)</option>
        <option value="manual">Manual (copiar prompt)</option></select></div>
      <div><label class="f">IA: endpoint</label><input type="text" name="ai_url" value="$aiU" placeholder="https://api.openai.com/v1/chat/completions"></div>
      <div><label class="f">IA: API key</label><input type="password" name="ai_key" value="$aiK" placeholder="sk-... (locales no necesitan key)"></div>
      <div><label class="f">IA: modelo</label><input type="text" name="ai_model" value="$aiM" placeholder="gpt-4o-mini / qwen2.5-coder…"></div>
    </div>
    <div class="row"><button class="btn sm" type="submit">Guardar</button>
    <button class="btn sm" type="submit" formaction="/aitest" formnovalidate style="background:#0e7490">🔬 Probar IA</button></div>
    <div class="note">ntfy.sh: crea un topico unico y suscribete desde la app del movil (gratis, sin cuenta). Telegram: crea un bot con @BotFather. Webhook: recibe JSON con target+status+counts.<br><b>IA local gratis</b>: instala Ollama (ollama.com) o LM Studio, baja un modelo de codigo (qwen2.5-coder, codellama…), elige el preset y guarda — sin API key, tus ficheros no salen de tu PC. Con IA en la nube (OpenAI/DeepSeek/Groq) pon tu API key. Sin nada configurado, "Reparar con IA" genera el prompt para copiar a mano.</div>
    <script>function aip(v){const M={openai:['https://api.openai.com/v1/chat/completions','gpt-4o-mini'],deepseek:['https://api.deepseek.com/v1/chat/completions','deepseek-chat'],groq:['https://api.groq.com/openai/v1/chat/completions','llama-3.3-70b-versatile'],ollama:['http://127.0.0.1:11434/v1/chat/completions','qwen2.5-coder'],lmstudio:['http://127.0.0.1:1234/v1/chat/completions','local-model'],manual:['','']};if(!M[v])return;document.querySelector('[name=ai_url]').value=M[v][0];document.querySelector('[name=ai_model]').value=M[v][1];}</script>
  </form>
</div>

<div class="card"><h2>📋 Auditorias anteriores</h2>$jobsHtml</div>
<script>if('serviceWorker' in navigator)navigator.serviceWorker.register('/sw.js').catch(()=>{});</script>
</div></body></html>
HTML;
return true;
