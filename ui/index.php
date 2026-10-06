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
Orizon\CyberShield\CredentialStore::init($jobsRoot);

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?: '/';

// Estaticos dentro de ui/ se sirven tal cual (manifest, sw.js)
if ($path !== '/' && is_file(__DIR__ . $path)) return false;

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');

$readJson = fn($f, $def = []) => json_decode((string) @file_get_contents($f), true) ?: $def;

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
input{width:100%;background:#0a0e1a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;padding:11px;font-size:14px;margin-bottom:14px;box-sizing:border-box}
button{width:100%;background:#6366f1;color:#fff;border:0;border-radius:10px;padding:12px;font-weight:700;cursor:pointer}
.note{color:#64748b;font-size:12px;margin-top:14px}</style></head><body>
<form class='card' method='post' action='/login'>
<h1>🛡️ CyberShield AI</h1><div class='sub'>Orizon Studio · Panel</div>
$msg
<input type='password' name='pass' placeholder='" . ($isSetup ? 'Crea la contrasena del panel' : 'Contrasena') . "' autofocus required>
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

// ---------- Vistas ----------

$logoFile = $root . '/assets/logo.jpg';
$logo     = is_file($logoFile) ? 'data:image/jpeg;base64,' . base64_encode(file_get_contents($logoFile)) : '';

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
  el.innerHTML = (s.targets||[]).map(t=>{
    let pills='',big='',links='',note='';
    if(t.counts){pills='<div class="pills">'+sev.map(k=>icon[k]+' '+(t.counts[k]||0)).join(' &nbsp;')+'</div>';}
    if(t.status){const cls=t.status==='SEGURO'?'ok':(t.status==='AMENAZA DETECTADA'?'bad':'warn');
      big='<div class="status-big '+cls+'">🛡️ '+t.status+'</div>';}
    if(t.note)note='<div class="note">'+t.note+'</div>';
    if(t.html)links+='<a href="/report?id='+id+'&f='+t.html+'" target="_blank">📄 Informe HTML</a>';
    if(t.txt)links+='<a href="/report?id='+id+'&f='+t.txt+'" target="_blank">🖥️ Salida consola</a>';
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
    </div>
    <div class="row"><button class="btn sm" type="submit">Guardar</button></div>
    <div class="note">ntfy.sh: crea un topico unico y suscribete desde la app del movil (gratis, sin cuenta). Telegram: crea un bot con @BotFather. Webhook: recibe JSON con target+status+counts.</div>
  </form>
</div>

<div class="card"><h2>📋 Auditorias anteriores</h2>$jobsHtml</div>
<script>if('serviceWorker' in navigator)navigator.serviceWorker.register('/sw.js').catch(()=>{});</script>
</div></body></html>
HTML;
return true;
