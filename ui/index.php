<?php
/**
 * CyberShield UI — panel local (router para "php -S").
 * Todo el panel vive aqui: formulario, cola de auditorias e informes.
 * Solo escucha en 127.0.0.1 — es una app local, no un servicio publico.
 */

$root     = dirname(__DIR__);
$jobsRoot = $root . '/informes/ui';
if (!is_dir($jobsRoot) && !@mkdir($jobsRoot, 0777, true)) {
    $jobsRoot = sys_get_temp_dir() . '/cybershield-ui';
    if (!is_dir($jobsRoot)) @mkdir($jobsRoot, 0777, true);
}

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?: '/';

// Estaticos dentro de ui/ se sirven tal cual
if ($path !== '/' && is_file(__DIR__ . $path)) return false;

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');

// ---------- API: estado de un job (polling JS) ----------
if ($path === '/api/status') {
    $id = preg_replace('/[^a-zA-Z0-9_-]/', '', $_GET['id'] ?? '');
    $f  = "$jobsRoot/$id/status.json";
    header('Content-Type: application/json; charset=utf-8');
    echo is_file($f) ? file_get_contents($f) : '{"state":"missing","targets":[]}';
    return true;
}

// ---------- Ver informe / salida de consola ----------
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

// ---------- Lanzar auditoria ----------
if ($path === '/run' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $raw     = trim((string) ($_POST['targets'] ?? ''));
    $targets = array_values(array_filter(array_map('trim', preg_split('/[\r\n,;]+/', $raw))));
    $profile = in_array($_POST['profile'] ?? 'orizon', ['orizon', 'wordpress', 'generic'], true)
        ? $_POST['profile'] : 'orizon';
    $wantHtml = isset($_POST['html']);

    if (!$targets) { header('Location: /?err=1'); return true; }

    $id     = date('Ymd-His') . '-' . bin2hex(random_bytes(3));
    $jobDir = "$jobsRoot/$id";
    mkdir($jobDir, 0777, true);

    $list = [];
    foreach ($targets as $t) {
        $mode = preg_match('#^https?://#i', $t) ? 'web'
              : (preg_match('/\.log$/i', $t) ? 'log' : 'all');
        $list[] = ['target' => $t, 'mode' => $mode];
    }
    file_put_contents("$jobDir/job.json", json_encode([
        'id' => $id, 'profile' => $profile, 'html' => $wantHtml, 'targets' => $list,
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
    file_put_contents("$jobDir/status.json", json_encode(['state' => 'queued', 'targets' => []]));

    // Worker en segundo plano (la peticion vuelve al instante)
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
<title>$title · CyberShield</title>
<style>
*{box-sizing:border-box}body{background:#0a0e1a;color:#e2e8f0;font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:24px}
.wrap{max-width:1100px;margin:auto}
.head{display:flex;align-items:center;gap:16px;padding:20px 24px;background:linear-gradient(135deg,#0a0e1a,#1e1b4b);border:1px solid #312e81;border-radius:14px;margin-bottom:20px}
.head img{width:56px;height:56px;border-radius:10px;object-fit:cover}
h1{margin:0;font-size:20px;letter-spacing:1px}.sub{color:#818cf8;font-size:11px;letter-spacing:2px;text-transform:uppercase}
.card{background:#0f172a;border:1px solid #1e293b;border-radius:14px;padding:22px;margin-bottom:18px}
h2{margin:0 0 14px;font-size:15px;color:#a5b4fc;text-transform:uppercase;letter-spacing:1px}
textarea{width:100%;min-height:110px;background:#0a0e1a;border:1px solid #334155;border-radius:10px;color:#e2e8f0;padding:12px;font-family:Consolas,monospace;font-size:13px;resize:vertical}
select{background:#0a0e1a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;padding:8px 10px}
.row{display:flex;gap:14px;align-items:center;margin-top:14px;flex-wrap:wrap}
.btn{background:#6366f1;color:#fff;border:0;border-radius:10px;padding:11px 26px;font-size:14px;font-weight:700;cursor:pointer;letter-spacing:.5px}
.btn:hover{background:#818cf8}
label.chk{display:flex;gap:8px;align-items:center;color:#94a3b8;font-size:13px;cursor:pointer}
.job{border:1px solid #1e293b;border-radius:10px;padding:12px 16px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;gap:12px}
.job a{color:#a5b4fc;text-decoration:none}.job a:hover{text-decoration:underline}
.muted{color:#64748b;font-size:12px}
.tcard{border:1px solid #1e293b;border-radius:12px;padding:16px;margin-bottom:12px;background:#0a0e1a}
.tcard .tgt{font-family:Consolas,monospace;color:#a5b4fc;font-size:13px;word-break:break-all}
.badge{display:inline-block;padding:3px 10px;border-radius:6px;font-size:11px;font-weight:700;text-transform:uppercase}
.b-web{background:#312e81;color:#c7d2fe}.b-all{background:#134e4a;color:#99f6e4}.b-log{background:#713f12;color:#fde68a}
.b-code{background:#1e3a5f;color:#93c5fd}.b-sys{background:#3b0764;color:#d8b4fe}
.st-queued{color:#94a3b8}.st-running{color:#f59e0b}.st-done{color:#22c55e}.st-error{color:#ef4444}
.pills{font-size:15px;letter-spacing:1px;margin-top:8px}
.status-big{font-weight:700;margin-top:6px}
.links{margin-top:10px}.links a{color:#86efac;font-size:12.5px;margin-right:14px;text-decoration:none}.links a:hover{text-decoration:underline}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#f59e0b;margin-right:6px;animation:p 1s infinite}
@keyframes p{50%{opacity:.3}}
.ok{color:#22c55e}.warn{color:#f59e0b}.bad{color:#ef4444}
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
    let pills='',big='',links='';
    if(t.counts){pills='<div class="pills">'+sev.map(k=>icon[k]+' '+(t.counts[k]||0)).join(' &nbsp;')+'</div>';}
    if(t.status){const cls=t.status==='SEGURO'?'ok':(t.status==='AMENAZA DETECTADA'?'bad':'warn');
      big='<div class="status-big '+cls+'">🛡️ '+t.status+'</div>';}
    if(t.html)links+='<a href="/report?id='+id+'&f='+t.html+'" target="_blank">📄 Informe HTML</a>';
    if(t.txt)links+='<a href="/report?id='+id+'&f='+t.txt+'" target="_blank">🖥️ Salida consola</a>';
    const run=t.state==='running'?'<span class="dot"></span>':'';
    return '<div class="tcard"><div style="display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap">'
      +'<div><span class="badge b-'+t.mode+'">'+t.mode+'</span> <span class="tgt">'+t.target+'</span></div>'
      +'<span class="'+stCls[t.state]+'">'+run+stName[t.state]+'</span></div>'
      +pills+big+(links?'<div class="links">'+links+'</div>':'')+'</div>';
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
$jobs = array_values(array_filter(scandir($jobsRoot) ?: [], fn($d) => $d[0] !== '.'));
rsort($jobs);
$jobsHtml = '';
foreach (array_slice($jobs, 0, 20) as $d) {
    $st = is_file("$jobsRoot/$d/status.json") ? json_decode((string) file_get_contents("$jobsRoot/$d/status.json"), true) : null;
    $n  = count($st['targets'] ?? []);
    $state = $st['state'] ?? '?';
    $cls = $state === 'done' ? 'ok' : ($state === 'running' || $state === 'queued' ? 'warn' : 'bad');
    $jobsHtml .= "<div class='job'><div><a href='/job?id=$d'>$d</a> <span class='muted'>· $n objetivo(s)</span></div><span class='$cls'>$state</span></div>";
}
if (!$jobsHtml) $jobsHtml = "<div class='muted'>Sin auditorias todavia. Lanza la primera arriba.</div>";

$err = isset($_GET['err']) ? "<div class='card' style='border-color:#ef4444;color:#fca5a5'>Escribe al menos una web o ruta a auditar.</div>" : '';

echo head('Panel', $logo);
echo <<<HTML
<div class="card">
  <h2>Nueva auditoria</h2>
  <form method="post" action="/run">
    <textarea name="targets" placeholder="Una por linea (webs, carpetas o logs):
https://mi-dominio.com
https://otraweb.com
C:\xampp\htdocs\mi-web
/var/log/apache2/access.log"></textarea>
    <div class="row">
      <label class="chk" style="color:#94a3b8">Perfil <select name="profile">
        <option value="orizon">orizon</option>
        <option value="wordpress">wordpress</option>
        <option value="generic">generic</option>
      </select></label>
      <label class="chk"><input type="checkbox" name="html" checked> Generar informe HTML</label>
      <button class="btn" type="submit">🛡️ Auditar</button>
    </div>
    <div class="muted" style="margin-top:10px">URLs https:// → auditoria remota · carpetas → analisis de codigo + docroot · *.log → analisis de incidentes</div>
  </form>
</div>
$err
<div class="card"><h2>Auditorias anteriores</h2>$jobsHtml</div>
</div></body></html>
HTML;
return true;
