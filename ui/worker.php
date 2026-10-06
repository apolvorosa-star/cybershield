<?php
/**
 * CyberShield UI — worker en segundo plano.
 * Lanzado por index.php con: php worker.php <jobDir>
 * Ejecuta las auditorias de job.json una a una y va volcando status.json.
 * Soporta: auditoria local (all/log/web) y remota (agent-ssh / agent-ftp).
 */

// Autoload de las clases (Composer si existe, si no manual)
$autoloadFound = false;
foreach ([
    dirname(__DIR__) . '/vendor/autoload.php',
    dirname(__DIR__, 3) . '/autoload.php',
] as $autoload) {
    if (is_file($autoload)) { require_once $autoload; $autoloadFound = true; break; }
}
if (!$autoloadFound) {
    foreach (glob(dirname(__DIR__) . '/src/*.php') ?: [] as $f) {
        if (basename($f) !== 'cli.php') require_once $f;
    }
}

use Orizon\CyberShield\AgentBuilder;
use Orizon\CyberShield\RemoteAudit;
use Orizon\CyberShield\Report;

$jobDir = $argv[1] ?? '';
if (!is_dir($jobDir)) exit(1);

$root     = dirname(__DIR__);
$cli      = $root . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . 'cybershield';
$jobsRoot = dirname($jobDir);
$job      = json_decode((string) file_get_contents($jobDir . '/job.json'), true);
if (!$job || empty($job['targets'])) exit(1);

$settings  = json_decode((string) @file_get_contents("$jobsRoot/settings.json"), true) ?: [];
$alertsFile = $jobsRoot . '/alerts.json';

$save = function (array $status) use ($jobDir): void {
    file_put_contents($jobDir . '/status.json', json_encode($status, JSON_UNESCAPED_UNICODE));
};

$alert = function (array $t, array $result) use ($alertsFile, $settings): void {
    $status = $result['status'] ?? '';
    if ($status === 'SEGURO' || $status === '') return;
    $alerts = json_decode((string) @file_get_contents($alertsFile), true) ?: [];
    $alerts[] = [
        'time'    => date('Y-m-d H:i'),
        'target'  => $t['target'],
        'status'  => $status,
        'counts'  => $result['counts'] ?? [],
    ];
    file_put_contents($alertsFile, json_encode($alerts, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));

    // Push opcional via ntfy.sh (configurar en el panel)
    if (!empty($settings['ntfy'])) {
        $c = $result['counts'] ?? [];
        $body = "{$t['target']}\n$status — 🔴{$c['critical']} 🟠{$c['high']} 🟡{$c['medium']}";
        $ctx = stream_context_create(['http' => [
            'method' => 'POST', 'timeout' => 8,
            'header' => "Title: CyberShield: " . $status . "\r\nPriority: high\r\n",
            'content' => $body,
        ]]);
        @file_get_contents(rtrim($settings['ntfy'], '/'), false, $ctx);
    }
};

$status = ['state' => 'running', 'targets' => []];
foreach ($job['targets'] as $i => $t) {
    $status['targets'][$i] = ['target' => $t['target'], 'mode' => $t['mode'], 'state' => 'queued'];
}
$save($status);

foreach ($job['targets'] as $i => $t) {
    $status['targets'][$i]['state'] = 'running';
    $save($status);

    $json = "$jobDir/t$i.json";
    $html = "$jobDir/t$i.html";
    $txt  = "$jobDir/t$i.txt";
    $result = null;

    if (in_array($t['mode'], ['agent-ssh', 'agent-ftp'], true)) {
        // ---- Auditoria remota con agente ----
        $token = bin2hex(random_bytes(16));
        $conn  = $t['conn'] ?? [];
        $agent = AgentBuilder::code($token);
        $r = $t['mode'] === 'agent-ssh'
            ? RemoteAudit::viaSsh($conn, $agent, $token, $conn['docroot'] ?? '/var/www/html')
            : RemoteAudit::viaFtp($conn, $agent, $token, $t['target']);

        if (isset($r['error'])) {
            file_put_contents($txt, "ERROR: {$r['error']}\n");
            $status['targets'][$i]['state'] = 'error';
            $status['targets'][$i]['note']  = $r['error'];
        } else {
            $result = $r;
            file_put_contents($json, json_encode([
                'target' => $t['target'], 'mode' => $t['mode'],
                'counts' => $r['counts'], 'status' => $r['status'], 'findings' => $r['findings'],
            ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
            file_put_contents($txt, Report::text($r['findings'], $t['target']));
            if (!empty($job['html'])) {
                Report::html($r['findings'], $t['target'], $html, ['files' => $r['files'] ?? 0]);
            }
        }
    } else {
        // ---- Auditoria local/remota por URL (binario cli) ----
        $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($cli)
            . ' ' . $t['mode'] . ' ' . escapeshellarg($t['target'])
            . ' --profile ' . escapeshellarg($job['profile'] ?? 'orizon')
            . ' --json ' . escapeshellarg($json)
            . (!empty($job['html']) ? ' --html ' . escapeshellarg($html) : '')
            . ' > ' . escapeshellarg($txt) . ' 2>&1';
        exec($cmd, $out, $code);
        $result = is_file($json) ? json_decode((string) file_get_contents($json), true) : null;
        $status['targets'][$i]['state'] = ($code === 0) ? 'done' : 'error';
    }

    if ($result) {
        $status['targets'][$i]['state']  = 'done';
        $status['targets'][$i]['counts'] = $result['counts'] ?? null;
        $status['targets'][$i]['status'] = $result['status'] ?? null;
        $alert($t, $result);
    }
    $status['targets'][$i]['html'] = is_file($html) ? "t$i.html" : null;
    $status['targets'][$i]['txt']  = is_file($txt) ? "t$i.txt" : null;
    $save($status);
}

$status['state'] = 'done';
$save($status);
