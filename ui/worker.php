<?php
/**
 * CyberShield UI — worker en segundo plano.
 * Lanzado por index.php con: php worker.php <jobDir>
 * Ejecuta las auditorias de job.json una a una y va volcando status.json.
 */

$jobDir = $argv[1] ?? '';
if (!is_dir($jobDir)) exit(1);

$root = dirname(__DIR__);
$cli  = $root . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . 'cybershield';
$job  = json_decode((string) file_get_contents($jobDir . '/job.json'), true);
if (!$job || empty($job['targets'])) exit(1);

$save = function (array $status) use ($jobDir): void {
    file_put_contents($jobDir . '/status.json', json_encode($status, JSON_UNESCAPED_UNICODE));
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

    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($cli)
        . ' ' . $t['mode'] . ' ' . escapeshellarg($t['target'])
        . ' --profile ' . escapeshellarg($job['profile'] ?? 'orizon')
        . ' --json ' . escapeshellarg($json)
        . (!empty($job['html']) ? ' --html ' . escapeshellarg($html) : '')
        . ' > ' . escapeshellarg($txt) . ' 2>&1';

    exec($cmd, $out, $code);

    $r = is_file($json) ? json_decode((string) file_get_contents($json), true) : null;
    $status['targets'][$i]['state']  = ($code === 0) ? 'done' : 'error';
    $status['targets'][$i]['counts'] = $r['counts'] ?? null;
    $status['targets'][$i]['status'] = $r['status'] ?? null;
    $status['targets'][$i]['html']   = is_file($html) ? "t$i.html" : null;
    $status['targets'][$i]['txt']    = is_file($txt) ? "t$i.txt" : null;
    $save($status);
}

$status['state'] = 'done';
$save($status);
