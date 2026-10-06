<?php
/**
 * CyberShield - LogAnalyzer
 *
 * Modo 2: analisis de incidentes en access logs (formato Apache
 * combined/common + nginx por defecto). Clasifica ataques por IP,
 * asigna gravedad y genera respuesta inmediata: reglas de bloqueo
 * (.htaccess / iptables) listas para copiar.
 */

namespace Orizon\CyberShield;

class LogAnalyzer
{
    private const ATTACK_PATTERNS = [
        'sqli' => [
            'label' => 'Inyeccion SQL',
            'severity' => 'critical',
            're' => '/(\%27|\')\s*(or|and)\s+\d|union\s+(all\s+)?select|information_schema|concat\s*\(|sleep\s*\(\s*\d|benchmark\s*\(|into\s+outfile|load_file|updatexml|extractvalue/i',
        ],
        'traversal' => [
            'label' => 'Path Traversal / LFI',
            'severity' => 'critical',
            're' => '/\.\.[\/\\\\]|\.\.\%2f|\%2e\%2e|\/etc\/passwd|\/proc\/self|boot\.ini|win\.ini|php:\/\/|expect:\/\//i',
        ],
        'rce' => [
            'label' => 'Ejecucion remota (RCE)',
            'severity' => 'critical',
            're' => '/eval-stdin|shell\.sh|cmd\.exe|\/bin\/(ba)?sh|\$\{jndi|wget\s|curl\s|chmod\s|certutil|powershell/i',
        ],
        'xss' => [
            'label' => 'XSS en peticion',
            'severity' => 'high',
            're' => '/<script|%3cscript|javascript:|onerror\s*=|onload\s*=|<img|<svg/i',
        ],
        'scanner' => [
            'label' => 'Sondeo de archivos sensibles',
            'severity' => 'high',
            're' => '/\/\.env|\/\.git|\/wp-login|\/xmlrpc\.php|wp-config|\/\.aws|phpmyadmin|\/\.ssh|composer\.(json|lock)|\.sql\b|\.bak\b|\/vendor\/|boaform|\/HNAP1|\/cgi-bin\//i',
        ],
        'bruteforce' => [
            'label' => 'Fuerza bruta (login/admin)',
            'severity' => 'high',
            're' => '/(POST\s+[^ ]*(login|admin|signin|wp-login|xmlrpc))/i',
        ],
    ];

    private const BAD_UA = '/sqlmap|nikto|acunetix|nmap|masscan|nessus|openvas|wpscan|hydra|metasploit|nuclei|zgrab|dirbuster|gobuster|zmeu|morfeus/i';

    private const SEV_ORDER = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3];

    /**
     * Devuelve:
     *  - lines: lineas procesadas
     *  - ips: [ip => ['count','attacks'=>[],'severity','hits'=>int,'samples'=>[]]]
     *  - totals: por categoria
     *  - blocklist: ips a bloquear (severity high|critical)
     *  - htaccess: snippet de bloqueo
     */
    public function analyze(string $logFile, int $maxLines = 200000): array
    {
        $fh = @fopen($logFile, 'r');
        if (!$fh) return ['error' => "No puedo abrir $logFile"];

        $ips = [];
        $totals = array_fill_keys(array_keys(self::ATTACK_PATTERNS), 0);
        $totals['bad_ua'] = 0;
        $lines = 0;
        $re = '/^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(.*?)(?:\s+HTTP[^\s"]*)?"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?/';

        while (($line = fgets($fh)) !== false && $lines < $maxLines) {
            $lines++;
            if (!preg_match($re, trim($line), $m)) continue;
            [$full, $ip, $time, $method, $uri, $status, $size, $ref, $ua] = $m + array_fill(0, 9, '');

            $ips[$ip]['ip'] = $ip;
            $ips[$ip]['count'] = ($ips[$ip]['count'] ?? 0) + 1;
            $ips[$ip]['attacks'] = $ips[$ip]['attacks'] ?? [];
            $ips[$ip]['samples'] = $ips[$ip]['samples'] ?? [];

            $target = rawurldecode($method . ' ' . $uri);
            foreach (self::ATTACK_PATTERNS as $key => $pat) {
                if (preg_match($pat['re'], $target)) {
                    $ips[$ip]['attacks'][$key] = ($ips[$ip]['attacks'][$key] ?? 0) + 1;
                    $totals[$key]++;
                    if (count($ips[$ip]['samples']) < 3) {
                        $ips[$ip]['samples'][] = trim(substr($uri, 0, 160));
                    }
                }
            }
            if ($ua && preg_match(self::BAD_UA, $ua)) {
                $ips[$ip]['attacks']['bad_ua'] = ($ips[$ip]['attacks']['bad_ua'] ?? 0) + 1;
                $ips[$ip]['ua'] = substr($ua, 0, 80);
                $totals['bad_ua']++;
            }
        }
        fclose($fh);

        // Gravedad por IP
        foreach ($ips as &$info) {
            $sev = 'low';
            $att = $info['attacks'];
            if (!empty($att['sqli']) || !empty($att['rce']) || !empty($att['traversal'])) $sev = 'critical';
            elseif (!empty($att['scanner']) && $att['scanner'] >= 5) $sev = 'high';
            elseif (!empty($att['scanner']) || !empty($att['xss']) || !empty($att['bad_ua'])) $sev = 'medium';
            elseif (!empty($att['bruteforce']) && $att['bruteforce'] >= 20) $sev = 'high';
            elseif (!empty($att['bruteforce']) && $att['bruteforce'] >= 5) $sev = 'medium';
            $info['severity'] = $sev;
        }
        unset($info);

        uasort($ips, fn($a, $b) => self::SEV_ORDER[$a['severity']] <=> self::SEV_ORDER[$b['severity']]
            ?: ($b['count'] <=> $a['count']));

        $blocklist = [];
        foreach ($ips as $ip => $info) {
            if (in_array($info['severity'], ['critical', 'high'], true)) $blocklist[] = $ip;
        }

        $htaccess = '';
        if ($blocklist) {
            $htaccess = "# CyberShield - bloqueo automatico\n";
            foreach ($blocklist as $ip) {
                $htaccess .= "Require not ip $ip\n";
            }
        }

        return [
            'lines' => $lines,
            'ips' => $ips,
            'totals' => $totals,
            'blocklist' => $blocklist,
            'htaccess' => $htaccess,
            'file' => $logFile,
        ];
    }
}
