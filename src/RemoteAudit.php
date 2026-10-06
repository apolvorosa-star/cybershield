<?php
/**
 * CyberShield - RemoteAudit
 *
 * Audita un servidor remoto "de verdad" (codigo incluido), subiendo el
 * agente autocontenido generado por AgentBuilder:
 *
 *  - SSH:  scp del agente a /tmp + ejecucion por CLI (php agent.php).
 *          Nada queda expuesto por HTTP. Necesita llave (OpenSSH no
 *          acepta password por linea de comandos).
 *  - FTP:  sube el agente al docroot, lo ejecuta via HTTPS con token
 *          y lo borra. Pensado para hosting compartido sin SSH.
 */

namespace Orizon\CyberShield;

class RemoteAudit
{
    /**
     * conn: host, user, port(22), key(ruta a llave privada, opcional)
     * docroot: ruta absoluta en el servidor (p.ej. /var/www/html)
     */
    public static function viaSsh(array $conn, string $agentCode, string $token, string $docroot): array
    {
        $tmp = tempnam(sys_get_temp_dir(), 'csa') . '.php';
        file_put_contents($tmp, $agentCode);
        $remote = '/tmp/cybershield-agent-' . substr($token, 0, 12) . '.php';
        $port   = (int) ($conn['port'] ?? 22) ?: 22;
        $keyOpt = !empty($conn['key']) ? ' -i ' . escapeshellarg($conn['key']) : '';
        $host   = escapeshellarg(($conn['user'] ?? 'root') . '@' . $conn['host']);

        $base = '-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new' . $keyOpt;

        exec("scp $base -P $port " . escapeshellarg($tmp) . " $host:" . escapeshellarg($remote) . " 2>&1", $o1, $c1);
        @unlink($tmp);
        if ($c1 !== 0) {
            return ['error' => 'No se pudo subir el agente por SSH: ' . implode(' ', $o1)
                . ' (recuerda: SSH requiere llave configurada, password no soportado)'];
        }

        $cmd = escapeshellarg("php " . $remote . ' ' . escapeshellarg($token) . ' ' . escapeshellarg($docroot));
        exec("ssh $base -p $port $host $cmd", $o2, $c2);
        exec("ssh $base -p $port $host " . escapeshellarg("rm -f $remote") . ' 2>&1');

        $json = json_decode(implode("\n", $o2), true);
        if (!is_array($json) || !isset($json['status'])) {
            return ['error' => 'El agente no devolvio JSON valido (¿PHP CLI en el servidor?): ' . substr(implode(' ', $o2), 0, 300)];
        }
        return $json;
    }

    /**
     * conn: host, user, pass, port(21), docroot(ruta FTP donde va el agente)
     * url: URL publica que mapea ese docroot (p.ej. https://midominio.com)
     */
    public static function viaFtp(array $conn, string $agentCode, string $token, string $url): array
    {
        if (!function_exists('ftp_connect')) {
            return ['error' => 'PHP no tiene ext-ftp. Activala en php.ini o usa acceso SSH.'];
        }
        $port = (int) ($conn['port'] ?? 21) ?: 21;
        $ftp = @ftp_connect($conn['host'], $port, 10);
        if (!$ftp) return ['error' => "No se pudo conectar por FTP a {$conn['host']}:$port"];
        if (!@ftp_login($ftp, $conn['user'] ?? '', $conn['pass'] ?? '')) {
            ftp_close($ftp);
            return ['error' => 'Login FTP rechazado (usuario/contraseña)'];
        }
        ftp_pasv($ftp, true);

        $remoteDir = $conn['docroot'] ?? '/';
        if ($remoteDir !== '/' && !@ftp_chdir($ftp, $remoteDir)) {
            ftp_close($ftp);
            return ['error' => "FTP ok pero no existe el directorio remoto '$remoteDir'"];
        }

        $name  = 'cybershield-agent-' . substr($token, 0, 12) . '.php';
        $tmp   = tempnam(sys_get_temp_dir(), 'csa') . '.php';
        file_put_contents($tmp, $agentCode);
        $ok = @ftp_put($ftp, $name, $tmp, FTP_BINARY);
        @unlink($tmp);
        if (!$ok) { ftp_close($ftp); return ['error' => "No se pudo subir $name al docroot remoto"]; }

        // Ejecutar via HTTP con token
        $agentUrl = rtrim($url, '/') . '/' . $name . '?token=' . $token;
        $resp = self::httpGet($agentUrl);

        // Borrar el agente siempre (ademas se autodestruye tras responder)
        @ftp_delete($ftp, $name);
        ftp_close($ftp);

        if ($resp['status'] === 404) {
            return ['error' => 'Agente subido pero la URL no lo alcanza (404): el docroot FTP no mapea a la URL publica'];
        }
        $json = json_decode($resp['body'], true);
        if (!is_array($json) || !isset($json['status'])) {
            return ['error' => 'El agente no devolvio JSON valido (HTTP ' . $resp['status'] . '): ' . substr($resp['body'], 0, 200)];
        }
        return $json;
    }

    private static function httpGet(string $url): array
    {
        if (extension_loaded('curl')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 120,
                CURLOPT_FOLLOWLOCATION => false, CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => 0,
                CURLOPT_USERAGENT => 'CyberShield-AI/1.0 (Orizon Studio)',
            ]);
            $body = curl_exec($ch);
            $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            curl_close($ch);
            return ['status' => $code, 'body' => (string) $body];
        }
        $ctx = stream_context_create([
            'http' => ['timeout' => 120, 'ignore_errors' => true,
                       'user_agent' => 'CyberShield-AI/1.0 (Orizon Studio)'],
            'ssl'  => ['verify_peer' => false, 'verify_peer_name' => false],
        ]);
        $body = @file_get_contents($url, false, $ctx);
        $status = 0;
        if (isset($http_response_header[0]) && preg_match('/\s(\d{3})\s/', $http_response_header[0], $m)) {
            $status = (int) $m[1];
        }
        return ['status' => $status, 'body' => (string) $body];
    }
}
