<?php
/**
 * CyberShield - RemoteAudit
 *
 * Audita un servidor remoto "de verdad" (codigo incluido), subiendo el
 * agente efimero de AgentBuilder con auth HMAC (timestamp + firma):
 *
 *  - SSH:  scp del agente a /tmp + ejecucion por CLI (php agent.php).
 *          Nada queda expuesto por HTTP. Requiere llave (OpenSSH no
 *          acepta password por linea de comandos).
 *  - FTP:  sube el agente al docroot, lo ejecuta via HTTPS firmado
 *          y lo borra. Para hosting compartido sin SSH.
 */

namespace Orizon\CyberShield;

class RemoteAudit
{
    /**
     * conn: host, user, port(22), key(ruta a llave privada, opcional)
     * docroot: ruta absoluta en el servidor (p.ej. /var/www/html)
     */
    public static function viaSsh(array $conn, string $secret, string $docroot): array
    {
        $ts  = time();
        $sig = hash_hmac('sha256', (string) $ts, $secret);

        $tmp = tempnam(sys_get_temp_dir(), 'csa') . '.php';
        file_put_contents($tmp, AgentBuilder::code($secret));
        $remote = '/tmp/cybershield-agent-' . substr($sig, 0, 12) . '.php';
        $port   = (int) ($conn['port'] ?? 22) ?: 22;
        $keyOpt = !empty($conn['key']) ? ' -i ' . escapeshellarg($conn['key']) : '';
        $host   = escapeshellarg(($conn['user'] ?? 'root') . '@' . $conn['host']);
        $base   = '-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new' . $keyOpt;

        exec("scp $base -P $port " . escapeshellarg($tmp) . " $host:" . escapeshellarg($remote) . " 2>&1", $o1, $c1);
        @unlink($tmp);
        if ($c1 !== 0) {
            return ['error' => 'No se pudo subir el agente por SSH: ' . implode(' ', $o1)
                . ' (recuerda: SSH requiere llave configurada, password no soportado)'];
        }

        $cmd = escapeshellarg("php $remote " . escapeshellarg((string) $ts) . ' ' . escapeshellarg($sig) . ' ' . escapeshellarg($docroot));
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
    public static function viaFtp(array $conn, string $secret, string $url): array
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

        $name  = 'cybershield-agent-' . substr(hash_hmac('sha256', (string) time(), $secret), 0, 12) . '.php';
        $tmp   = tempnam(sys_get_temp_dir(), 'csa') . '.php';
        file_put_contents($tmp, AgentBuilder::code($secret));
        $ok = @ftp_put($ftp, $name, $tmp, FTP_BINARY);
        @unlink($tmp);
        if (!$ok) { ftp_close($ftp); return ['error' => "No se pudo subir $name al docroot remoto"]; }

        // Ejecutar via HTTP con firma HMAC (timestamp dentro de ventana de 5 min)
        $ts  = time();
        $sig = hash_hmac('sha256', (string) $ts, $secret);
        $agentUrl = rtrim($url, '/') . '/' . $name . '?t=' . $ts . '&sig=' . $sig;
        $resp = self::httpGet($agentUrl);

        // Borrado doble: el agente se autodestruye + ftp_delete por si acaso
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
                CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 130,
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
            'http' => ['timeout' => 130, 'ignore_errors' => true,
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
