<?php
/**
 * CyberShield - WebAudit
 *
 * Auditoria remota de superficie: peticiones HTTP pasivas contra una URL
 * publica para comprobar lo que un atacante probaria primero:
 * archivos sensibles accesibles (.env, .git, backups), directorios con
 * listado y cabeceras de seguridad ausentes.
 *
 * Sin exploits ni payloads: solo GETs de lectura, como haria un navegador.
 */

namespace Orizon\CyberShield;

class WebAudit
{
    private const SEV_ORDER = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4];

    private array $findings = [];
    private string $base = '';
    public int $testedPaths = 0;

    // ruta => [severidad, regex para confirmar que el contenido es real (no un 404 disfrazado de 200)]
    private const PATHS = [
        '/.env'                => ['critical', '/^[A-Z_][A-Z0-9_]*\s*=/m'],
        '/.env.backup'         => ['critical', '/^[A-Z_][A-Z0-9_]*\s*=/m'],
        '/.env.old'            => ['critical', '/^[A-Z_][A-Z0-9_]*\s*=/m'],
        '/.git/HEAD'           => ['high',     '/^ref:/'],
        '/.git/config'         => ['high',     '/\[core\]/'],
        '/.svn/entries'        => ['medium',   '/^\d/'],
        '/composer.json'       => ['medium',   '/"(name|require)"/'],
        '/composer.lock'       => ['low',      '/"packages"/'],
        '/.htpasswd'           => ['high',     '/^[\w.-]+:/m'],
        '/.htaccess'           => ['low',      '/(RewriteRule|Require|Deny|Order|Options)/i'],
        '/web.config'          => ['low',      '/<configuration/i'],
        '/config.php.bak'      => ['high',     '/<\?php|\$|DB_/i'],
        '/wp-config.php.bak'   => ['high',     '/(DB_NAME|DB_PASSWORD)/'],
        '/wp-config.php~'      => ['high',     '/(DB_NAME|DB_PASSWORD)/'],
        '/backup.sql'          => ['high',     '/(CREATE TABLE|INSERT INTO|DROP TABLE|-- MySQL|-- PostgreSQL)/i'],
        '/database.sql'        => ['high',     '/(CREATE TABLE|INSERT INTO|DROP TABLE|-- MySQL|-- PostgreSQL)/i'],
        '/dump.sql'            => ['high',     '/(CREATE TABLE|INSERT INTO|DROP TABLE|-- MySQL|-- PostgreSQL)/i'],
        '/db.sql'              => ['high',     '/(CREATE TABLE|INSERT INTO|DROP TABLE|-- MySQL|-- PostgreSQL)/i'],
        '/phpinfo.php'         => ['medium',   '/(phpinfo|PHP Version)/i'],
        '/info.php'            => ['medium',   '/(phpinfo|PHP Version)/i'],
        '/server-status'       => ['medium',   '/(Apache Status|Server Status|Server uptime)/i'],
        '/.DS_Store'           => ['low',      '/Bud1/'],
        '/.idea/workspace.xml' => ['low',      '/<project/i'],
    ];

    // cabeceras de seguridad esperadas en la respuesta principal
    private const SECURITY_HEADERS = [
        'x-content-type-options' => ['low',  'Falta X-Content-Type-Options: nosniff — el navegador puede "adivinar" MIME y ejecutar contenido inesperado.'],
        'x-frame-options'        => ['low',  'Falta X-Frame-Options / CSP frame-ancestors — la web puede embeberse en iframes ajenos (clickjacking).'],
        'strict-transport-security' => ['low', 'Falta Strict-Transport-Security — sin HSTS, un atacante en la red puede forzar HTTP plano.'],
        'referrer-policy'        => ['info', 'Falta Referrer-Policy — las URLs internas pueden filtrarse a terceros en el header Referer.'],
        'content-security-policy' => ['info','Falta Content-Security-Policy — la defensa en profundidad contra XSS queda solo en el escape manual.'],
    ];

    public function audit(string $url): array
    {
        $this->findings = [];
        $this->testedPaths = 0;
        $this->base = rtrim($url, '/');

        $home = $this->request($this->base . '/');
        if ($home['status'] === 0) {
            $this->add('unreachable', 'info', $this->base,
                'No se pudo conectar con la URL (DNS, puerto cerrado o TLS fallido).',
                'Comprueba que la URL responde en un navegador y que es accesible desde aqui.');
            return $this->findings;
        }

        // Un redirect inicial (HTTP->HTTPS, www, etc.) no es exposicion: seguimos el destino final
        if (in_array($home['status'], [301, 302, 303, 307, 308], true)
            && isset($home['headers']['location'])
            && preg_match('#^https?://#i', $home['headers']['location'])) {
            $this->base = rtrim($home['headers']['location'], '/');
            echo "  → Redirige a {$this->base} — auditando el destino final\n";
            $home = $this->request($this->base . '/');
        }

        $this->checkHeaders($home);

        foreach (self::PATHS as $path => [$sev, $verify]) {
            usleep(40000);
            $r = $this->request($this->base . $path);
            $this->testedPaths++;
            if ($r['status'] !== 200 || $r['body'] === '') continue;
            if (!preg_match($verify, $r['body'])) continue; // 200 suave / pagina de error custom
            $this->reportExposed($path, $sev);
        }

        usort($this->findings, fn($a, $b) => self::SEV_ORDER[$a['severity']] <=> self::SEV_ORDER[$b['severity']]);
        return $this->findings;
    }

    // ---- peticion HTTP (curl si esta, streams si no) ----
    private function request(string $url): array
    {
        if (extension_loaded('curl')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER         => true,
                CURLOPT_NOBODY         => false,
                CURLOPT_TIMEOUT        => 10,
                CURLOPT_CONNECTTIMEOUT => 6,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => 0,
                CURLOPT_USERAGENT      => 'CyberShield-AI/1.0 (Orizon Studio; defensive audit)',
            ]);
            $raw = curl_exec($ch);
            if ($raw === false) { curl_close($ch); return ['status' => 0, 'headers' => [], 'body' => '']; }
            $hsz   = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $code  = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            curl_close($ch);
            $head = substr($raw, 0, $hsz);
            $body = substr(substr($raw, $hsz), 0, 32768);
            return ['status' => $code, 'headers' => $this->parseHeaders($head), 'body' => $body];
        }

        $ctx = stream_context_create([
            'http' => ['method' => 'GET', 'timeout' => 10, 'ignore_errors' => true,
                       'follow_location' => 0, 'user_agent' => 'CyberShield-AI/1.0 (Orizon Studio; defensive audit)'],
            'ssl'  => ['verify_peer' => false, 'verify_peer_name' => false],
        ]);
        $body = @file_get_contents($url, false, $ctx);
        $headers = $this->parseHeaders(implode("\n", $http_response_header ?? []));
        $status = 0;
        if (isset($http_response_header[0]) && preg_match('/\s(\d{3})\s/', $http_response_header[0], $m)) {
            $status = (int) $m[1];
        }
        return ['status' => $status, 'headers' => $headers, 'body' => substr((string) $body, 0, 32768)];
    }

    private function parseHeaders(string $raw): array
    {
        $out = [];
        foreach (preg_split('/\r?\n/', $raw) as $line) {
            if (strpos($line, ':') !== false) {
                [$k, $v] = explode(':', $line, 2);
                $out[strtolower(trim($k))] = trim($v);
            }
        }
        return $out;
    }

    // ---- cabeceras y fingerprint ----
    private function checkHeaders(array $home): void
    {
        $h = $home['headers'];
        $isHttps = str_starts_with($this->base, 'https://');

        if (!$isHttps) {
            $this->add('no-https', 'low', $this->base . '/',
                'La web responde por HTTP plano: credenciales, cookies y datos de formularios viajan sin cifrar.',
                'Instala un certificado (Let\'s Encrypt es gratis) y redirige todo HTTP→HTTPS.');
        }

        foreach (self::SECURITY_HEADERS as $name => [$sev, $risk]) {
            if ($name === 'strict-transport-security' && !$isHttps) continue; // HSTS solo aplica a HTTPS
            if ($name === 'x-frame-options' && isset($h['content-security-policy'])
                && stripos($h['content-security-policy'], 'frame-ancestors') !== false) continue;
            if (!isset($h[$name])) {
                $this->add('missing-header', $sev, $this->base . '/', $risk,
                    'Anade la cabecera en .htaccess (mod_headers) o en la configuracion de Nginx/Apache.');
            }
        }

        if (isset($h['server']) && preg_match('#/\d#', $h['server'])) {
            $this->add('server-version', 'info', $this->base . '/',
                "La cabecera Server anuncia la version exacta ({$h['server']}). Facilita buscar exploits conocidos.",
                'Oculta la version: ServerTokens Prod (Apache) / server_tokens off (Nginx).');
        }
        if (isset($h['x-powered-by'])) {
            $this->add('x-powered-by', 'info', $this->base . '/',
                "X-Powered-By revela la tecnologia ({$h['x-powered-by']}).",
                'Quitala: expose_php=Off en php.ini o Header unset X-Powered-By.');
        }
    }

    private function reportExposed(string $path, string $sev): void
    {
        $messages = [
            'critical' => 'Archivo de credenciales accesible desde Internet. Cualquiera puede descargar tus claves AHORA MISMO.',
            'high'     => 'Archivo sensible accesible publicamente: permite reconstruir codigo, base de datos o credenciales.',
            'medium'   => 'Archivo interno accesible publicamente: revela estructura, dependencias o configuracion del servidor.',
            'low'      => 'Archivo de configuracion/listado visible publicamente.',
        ];
        $name = ltrim($path, '/');
        $fix = str_contains($path, '.git')
            ? 'Deniega /.git en el servidor web (RedirectMatch 404 /\\.git) y revisa si hubo fugas de codigo.'
            : "Borra $name del docroot o deniega su acceso con .htaccess (Require all denied).";
        $this->add('exposed-remote', $sev, $this->base . $path, $messages[$sev], $fix);
    }

    private function add(string $rule, string $sev, string $file, string $risk, string $fix): void
    {
        $this->findings[] = [
            'rule' => $rule, 'severity' => $sev, 'file' => $file, 'line' => 0,
            'code' => $file, 'risk' => $risk, 'fix' => $fix,
        ];
    }
}
