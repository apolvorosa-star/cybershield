<?php
/**
 * CyberShield - Whitelist
 *
 * Reglas que protegen ficheros de la reparacion/cuarentena automatica.
 * Las usan Repair (local), fixauto y RemoteFixer (remoto FTP).
 *
 * Fuentes: <paquete>/whitelist.dist.txt + <paquete>/whitelist.txt +
 *          <docroot remoto>/.cybershield-whitelist (bajada por FTP).
 *
 * Formato por linea:  <scope>|<patron>   o solo   <patron>  (* = fnmatch)
 *   - sin scope -> aplica a cualquier objetivo
 *   - scope X   -> aplica si X aparece en el docroot/URL/host del objetivo
 *                  (vale tanto ruta completa "C:/xampp/..." como dominio
 *                  "orizonstudio.cloud")
 */

namespace Orizon\CyberShield;

class Whitelist
{
    /** @return list<array{scope:string, pattern:string}> */
    public static function rules(?array $conn = null): array
    {
        $raw = '';
        foreach ([
            dirname(__DIR__) . '/whitelist.dist.txt',
            dirname(__DIR__) . '/whitelist.txt',
        ] as $wf) {
            if (is_file($wf)) {
                $raw .= (string) file_get_contents($wf) . "\n";
            }
        }
        if ($conn && !empty($conn['docroot'])) {
            $remote = RemoteAudit::ftpDownload(
                $conn,
                rtrim((string) $conn['docroot'], '/') . '/.cybershield-whitelist'
            );
            if (is_string($remote)) {
                $raw .= $remote;
            }
        }
        $rules = [];
        foreach (preg_split('/\r?\n/', (string) $raw) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            $scope = '';
            $pat = $line;
            if (strpos($line, '|') !== false) {
                [$scope, $pat] = array_map('trim', explode('|', $line, 2));
            }
            $rules[] = [
                'scope'   => strtolower(rtrim(str_replace('\\', '/', $scope), '/')),
                'pattern' => str_replace('\\', '/', $pat),
            ];
        }
        return $rules;
    }

    /**
     * ¿Esta ruta (remota FTP o local) protegida por whitelist?
     * $siteUrl = URL del objetivo, para scopes tipo "orizonstudio.cloud".
     */
    public static function check(array $rules, string $path, ?array $conn = null, string $siteUrl = ''): bool
    {
        $dr  = rtrim(str_replace('\\', '/', (string) ($conn['docroot'] ?? '')), '/');
        $p   = str_replace('\\', '/', $path);
        $rel = $p;
        if ($dr !== '' && str_starts_with($p, $dr . '/')) {
            $rel = substr($p, strlen($dr) + 1);
        }
        $rel = ltrim($rel, '/');
        $hay = strtolower($dr . ' ' . $siteUrl . ' ' . (string) ($conn['host'] ?? ''));
        foreach ($rules as $w) {
            if ($w['scope'] !== '' && strpos($hay, $w['scope']) === false) {
                continue;
            }
            if (fnmatch($w['pattern'], $rel, FNM_CASEFOLD)
                || fnmatch($w['pattern'], basename($rel), FNM_CASEFOLD)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Ficheros que la reparacion automatica NUNCA reescribe ni mueve:
     * secretos y config se protegen via .htaccess, no se tocan.
     */
    public static function isProtectedName(string $path): bool
    {
        $b = strtolower(basename(str_replace('\\', '/', $path)));
        if (in_array($b, ['wp-config.php', '.htaccess', '.htpasswd', 'config.local.php', 'config.php'], true)) {
            return true;
        }
        return (bool) fnmatch('.env*', $b, FNM_CASEFOLD);
    }
}
