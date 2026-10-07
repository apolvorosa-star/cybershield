<?php
/**
 * CyberShield - RemoteFixer
 *
 * "Fix rapido" sin IA sobre FTP — equivalente remoto de Repair::run():
 *   1) .htaccess del docroot: niega dotfiles, .env, dumps, instaladores,
 *      listados y anade cabeceras de seguridad (idempotente, con backup)
 *   2) Mueve a _cs_cuarentena/sensibles/ los ficheros peligrosos del docroot
 *      (*.sql, *.bak, *.zip, install.php, phpinfo.php…) respetando whitelist
 *   3) .htaccess anti-ejecucion en carpetas de subidas (uploads, descargas…)
 *
 * No reescribe codigo fuente: eso es trabajo de fixauto + AiFixer.
 * Las acciones se devuelven como lista para pintarlas en el panel o
 * guardarlas en el log del job.
 */

namespace Orizon\CyberShield;

class RemoteFixer
{
    /**
     * Ejecuta los fixes rapidos sobre el servidor remoto.
     *
     * @param array $conn conn FTP de la ficha (pass ya descifrada)
     * @param string $siteUrl URL del objetivo (para scopes de whitelist)
     * @return list<array{accion:string, ok:bool, detalle:string}>
     */
    public static function quickFixes(array $conn, string $siteUrl = ''): array
    {
        $dr = rtrim(str_replace('\\', '/', (string) ($conn['docroot'] ?? '')), '/');
        if ($dr === '') {
            return [['accion' => 'fix rapido', 'ok' => false, 'detalle' => 'el objetivo no tiene docroot FTP']];
        }
        $wl   = Whitelist::rules($conn);
        $quar = "$dr/_cs_cuarentena";
        $out  = [];

        // ---------- 1. .htaccess del docroot ----------
        $htPath = "$dr/.htaccess";
        $ht = RemoteAudit::ftpDownload($conn, $htPath);
        $ht = is_string($ht) ? $ht : '';
        if (strpos($ht, 'CyberShield') !== false) {
            $out[] = ['accion' => '.htaccess docroot', 'ok' => true, 'detalle' => 'ya contiene reglas CyberShield'];
        } else {
            if ($ht !== '') {
                RemoteAudit::ftpUpload($conn, $quar . '/htaccess-backup-' . date('Ymd-His'), $ht);
            }
            $ok = RemoteAudit::ftpUpload($conn, $htPath, $ht . self::htaccessBlock());
            $out[] = [
                'accion'  => '.htaccess docroot',
                'ok'      => $ok,
                'detalle' => $ok
                    ? 'niega .env/.git/.sql/.bak/.zip, instaladores y listados + cabeceras'
                    : 'fallo FTP al subir .htaccess',
            ];
        }

        // ---------- 2. Cuarentena de ficheros peligrosos ----------
        // .env y wp-config NO se mueven (PHP puede leerlos por filesystem;
        // ya quedan bloqueados via .htaccess). Solo nivel raiz del docroot.
        $moveExts  = ['sql', 'bak', 'old', 'orig', 'dump', 'zip', 'tar', 'gz', 'tgz', 'log', 'swp', '7z'];
        $moveNames = ['install.php', 'installer.php', 'setup.php', 'phpinfo.php', 'info.php', 'test.php',
                      'create_admin.php', 'reset_admin.php', 'database.sql', 'dump.sql', 'tabla.bd.txt'];
        $entries = RemoteAudit::ftpList($conn, $dr);
        if ($entries === null) {
            $out[] = ['accion' => 'listar docroot', 'ok' => false, 'detalle' => 'ftp_nlist fallo'];
        } else {
            $moved = 0;
            foreach ($entries as $name) {
                $low  = strtolower($name);
                $ext  = strtolower(pathinfo($name, PATHINFO_EXTENSION));
                $hit  = in_array($ext, $moveExts, true) || in_array($low, $moveNames, true);
                if (!$hit || Whitelist::isProtectedName($name)) continue;
                if (RemoteAudit::ftpSize($conn, "$dr/$name") < 0) continue; // es directorio o no existe
                if (Whitelist::check($wl, "$dr/$name", $conn, $siteUrl)) {
                    $out[] = ['accion' => "cuarentena $name", 'ok' => true, 'detalle' => 'en whitelist — se conserva'];
                    continue;
                }
                $ok = RemoteAudit::ftpMove($conn, "$dr/$name", "$quar/sensibles/$name");
                $out[] = [
                    'accion'  => "cuarentena $name",
                    'ok'      => $ok,
                    'detalle' => $ok ? "movido a _cs_cuarentena/sensibles/" : 'no se pudo mover',
                ];
                if ($ok) $moved++;
            }
            if ($moved === 0 && !$out) {
                $out[] = ['accion' => 'cuarentena', 'ok' => true, 'detalle' => 'no habia ficheros peligrosos sueltos'];
            }
        }

        // ---------- 3. Carpetas de subidas: sin ejecucion de PHP ----------
        // Sin php_flag (rompe en PHP-FPM/CGI): FilesMatch deny funciona siempre.
        $dirs = ['uploads', 'downloads', 'descargas', 'descargas/data', 'media', 'files', 'storage'];
        $rootEntries = $entries ?? RemoteAudit::ftpList($conn, $dr) ?? [];
        foreach ($dirs as $d) {
            $first = explode('/', $d)[0];
            if (!in_array($first, $rootEntries, true)) continue; // la carpeta no existe
            if (Whitelist::check($wl, "$dr/$d/", $conn, $siteUrl)) continue;
            $ok = RemoteAudit::ftpUpload($conn, "$dr/$d/.htaccess", self::noExecBlock($d !== '_cs_cuarentena'));
            $out[] = [
                'accion'  => "proteger $d/",
                'ok'      => $ok,
                'detalle' => $ok ? 'PHP/scripts denegados en la carpeta' : 'fallo FTP',
            ];
        }
        // Cuarentena: denegar TODO (los .bak/.sql movidos no deben ser legibles por web)
        RemoteAudit::ftpUpload($conn, "$quar/.htaccess", "Require all denied\nDeny from all\n");

        return $out;
    }

    /** Bloque de reglas para el .htaccess del docroot (igual que Repair::hardenHtaccess, sin php_flag). */
    private static function htaccessBlock(): string
    {
        return <<<HTA

# ============ CyberShield — reglas de seguridad ============
# Directorios sin listado
Options -Indexes

# Carpetas/archivos ocultos (.git, .env, _cs_cuarentena…)
# excluyendo .well-known (Let's Encrypt)
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteRule (^|/)\.(?!well-known) - [F,L]
</IfModule>
<FilesMatch "^\.">
    Require all denied
</FilesMatch>

# Archivos sensibles: dumps, backups, logs, credenciales
<FilesMatch "\.(sql|bak|old|orig|swp|save|dump|log|ini|sh|env|md|yml|yaml|lock|dist|inc)$">
    Require all denied
</FilesMatch>

# Scripts de instalacion/admin tipicos (por si quedan)
<FilesMatch "^(install|installer|setup|create_admin|reset_admin|phpinfo|info|test)\d*\.php$">
    Require all denied
</FilesMatch>

# Cabeceras de seguridad
<IfModule mod_headers.c>
    Header set X-Content-Type-Options "nosniff"
    Header set X-Frame-Options "SAMEORIGIN"
    Header set X-XSS-Protection "1; mode=block"
    Header set Referrer-Policy "strict-origin-when-cross-origin"
    Header unset X-Powered-By
</IfModule>
# =============== fin reglas CyberShield ===============

HTA;
    }

    /** .htaccess para carpetas de subidas: nada de codigo ejecutable. */
    private static function noExecBlock(bool $onlyCode): string
    {
        if (!$onlyCode) {
            return "# CyberShield: cuarentena, denegar todo\nRequire all denied\nDeny from all\n";
        }
        return <<<HTA
# CyberShield: carpeta de subidas — nada de codigo ejecutable
Options -ExecCGI
<FilesMatch "\.(php|phtml|php3|php4|php5|php7|phar|cgi|pl|asp|aspx|jsp|sh)$">
    Require all denied
    Deny from all
</FilesMatch>
HTA;
    }
}
