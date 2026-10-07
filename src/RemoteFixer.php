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
        // Con verificacion HTTP: si el hosting rechaza alguna directiva
        // (Options no permitido, mod_* ausente…) la web entera da 500 —
        // en ese caso se restaura el .htaccess original al momento.
        $htPath = "$dr/.htaccess";
        $ht = RemoteAudit::ftpDownload($conn, $htPath);
        $ht = is_string($ht) ? $ht : '';
        if (strpos($ht, 'CyberShield') !== false) {
            $out[] = ['accion' => '.htaccess docroot', 'ok' => true, 'detalle' => 'ya contiene reglas CyberShield'];
        } else {
            if ($ht !== '') {
                RemoteAudit::ftpUpload($conn, $quar . '/htaccess-backup-' . date('Ymd-His'), $ht);
            }
            $before  = $siteUrl !== '' ? RemoteAudit::httpStatus($siteUrl) : 0;
            $detalle = 'fallo FTP al subir .htaccess';
            $ok = RemoteAudit::ftpUpload($conn, $htPath, $ht . self::htaccessBlock());
            if ($ok) {
                $after = $siteUrl !== '' ? RemoteAudit::httpStatus($siteUrl) : 0;
                if ($before > 0 && $before < 500 && $after >= 500) {
                    RemoteAudit::ftpUpload($conn, $htPath, $ht); // restaura el original
                    $ok      = false;
                    $detalle = "el servidor rechazo las reglas (HTTP $after) — .htaccess restaurado";
                } else {
                    $detalle = 'niega .env/.git/.sql/.bak/.zip, instaladores y listados + cabeceras';
                }
            }
            $out[] = ['accion' => '.htaccess docroot', 'ok' => $ok, 'detalle' => $detalle];
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
            $movedNames = [];
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
                if ($ok) { $moved++; $movedNames[] = $name; }
            }
            // Rollback: si la web cae tras mover ficheros (p.ej. un .php
            // que otro fichero incluia), se restauran solos.
            if ($moved > 0 && $siteUrl !== '') {
                $st = RemoteAudit::httpStatus($siteUrl);
                if ($st >= 500) {
                    foreach ($movedNames as $name) {
                        RemoteAudit::ftpMove($conn, "$quar/sensibles/$name", "$dr/$name");
                    }
                    $out[] = ['accion' => 'cuarentena', 'ok' => false,
                              'detalle' => "la web cayo tras mover ficheros (HTTP $st) — restaurados al docroot"];
                }
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
            // Guardia: si la carpeta sirve PHP legitimo (p.ej. descargas/index.php),
            // denegar PHP ahi romperia la web — se salta y se avisa.
            $inside = RemoteAudit::ftpList($conn, "$dr/$d") ?? [];
            $phpInUse = array_filter($inside, fn($n) => (bool) preg_match('/\.(php|phtml|phar)$/i', $n));
            if ($phpInUse) {
                $out[] = [
                    'accion'  => "proteger $d/",
                    'ok'      => true,
                    'detalle' => 'OJO: contiene PHP en uso (' . implode(', ', array_slice($phpInUse, 0, 3)) . ') — no se deniega, revisar a mano',
                ];
                continue;
            }
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
        // Nota: nada de "Options -Indexes" — en hostings sin AllowOverride
        // Options el .htaccess entero da 500. Require/Deny van dentro de
        // IfModule para valer en Apache 2.4 (mod_authz_core) y 2.2 a la vez.
        return <<<HTA

# ============ CyberShield — reglas de seguridad ============
# Carpetas/archivos ocultos (.git, .env, _cs_cuarentena…)
# excluyendo .well-known (Let's Encrypt)
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteRule (^|/)\.(?!well-known) - [F,L]
</IfModule>

# Archivos sensibles: dotfiles, dumps, backups, logs, credenciales
<IfModule mod_authz_core.c>
<FilesMatch "^\.|\.(sql|bak|old|orig|swp|save|dump|log|ini|sh|env|md|yml|yaml|lock|dist|inc)$">
    Require all denied
</FilesMatch>
<FilesMatch "^(install|installer|setup|create_admin|reset_admin|phpinfo|info|test)\d*\.php$">
    Require all denied
</FilesMatch>
</IfModule>
<IfModule !mod_authz_core.c>
<FilesMatch "^\.|\.(sql|bak|old|orig|swp|save|dump|log|ini|sh|env|md|yml|yaml|lock|dist|inc)$">
    Deny from all
</FilesMatch>
<FilesMatch "^(install|installer|setup|create_admin|reset_admin|phpinfo|info|test)\d*\.php$">
    Deny from all
</FilesMatch>
</IfModule>

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
        // Sin "Options -ExecCGI": si AllowOverride no permite Options,
        // el .htaccess entero da 500 y tumba la carpeta. FilesMatch basta.
        return <<<HTA
# CyberShield: carpeta de subidas — nada de codigo ejecutable
<IfModule mod_authz_core.c>
<FilesMatch "\.(php|phtml|php3|php4|php5|php7|phar|cgi|pl|asp|aspx|jsp|sh)$">
    Require all denied
</FilesMatch>
</IfModule>
<IfModule !mod_authz_core.c>
<FilesMatch "\.(php|phtml|php3|php4|php5|php7|phar|cgi|pl|asp|aspx|jsp|sh)$">
    Deny from all
</FilesMatch>
</IfModule>
HTA;
    }
}
