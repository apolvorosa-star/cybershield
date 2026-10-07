<?php
/**
 * CyberShield - SystemAudit
 *
 * Auditoria del docroot/servidor: archivos sensibles expuestos,
 * instaladores olvidados, carpetas de subida sin proteccion,
 * php.ini inseguro y permisos delicados.
 */

namespace Orizon\CyberShield;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

class SystemAudit
{
    private const SEV_ORDER = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4];

    private array $findings = [];

    private function add(string $rule, string $sev, string $file, string $risk, string $fix): void
    {
        $this->findings[] = [
            'rule' => $rule, 'severity' => $sev, 'file' => $file, 'line' => 0,
            'code' => basename($file), 'risk' => $risk, 'fix' => $fix,
        ];
    }

    public function audit(string $docroot, ?string $phpIni = null): array
    {
        $this->findings = [];
        $docroot = rtrim($docroot, '\\/');

        $this->checkExposedFiles($docroot);
        $this->checkInstallers($docroot);
        $this->checkUploadDirs($docroot);
        $this->checkHtaccess($docroot);
        if ($phpIni !== null && is_file($phpIni)) {
            $this->checkPhpIni($phpIni);
        }

        usort($this->findings, fn($a, $b) => self::SEV_ORDER[$a['severity']] <=> self::SEV_ORDER[$b['severity']]);
        return $this->findings;
    }

    // ---- Archivos sensibles expuestos en el docroot ----
    private function checkExposedFiles(string $dir): void
    {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if (!$f->isFile()) continue;
            $path = $f->getPathname();
            if (strpos(str_replace('\\', '/', $path), '_cs_cuarentena/') !== false
                || strpos($path, '.cybershield-quarantine') !== false) continue;
            $name = strtolower($f->getFilename());
            $rel = substr($path, strlen($dir));
            // Si un .htaccess ya deniega el fichero, no es una exposicion:
            // se informa como info (mitigado) en vez de falso critico.
            $denied = $this->htaccessDenies($path, $dir);

            if (preg_match('/^\.env($|\.)/', $name) || in_array($name, ['credentials.md','credenciales.md','secrets.txt','passwords.txt'], true)) {
                if ($denied) {
                    $this->add('exposed-secret', 'info', $path,
                        'Archivo de credenciales en la web publica, pero ya bloqueado por .htaccess (mitigado).',
                        'Nada que hacer — considera sacarlo del docroot de todos modos.');
                } else {
                    $this->add('exposed-secret', 'critical', $path,
                        'Archivo de credenciales dentro de la web publica. Si es accesible por HTTP, todas tus claves son publicas.',
                        'Sacalo del docroot o deniega el acceso con .htaccess (Require all denied).');
                }
            } elseif (preg_match('/\.(sql|bak|old|orig|swp|save|backup|dump)$/i', $name)) {
                $this->add('exposed-backup', $denied ? 'info' : 'high', $path,
                    $denied
                        ? 'Copia de seguridad dentro del docroot, pero bloqueada por .htaccess (mitigado).'
                        : 'Copia de seguridad o dump dentro del docroot. Puede contener datos y la estructura de la BD.',
                    $denied ? 'Nada que hacer — aun asi, mejor fuera del docroot.' : 'Muevelo fuera de la web o borralo.');
            } elseif (preg_match('/\.(log|txt)$/i', $name) && preg_match('/(error|debug|access|auth|password|log)/i', $name)) {
                $this->add('exposed-log', $denied ? 'info' : 'medium', $path,
                    $denied
                        ? 'Log dentro del docroot, pero bloqueado por .htaccess (mitigado).'
                        : 'Log dentro del docroot: puede revelar rutas, usuarios y errores internos.',
                    'Guarda los logs fuera del docroot.');
            }
            if (strpos($rel, DIRECTORY_SEPARATOR . '.git' . DIRECTORY_SEPARATOR) !== false && $name === 'config') {
                $this->add('exposed-git', $denied ? 'info' : 'high', $path,
                    $denied
                        ? 'Carpeta .git presente, pero bloqueada por .htaccess (mitigado).'
                        : 'Carpeta .git expuesta: cualquiera puede reconstruir el codigo fuente completo.',
                    'Deniega /.git en el servidor web (RedirectMatch 404 /\\.git).');
            }
        }
    }

    /**
     * ¿Deniega un .htaccess el fichero? Recorre los .htaccess del propio
     * directorio hacia arriba hasta el docroot (Apache hereda reglas).
     * Cubre: Require all denied / Deny from all a nivel directorio,
     * <Files>/<FilesMatch> con deny, RedirectMatch 404 y RewriteRule [F].
     */
    private function htaccessDenies(string $file, string $docroot): bool
    {
        $doc = rtrim(str_replace('\\', '/', $docroot), '/');
        $rel = ltrim(substr(str_replace('\\', '/', $file), strlen($doc)), '/');
        $dir = str_replace('\\', '/', dirname($file));
        $base = basename($file);
        while (str_starts_with($dir, $doc)) {
            $hta = $dir . '/.htaccess';
            if (is_file($hta)) {
                $c = (string) @file_get_contents($hta);
                // Denegacion total del directorio (fuera de bloques <Files*>)
                $plain = preg_replace('/<Files(Match)?\b.*?<\/Files\1?>/is', '', $c);
                $plain = preg_replace('/<FilesMatch\b.*?<\/FilesMatch>/is', '', $plain);
                if (preg_match('/(Require\s+all\s+denied|Deny\s+from\s+all)/i', (string) $plain)
                    && !preg_match('/(Require\s+all\s+granted|Allow\s+from\s+all)/i', (string) $plain)) {
                    return true;
                }
                // <FilesMatch "..."> con deny
                if (preg_match_all('/<FilesMatch\s+["\']([^"\']+)["\']\s*>(.*?)<\/FilesMatch>/is', $c, $m, PREG_SET_ORDER)) {
                    foreach ($m as $blk) {
                        if (@preg_match('#' . str_replace('#', '\#', $blk[1]) . '#i', $base)
                            && preg_match('/(Require\s+all\s+denied|Deny\s+from\s+all|RewriteRule)/i', $blk[2])) {
                            return true;
                        }
                    }
                }
                // <Files "..."> con deny (comodines estilo Apache ≈ fnmatch)
                if (preg_match_all('/<Files\s+["\']([^"\']+)["\']\s*>(.*?)<\/Files>/is', $c, $m3, PREG_SET_ORDER)) {
                    foreach ($m3 as $blk) {
                        if (fnmatch($blk[1], $base, FNM_CASEFOLD)
                            && preg_match('/(Require\s+all\s+denied|Deny\s+from\s+all)/i', $blk[2])) {
                            return true;
                        }
                    }
                }
                // RedirectMatch 404 /patron  (p.ej. bloqueo de /.git)
                if (preg_match_all('/RedirectMatch\s+404\s+(\S+)/i', $c, $m2)) {
                    foreach ($m2[1] as $rx) {
                        if (@preg_match('#' . str_replace('#', '\#', trim($rx, '"\'')) . '#i', '/' . $rel)) {
                            return true;
                        }
                    }
                }
            }
            if ($dir === $doc) break;
            $parent = dirname($dir);
            if ($parent === $dir) break;
            $dir = $parent;
        }
        return false;
    }

    // ---- Instaladores olvidados ----
    private function checkInstallers(string $dir): void
    {
        $candidates = ['install.php','installer.php','setup.php','install.sql','_reg_archivo.php','create_admin.php','reset_admin.php','phpinfo.php','test.php','info.php'];
        foreach ($candidates as $c) {
            $found = glob($dir . DIRECTORY_SEPARATOR . $c) ?: [];
            $found = array_merge($found, glob($dir . DIRECTORY_SEPARATOR . '*' . DIRECTORY_SEPARATOR . $c) ?: []);
            foreach ($found as $p) {
                if (strpos(str_replace('\\', '/', $p), '_cs_cuarentena/') !== false
                    || strpos($p, '.cybershield-quarantine') !== false) continue;
                if ($this->htaccessDenies($p, $dir)) {
                    $this->add('installer', 'info', $p,
                        'Script de instalacion presente, pero bloqueado por .htaccess (mitigado).',
                        'Nada urgente — aun asi, mejor borrarlo tras instalar.');
                    continue;
                }
                $this->add('installer', 'medium', $p,
                    'Script de instalacion/administracion accesible en produccion. Si permite reinstalar o crear admins, es una puerta trasera.',
                    'Borralo tras instalar, o protégelo con candado (installed.lock + comprobacion).');
            }
        }
    }

    // ---- Carpetas de subida sin proteccion ----
    private function checkUploadDirs(string $dir): void
    {
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($it as $d) {
            if (!$d->isDir()) continue;
            if (!preg_match('/(uploads?|media|files|storage|data)$/i', $d->getFilename())) continue;
            $path = $d->getPathname();
            $protected = is_file($path . DIRECTORY_SEPARATOR . '.htaccess')
                      || is_file($path . DIRECTORY_SEPARATOR . 'web.config')
                      || is_file($path . DIRECTORY_SEPARATOR . 'index.php');
            if (!$protected) {
                $this->add('upload-dir', 'medium', $path,
                    'Carpeta de subidas sin .htaccess/index.php. Si acepta .php, un archivo subido se ejecuta como codigo.',
                    'Anade .htaccess con "php_flag engine off" + denegar ejecucion, o index.php vacio.');
            }
        }
    }

    // ---- .htaccess raiz ----
    private function checkHtaccess(string $dir): void
    {
        if (!is_file($dir . DIRECTORY_SEPARATOR . '.htaccess') && !is_file($dir . DIRECTORY_SEPARATOR . 'web.config')) {
            $this->add('no-htaccess', 'info', $dir,
                'Sin .htaccess/web.config raiz: puede haber listado de directorios activo y sin reglas de seguridad.',
                'Anade .htaccess con Options -Indexes y cabeceras de seguridad.');
        }
    }

    // ---- php.ini ----
    private function checkPhpIni(string $ini): void
    {
        $content = file_get_contents($ini);
        $checks = [
            'display_errors' => ['expected' => 'off', 'sev' => 'medium', 'risk' => 'display_errors=On muestra errores (rutas, SQL, codigo) a los visitantes.'],
            'expose_php' => ['expected' => 'off', 'sev' => 'low', 'risk' => 'expose_php=On anuncia la version de PHP en cada respuesta.'],
            'allow_url_include' => ['expected' => 'off', 'sev' => 'critical', 'risk' => 'allow_url_include=On permite include() de URLs remotas = ejecucion remota directa.'],
            'allow_url_fopen' => ['expected' => 'off', 'sev' => 'low', 'risk' => 'allow_url_fopen=On facilita SSRF y descarga de payloads.'],
        ];
        foreach ($checks as $key => $c) {
            if (preg_match('/^\s*' . $key . '\s*=\s*on/im', $content)) {
                $this->add('phpini-' . $key, $c['sev'], $ini, $c['risk'], "Pon $key = Off en php.ini de produccion.");
            }
        }
    }
}
