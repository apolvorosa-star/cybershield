<?php
/**
 * CyberShield - Repair
 *
 * Aplica correcciones estructurales SEGURAS y reversibles:
 *  1. .htaccess blindado en el docroot (deniega .env, *.sql, .git,
 *     listado de directorios, cabeceras de seguridad)
 *  2. Cuarentena de scripts peligrosos (install.php, *.sql, admin-makers...)
 *     -> se mueven a .cybershield-quarantine/ (reversible)
 *  3. .htaccess en carpetas de subida (PHP desactivado)
 *
 * Los fallos a nivel de codigo (XSS/SQLi/CSRF) no se auto-reparan:
 * se listan como pendientes para correccion manual.
 */

namespace Orizon\CyberShield;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

class Repair
{
    private array $actions = [];
    private bool $autoYes;
    private string $quarantine;
    private array $whitelist = [];

    public function __construct(private string $docroot, bool $autoYes = false)
    {
        $this->docroot = rtrim($docroot, '\\/');
        $this->autoYes = $autoYes;
        $this->quarantine = $this->docroot . DIRECTORY_SEPARATOR . '.cybershield-quarantine';
        $this->loadWhitelist();
    }

    // Lista blanca: <paquete>/whitelist.dist.txt (plantilla publica) +
    // <paquete>/whitelist.txt (personal, no se distribuye) +
    // <docroot>/.cybershield-whitelist
    // Formatos por linea (sin espacios iniciales, # = comentario):
    //   ruta/relativa/al/archivo          -> aplica a cualquier proyecto auditado
    //   C:/ruta/al/docroot|ruta/relativa  -> solo aplica a ese proyecto
    //   patrones con * admitidos (fnmatch)
    private function loadWhitelist(): void
    {
        $root = dirname(__DIR__);
        $files = [
            $root . DIRECTORY_SEPARATOR . 'whitelist.dist.txt',
            $root . DIRECTORY_SEPARATOR . 'whitelist.txt',
        ];
        $local = $this->docroot . DIRECTORY_SEPARATOR . '.cybershield-whitelist';
        if (is_file($local)) $files[] = $local;

        foreach ($files as $file) {
            if (!is_file($file)) continue;
            foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
                $line = trim($line);
                if ($line === '' || $line[0] === '#') continue;
                $scope = null;
                $pat = $line;
                if (strpos($line, '|') !== false) {
                    [$scope, $pat] = array_map('trim', explode('|', $line, 2));
                    $scope = rtrim(str_replace('\\', '/', $scope), '/');
                }
                $this->whitelist[] = ['scope' => $scope, 'pattern' => str_replace('\\', '/', $pat)];
            }
        }
    }

    private function isWhitelisted(string $file): bool
    {
        $rel = str_replace('\\', '/', substr($file, strlen($this->docroot) + 1));
        $rootNorm = rtrim(str_replace('\\', '/', $this->docroot), '/');
        foreach ($this->whitelist as $w) {
            if ($w['scope'] !== null && strcasecmp($w['scope'], $rootNorm) !== 0) continue;
            if (strcasecmp($w['pattern'], $rel) === 0) return true;
            if (fnmatch($w['pattern'], $rel, FNM_CASEFOLD)) return true;
        }
        return false;
    }

    private function log(string $a): void { $this->actions[] = $a; }

    private function confirm(string $q): bool
    {
        if ($this->autoYes) { echo "  [auto] $q -> SI\n"; return true; }
        echo "  $q [S/n]: ";
        $r = strtolower(trim((string) fgets(STDIN)));
        return $r === '' || $r === 's' || $r === 'si' || $r === 'y' || $r === 'yes';
    }

    public function run(): array
    {
        if (!is_dir($this->docroot)) {
            echo "ERROR: no es un directorio: {$this->docroot}\n";
            return [];
        }

        $this->hardenHtaccess();
        $this->quarantineDangerous();
        $this->protectUploadDirs();

        return $this->actions;
    }

    // ================= 1. .htaccess blindado =================

    private function hardenHtaccess(): void
    {
        $f = $this->docroot . DIRECTORY_SEPARATOR . '.htaccess';
        $exists = is_file($f);
        $existing = $exists ? (string) file_get_contents($f) : '';

        if (strpos($existing, 'CyberShield') !== false) {
            echo "  .htaccess ya contiene reglas CyberShield — se omite.\n";
            return;
        }

        if (!$this->confirm(($exists ? 'Actualizar' : 'Crear') . ' .htaccess con reglas de seguridad?')) return;

        if ($exists) {
            $bak = $this->quarantine . DIRECTORY_SEPARATOR . 'htaccess-backup-' . date('Ymd-His');
            $this->ensureQuarantine();
            copy($f, $bak);
            $this->log("Backup .htaccess -> $bak");
        }

        $rules = <<<HTA

# ============ CyberShield — reglas de seguridad ============
# Directorios sin listado
Options -Indexes

# Carpetas/archivos ocultos (.git, .env, .cybershield-quarantine...)
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
<FilesMatch "^(install|installer|setup|create_admin|reset_admin|phpinfo|info|test)\.php$">
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

        file_put_contents($f, $existing . $rules);
        $this->log('.htaccess endurecido (deniega .env, .sql, .git, listados, cabeceras)');
    }

    // ================= 2. Cuarentena =================

    private function ensureQuarantine(): void
    {
        if (!is_dir($this->quarantine)) {
            mkdir($this->quarantine, 0755, true);
            file_put_contents(
                $this->quarantine . DIRECTORY_SEPARATOR . '.htaccess',
                "Require all denied\nDeny from all\n"
            );
        }
    }

    private function quarantineDangerous(): void
    {
        $patterns = [
            'install.php', 'installer.php', 'setup.php', 'create_admin.php',
            'reset_admin.php', 'phpinfo.php', 'info.php', 'test.php',
            '*.sql', '*.bak', '*.old', '*.dump',
        ];

        $candidates = [];
        foreach ($patterns as $p) {
            foreach (glob($this->docroot . DIRECTORY_SEPARATOR . $p) ?: [] as $f) $candidates[] = $f;
            foreach (glob($this->docroot . DIRECTORY_SEPARATOR . '*' . DIRECTORY_SEPARATOR . $p) ?: [] as $f) $candidates[] = $f;
            foreach (glob($this->docroot . DIRECTORY_SEPARATOR . '*' . DIRECTORY_SEPARATOR . '*' . DIRECTORY_SEPARATOR . $p) ?: [] as $f) $candidates[] = $f;
        }
        $candidates = array_unique(array_filter($candidates, 'is_file'));
        // Nunca tocar lo que ya esta en cuarentena
        $candidates = array_filter($candidates, fn($f) => strpos($f, '.cybershield-quarantine') === false);

        // Lista blanca (whitelist.txt / .cybershield-whitelist)
        $skipped = [];
        $candidates = array_filter($candidates, function ($f) use (&$skipped) {
            if ($this->isWhitelisted($f)) { $skipped[] = $f; return false; }
            return true;
        });
        foreach ($skipped as $f) {
            echo "  [whitelist] excluido: " . substr($f, strlen($this->docroot) + 1) . "\n";
        }

        if (!$candidates) { echo "  No hay scripts/archivos peligrosos que poner en cuarentena.\n"; return; }

        echo "  Archivos candidatos a cuarentena:\n";
        foreach ($candidates as $f) echo "    - " . substr($f, strlen($this->docroot) + 1) . "\n";
        if (!$this->confirm('Moverlos a .cybershield-quarantine/ (quedan bloqueados pero recuperables)?')) return;

        $this->ensureQuarantine();
        $log = [];
        foreach ($candidates as $f) {
            $rel = substr($f, strlen($this->docroot) + 1);
            $dest = $this->quarantine . DIRECTORY_SEPARATOR . str_replace(['/', '\\'], '__', $rel);
            if (rename($f, $dest)) {
                $this->log("Cuarentena: $rel -> .cybershield-quarantine/");
                $log[] = "$rel => " . basename($dest);
            }
        }
        if ($log) {
            file_put_contents(
                $this->quarantine . DIRECTORY_SEPARATOR . 'moves.log',
                implode("\n", $log) . "\n",
                FILE_APPEND
            );
        }
    }

    // ================= 3. Carpetas de subida =================

    private function protectUploadDirs(): void
    {
        $dirs = [];
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($this->docroot, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($it as $d) {
            if (!$d->isDir()) continue;
            if (!preg_match('/(uploads?|media|files|storage)$/i', $d->getFilename())) continue;
            $p = $d->getPathname();
            if (strpos($p, '.cybershield-quarantine') !== false) continue;
            if (!is_file($p . DIRECTORY_SEPARATOR . '.htaccess')) $dirs[] = $p;
        }

        if (!$dirs) { echo "  Carpetas de subida ya protegidas.\n"; return; }

        echo "  Carpetas de subida sin .htaccess:\n";
        foreach ($dirs as $d) echo "    - " . substr($d, strlen($this->docroot) + 1) . "\n";
        if (!$this->confirm('Crear .htaccess que desactiva PHP en esas carpetas?')) return;

        $rules = "php_flag engine off\nOptions -ExecCGI\n<FilesMatch \"\\.(php|phtml|php3|php4|php5|php7|phar|cgi|pl|asp|aspx|jsp)$\">\n    Require all denied\n</FilesMatch>\n";
        foreach ($dirs as $d) {
            file_put_contents($d . DIRECTORY_SEPARATOR . '.htaccess', $rules);
            $this->log('Protegida carpeta de subidas: ' . substr($d, strlen($this->docroot) + 1));
        }
    }
}
