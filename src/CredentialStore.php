<?php
/**
 * CyberShield - CredentialStore
 *
 * Cifrado AES-256-GCM de las credenciales de los servidores guardados
 * en el panel (webs.json). La clave maestra vive en un fichero local
 * (.master-key, permisos 0600) junto a los datos — asi el JSON de webs
 * no contiene secretos en claro.
 */

namespace Orizon\CyberShield;

class CredentialStore
{
    private static string $dir = '';
    private const KEY_FILE = '.master-key';

    public static function init(string $dir): void
    {
        self::$dir = rtrim($dir, '\\/');
    }

    private static function key(): string
    {
        $f = self::$dir . '/' . self::KEY_FILE;
        if (!is_file($f)) {
            file_put_contents($f, bin2hex(random_bytes(32)));
            @chmod($f, 0600);
        }
        return hex2bin(trim((string) file_get_contents($f)));
    }

    public static function encrypt(string $plain): string
    {
        if ($plain === '') return '';
        $iv  = random_bytes(12);
        $tag = '';
        $ct  = openssl_encrypt($plain, 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, $iv, $tag);
        if ($ct === false) return '';
        return 'v1:' . base64_encode($iv . $tag . $ct);
    }

    public static function decrypt(string $enc): string
    {
        if ($enc === '' || !str_starts_with($enc, 'v1:')) return $enc; // valor legado sin cifrar
        $raw = base64_decode(substr($enc, 3), true);
        if ($raw === false || strlen($raw) < 29) return '';
        $iv  = substr($raw, 0, 12);
        $tag = substr($raw, 12, 16);
        $ct  = substr($raw, 28);
        $pt  = openssl_decrypt($ct, 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, $iv, $tag);
        return $pt === false ? '' : $pt;
    }

    /** true si el valor parece cifrado por nosotros */
    public static function isEncrypted(string $v): bool
    {
        return str_starts_with($v, 'v1:');
    }
}
