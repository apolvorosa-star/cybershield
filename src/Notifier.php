<?php
/**
 * CyberShield - Notifier
 *
 * Envio de alertas cuando una auditoria termina en ACCION REQUERIDA
 * o AMENAZA DETECTADA. Canales (todos opcionales, configurables en el panel):
 *  - ntfy.sh   : push libre al movil (topico privado)
 *  - Telegram  : bot token + chat_id
 *  - Webhook   : POST JSON generico (Discord, Slack compatible, n8n...)
 */

namespace Orizon\CyberShield;

class Notifier
{
    public static function alert(array $settings, string $target, string $status, array $counts): void
    {
        $title = "🚨 CyberShield: $status";
        $body  = "$target\n🔴 {$counts['critical']}  🟠 {$counts['high']}  🟡 {$counts['medium']}  🔵 {$counts['low']}";

        if (!empty($settings['ntfy'])) {
            self::post(rtrim($settings['ntfy'], '/'), $body, [
                "Title: $title",
                'Priority: high',
                'Tags: shield,warning',
            ]);
        }
        if (!empty($settings['tg_token']) && !empty($settings['tg_chat'])) {
            self::post(
                'https://api.telegram.org/bot' . $settings['tg_token'] . '/sendMessage',
                http_build_query([
                    'chat_id' => $settings['tg_chat'],
                    'text'    => "$title\n$body",
                ]),
                ['Content-Type: application/x-www-form-urlencoded']
            );
        }
        if (!empty($settings['webhook'])) {
            self::post($settings['webhook'], json_encode([
                'source' => 'cybershield', 'target' => $target,
                'status' => $status, 'counts' => $counts,
            ], JSON_UNESCAPED_UNICODE), ['Content-Type: application/json']);
        }
    }

    private static function post(string $url, string $body, array $headers): void
    {
        $headerStr = implode("\r\n", $headers);
        $ctx = stream_context_create([
            'http' => [
                'method'  => 'POST',
                'timeout' => 8,
                'header'  => $headerStr . "\r\nUser-Agent: CyberShield-AI/1.0",
                'content' => $body,
                'ignore_errors' => true,
            ],
            'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
        ]);
        @file_get_contents($url, false, $ctx);
    }
}
