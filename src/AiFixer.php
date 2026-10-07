<?php
/**
 * CyberShield - AiFixer
 *
 * Reparacion asistida por IA de los hallazgos de una auditoria.
 *  - buildPrompt(): prompt autocontenido (hallazgo + codigo) listo para
 *    pegar en cualquier LLM, o para la API configurada.
 *  - fix(): llama a un endpoint OpenAI-compatible (settings: ai_url,
 *    ai_key, ai_model). Si no hay key, devuelve error y el panel usa
 *    el modo manual (copiar prompt / pegar respuesta).
 *  - extractCode(): saca el codigo de la respuesta (fences ```php o raw).
 * El panel SIEMPRE muestra la propuesta antes de aplicarla: la IA propone,
 * el humano decide.
 */

namespace Orizon\CyberShield;

class AiFixer
{
    public static function buildPrompt(array $f, string $code, string $file): string
    {
        $rule = $f['rule'] ?? 'vuln';
        $line = (int) ($f['line'] ?? 0);
        $desc = $f['desc'] ?? $f['risk'] ?? '';
        $fix  = $f['fix'] ?? '';

        // Contexto: si el archivo es una API JSON, un token CSRF romperia
        // a los clientes — el fix correcto es exigir POST.
        $apiHint = str_contains($code, 'application/json')
            ? "\nIMPORTANTE: este archivo es una API JSON (devuelve application/json). "
              . "Sus clientes NO son navegadores: NO uses session_start() ni tokens CSRF. "
              . "Para CSRF en APIs la correccion es rechazar metodos que no sean POST "
              . "(HTTP 405) y leer solo \$_POST."
            : '';

        return <<<PROMPT
Eres un experto en seguridad PHP. Corrige el siguiente archivo corrigiendo
SOLO la vulnerabilidad detectada — no refactorices ni cambies estilo.

ARCHIVO: $file
VULNERABILIDAD: $rule (linea $line)
DESCRIPCION: $desc
RECOMENDACION DEL SCANNER: $fix$apiHint

Reglas:
- Devuelve el archivo PHP COMPLETO corregido, sin explicaciones
- Mantén el comportamiento funcional identico
- Sanea/escapa el dato contaminado en el punto exacto del fallo
- Si hay mas vulnerabilidades evidentes del mismo tipo, corrigelas tambien
- NO llames a funciones que no existan en el fichero o sus includes
  (p.ej. csrf_token()): si necesitas helpers, DEFÍNELOS dentro del fichero
- Si generas un token en un formulario, verifica EXACTAMENTE ese mismo
  campo/nombre al procesar el POST
- Responde SOLO con el codigo entre ```php y ```

CODIGO ACTUAL:
```php
$code
```
PROMPT;
    }

    /** Llama a la API configurada. Devuelve ['code'=>string] o ['error'=>msg] */
    public static function fix(array $settings, array $f, string $code, string $file): array
    {
        $key = trim($settings['ai_key'] ?? '');
        $url = trim($settings['ai_url'] ?? '') ?: 'https://api.openai.com/v1/chat/completions';
        // Endpoints locales (Ollama, LM Studio…) no necesitan API key
        if ($key === '' && !preg_match('#^https?://(127\.|localhost|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)#i', $url)) {
            return ['error' => 'Sin ai_key en Ajustes — usa el modo manual (copiar prompt)'];
        }
        $model = trim($settings['ai_model'] ?? '') ?: 'gpt-4o-mini';

        $messages = [
            ['role' => 'system', 'content' => 'Eres un experto en seguridad PHP. Respondes solo con codigo.'],
            ['role' => 'user',   'content' => self::buildPrompt($f, $code, $file)],
        ];

        // Ollama: usar API nativa para poder subir num_ctx (ficheros grandes)
        $isOllama = (bool) preg_match('#://[^/]*:?11434#', $url);
        if ($isOllama) {
            $url = preg_replace('#/v1/.*$#', '/api/chat', $url);
            $payload = json_encode([
                'model'    => $model,
                'messages' => $messages,
                'stream'   => false,
                'options'  => [
                    'temperature' => 0.1,
                    // contexto adaptativo: ~3 chars/token, entrada+salida completas
                    'num_ctx' => max(8192, min(65536, (int) ceil(strlen($code) / 3 * 2 + 1024))),
                ],
            ]);
        } else {
            $payload = json_encode([
                'model'       => $model,
                'messages'    => $messages,
                'temperature' => 0.1,
            ]);
        }

        $ctx = stream_context_create(['http' => [
            'method'  => 'POST',
            'timeout' => 300, // modelos locales grandes tardan en cargar a VRAM
            'header'  => ($key !== '' ? "Authorization: Bearer $key\r\n" : '') . 'Content-Type: application/json',
            'content' => $payload,
            'ignore_errors' => true,
        ]]);
        $resp = @file_get_contents($url, false, $ctx);
        if ($resp === false) return ['error' => 'No se pudo contactar con la API de IA'];
        $j = json_decode($resp, true);
        $text = $isOllama
            ? ($j['message']['content'] ?? '')
            : ($j['choices'][0]['message']['content'] ?? '');
        if ($text === '') {
            return ['error' => 'Respuesta vacia de la IA: ' . substr($resp, 0, 200)];
        }
        return ['code' => self::extractCode($text)];
    }

    /** Extrae el codigo de una respuesta con fences ```php ... ``` */
    public static function extractCode(string $text): string
    {
        if (preg_match('/```(?:php)?\s*\n(.*?)```/s', $text, $m)) return trim($m[1]) . "\n";
        if (str_starts_with(ltrim($text), '<?php')) return trim($text) . "\n";
        return $text;
    }
}
