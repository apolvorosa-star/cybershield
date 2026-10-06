<?php
/**
 * Perfil OrizonCMS - funciones seguras del stack Orizon/Blanca Lorenzo
 * (PDO + e() + orizon_can() + csrf propio)
 */
return [
    'name' => 'OrizonCMS / PHP + PDO',
    'sanitizers' => [
        'e', 'htmlspecialchars', 'htmlentities', 'strip_tags',
        'intval', 'floatval', 'absint', 'filter_var', 'filter_input',
        'sanitize_text_field', 'esc_html', 'esc_attr', 'esc_url',
        'json_encode', 'rawurlencode', 'urlencode', 'basename', 'realpath',
        'escapeshellarg', 'escapeshellcmd', 'trim',
    ],
    'nonce_fns' => [
        'csrf', 'nonce', 'wp_verify_nonce', 'check_admin_referer',
        'token', 'verify_token', 'csrf_verify', 'verify_csrf', 'csrf_token',
    ],
    'capability_fns' => [
        'orizon_can', 'current_user_can', 'Auth::', 'requireAdmin',
        'isAdmin', 'is_admin', 'checkAdmin', 'requireLogin', 'require_auth',
        '$_SESSION[\'admin', '$_SESSION["admin', '$_SESSION[\'user_id',
    ],
];
