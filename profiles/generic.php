<?php
/**
 * Perfil generico - PHP puro: solo funciones nativas de escape/validacion.
 */
return [
    'name' => 'PHP generico',
    'sanitizers' => [
        'htmlspecialchars', 'htmlentities', 'strip_tags', 'filter_var',
        'filter_input', 'intval', 'floatval', 'basename', 'realpath',
        'escapeshellarg', 'escapeshellcmd', 'rawurlencode', 'urlencode',
        'json_encode', 'trim',
    ],
    'nonce_fns' => ['csrf', 'nonce', 'token'],
    'capability_fns' => [
        'current_user_can', 'orizon_can', 'isAdmin', 'is_admin',
        'requireLogin', 'requireAdmin', '$_SESSION[\'user', '$_SESSION["user',
    ],
];
