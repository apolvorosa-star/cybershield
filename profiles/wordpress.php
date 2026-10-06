<?php
/**
 * Perfil WordPress - checklist OWASP clasico WP:
 * $wpdb->prepare, esc_*, nonces, sanitize_*, current_user_can
 */
return [
    'name' => 'WordPress / $wpdb',
    'sanitizers' => [
        'esc_html', 'esc_attr', 'esc_url', 'esc_js', 'esc_textarea',
        'sanitize_text_field', 'sanitize_textarea_field', 'sanitize_email',
        'sanitize_file_name', 'sanitize_title', 'sanitize_key', 'sanitize_user',
        'absint', 'intval', 'floatval', 'wp_kses', 'wp_kses_post',
        'htmlspecialchars', 'filter_var', 'filter_input', 'intdiv',
        '$wpdb->prepare', 'prepare',
    ],
    'nonce_fns' => [
        'wp_verify_nonce', 'check_admin_referer', 'wp_nonce_field',
        'check_ajax_referer', 'wp_create_nonce', 'nonce',
    ],
    'capability_fns' => [
        'current_user_can', 'user_can', 'is_admin', 'is_super_admin',
        'is_user_logged_in', 'auth_redirect',
    ],
];
