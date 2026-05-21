<?php
// INTENTIONALLY INSECURE — BAZOOKA TEST LAB
// DO NOT USE IN PRODUCTION

// Default security keys (intentionally weak)
define('AUTH_KEY',         'put your unique phrase here');
define('SECURE_AUTH_KEY',  'put your unique phrase here');
define('LOGGED_IN_KEY',    'put your unique phrase here');
define('NONCE_KEY',        'put your unique phrase here');

// Debug enabled
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
define('WP_DEBUG_DISPLAY', false);

// File editing enabled (insecure)
// DISALLOW_FILE_EDIT is NOT set — intentional

// Disable auto-updates (insecure)
define('WP_AUTO_UPDATE_CORE', false);
