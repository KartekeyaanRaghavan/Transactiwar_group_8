<?php
/**
 * Logout Handler
 *
 * SECURITY: Logout requires POST method with CSRF token to prevent CSRF-based forced logout.
 * GET requests are redirected to the dashboard (session stays active).
 */

define('APP_ROOT', dirname(__DIR__));

require_once APP_ROOT . '/includes/security_headers.php';
require_once APP_ROOT . '/includes/session.php';
require_once APP_ROOT . '/includes/logger.php';

setSecurityHeaders();

// SECURITY: Only allow POST requests for logout (prevents CSRF via image/link tags)
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    // GET request to logout — redirect to dashboard instead of logging out
    header('Location: /dashboard.php');
    exit;
}

// Validate session exists
$session = validateSession();
if (!$session) {
    // No valid session — just redirect to login
    header('Location: /login.php');
    exit;
}

// SECURITY: Validate CSRF token
$csrfToken = (string)($_POST['csrf_token'] ?? '');
if (!validateCSRFToken($session, $csrfToken)) {
    // Invalid CSRF token — do not logout, redirect to dashboard
    header('Location: /dashboard.php');
    exit;
}

// Log before destroying session
logActivity('logout.php', $session);

// Destroy the session
destroySession();

// Redirect to login — pass reason if this was an inactivity logout
if (isset($_POST['inactivity']) && $_POST['inactivity'] === '1') {
    header('Location: /login.php?reason=inactivity');
} else {
    header('Location: /login.php');
}
exit;
