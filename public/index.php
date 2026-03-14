<?php
/**
 * Landing Page / Home
 * Redirects authenticated users to dashboard, shows welcome page to guests.
 */

define('APP_ROOT', dirname(__DIR__));

require_once APP_ROOT . '/includes/security_headers.php';
require_once APP_ROOT . '/includes/session.php';
require_once APP_ROOT . '/includes/validation.php';
require_once APP_ROOT . '/includes/logger.php';
require_once APP_ROOT . '/includes/functions.php';

setSecurityHeaders();

$session = validateSession();

// Log activity
logActivity('index.php', $session);

if ($session) {
    header('Location: /dashboard.php');
    exit;
}

$pageTitle = 'Welcome';
require_once APP_ROOT . '/templates/header.php';
?>

<div class="auth-container">
    <div class="card landing-card">
        <h1 class="landing-title">TransactiWar</h1>
        <p class="landing-subtitle">Secure Banking Application</p>
        <p class="landing-text">Welcome to TransactiWar, a secure money transfer platform. Register or login to get started.</p>
        <div class="btn-group-center">
            <a href="/login.php" class="btn btn-primary">Login</a>
            <a href="/register.php" class="btn btn-outline">Register</a>
        </div>
    </div>
</div>

<?php require_once APP_ROOT . '/templates/footer.php'; ?>
