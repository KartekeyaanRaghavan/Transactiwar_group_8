<?php
/**
 * Header Template
 * Included at the top of every page.
 *
 * Expected variables:
 * - $pageTitle: string - The page title
 * - $session: array|null - Current session data (null if not logged in)
 */

// Prevent direct access
if (!defined('APP_ROOT')) {
    die('Direct access not allowed.');
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title><?php echo sanitizeOutput($pageTitle ?? 'TransactiWar'); ?> - TransactiWar</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="nav-container">
            <a href="/" class="nav-brand">
                <span class="nav-brand-icon">⚡</span>
                TransactiWar
            </a>
            <?php if (isset($session) && $session): ?>
                <div class="nav-links">
                    <a href="/dashboard.php" class="nav-link">Dashboard</a>
                    <a href="/profile.php" class="nav-link">My Profile</a>
                    <a href="/search.php" class="nav-link">Search Users</a>
                    <a href="/transfer.php" class="nav-link">Transfer</a>
                    <a href="/transactions.php" class="nav-link">History</a>
                    <div class="nav-user">
                        <span class="nav-balance"><?php echo formatCurrency((float)($session['balance'] ?? 0)); ?></span>
                        <span class="nav-username"><?php echo sanitizeOutput($session['username']); ?></span>
                        <!-- SECURITY: Logout is POST-only with CSRF token (prevents logout CSRF) -->
                        <form method="POST" action="/logout.php" class="form-inline">
                            <input type="hidden" name="csrf_token" value="<?php echo sanitizeOutput($session['csrf_token']); ?>">
                            <button type="submit" class="nav-link nav-logout btn-reset">Logout</button>
                        </form>
                    </div>
                </div>
                <button class="nav-toggle" id="navToggle" aria-label="Toggle navigation">
                    <span></span><span></span><span></span>
                </button>
            <?php else: ?>
                <div class="nav-links">
                    <a href="/login.php" class="nav-link">Login</a>
                    <a href="/register.php" class="nav-link">Register</a>
                </div>
            <?php endif; ?>
        </div>
    </nav>

    <main class="main-content">
        <div class="container">
            <?php if (isset($successMessage) && $successMessage): ?>
                <div class="alert alert-success"><?php echo sanitizeOutput($successMessage); ?></div>
            <?php endif; ?>
            <?php if (isset($errorMessage) && $errorMessage): ?>
                <div class="alert alert-error"><?php echo sanitizeOutput($errorMessage); ?></div>
            <?php endif; ?>
