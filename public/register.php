<?php
/**
 * User Registration Page
 *
 * Security measures:
 * - Input validation (username, email, password strength)
 * - Password hashed with bcrypt
 * - CSRF protection
 * - XSS prevention via output encoding
 * - SQL injection prevented via prepared statements
 */

define('APP_ROOT', dirname(__DIR__));

require_once APP_ROOT . '/includes/security_headers.php';
require_once APP_ROOT . '/includes/session.php';
require_once APP_ROOT . '/includes/auth.php';
require_once APP_ROOT . '/includes/validation.php';
require_once APP_ROOT . '/includes/logger.php';
require_once APP_ROOT . '/includes/functions.php';

setSecurityHeaders();

// Redirect if already logged in
$session = validateSession();
if ($session) {
    header('Location: /dashboard.php');
    exit;
}

$errorMessage = '';
$successMessage = '';
$formData = ['username' => '', 'email' => ''];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get and sanitize input
    $username = trim($_POST['username'] ?? '');
    $email    = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';
    $csrfToken = (string)($_POST['register_csrf_token'] ?? '');

    $formData = ['username' => $username, 'email' => $email];

    // SECURITY: Validate registration CSRF token (double-submit cookie pattern)
    if (!validateLoginCSRFToken($csrfToken)) {
        $errorMessage = 'Invalid request. Please refresh the page and try again.';
    } elseif ($password !== $confirmPassword) {
        $errorMessage = 'Passwords do not match.';
    } else {
        // Register the user (validation is done inside registerUser)
        $result = registerUser($username, $email, $password);

        if ($result['success']) {
            // Clear the CSRF cookie after successful registration
            clearLoginCSRFCookie();

            // Log activity
            logActivity('register.php (success)', null);

            // Redirect to login with success message
            // SECURITY: Using a session flash message would be better,
            // but since user isn't logged in yet, we use a query parameter.
            // The parameter value is fixed, not user-controlled, so no XSS risk.
            header('Location: /login.php?registered=1');
            exit;
        } else {
            $errorMessage = $result['error'];
        }
    }
}

// Generate registration CSRF token (cookie-based double-submit)
$registerCsrfToken = generateLoginCSRFToken();

// SECURITY: Only log page view on GET — POST outcomes are already logged above
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    logActivity('register.php', null);
}

$pageTitle = 'Register';
require_once APP_ROOT . '/templates/header.php';
?>

<div class="auth-container">
    <div class="card">
        <div class="card-header">
            <h1 class="card-title">Create Account</h1>
            <p class="card-subtitle">Join TransactiWar and get Rs. 100 to start!</p>
        </div>

        <form method="POST" action="/register.php" autocomplete="off" novalidate>
            <!-- SECURITY: Registration CSRF token (double-submit cookie pattern) -->
            <input type="hidden" name="register_csrf_token" value="<?php echo sanitizeOutput($registerCsrfToken); ?>">
            <div class="form-group">
                <label for="username" class="form-label">Username</label>
                <input type="text" id="username" name="username" class="form-input"
                       value="<?php echo sanitizeOutput($formData['username']); ?>"
                       required minlength="3" maxlength="50"
                       pattern="[a-zA-Z0-9_]{3,50}"
                       placeholder="Choose a username">
                <div class="form-hint">3-50 characters. Letters, numbers, and underscores only.</div>
            </div>

            <div class="form-group">
                <label for="email" class="form-label">Email</label>
                <input type="email" id="email" name="email" class="form-input"
                       value="<?php echo sanitizeOutput($formData['email']); ?>"
                       required maxlength="255"
                       placeholder="you@example.com">
            </div>

            <div class="form-group">
                <label for="password" class="form-label">Password</label>
                <input type="password" id="password" name="password" class="form-input"
                       required minlength="8" maxlength="72"
                       placeholder="Create a strong password">
                <div id="passwordStrength" class="form-hint"></div>
                <div class="form-hint">Min 8 characters with uppercase, lowercase, digit, and special character.</div>
            </div>

            <div class="form-group">
                <label for="confirm_password" class="form-label">Confirm Password</label>
                <input type="password" id="confirm_password" name="confirm_password" class="form-input"
                       required minlength="8" maxlength="72"
                       placeholder="Confirm your password">
            </div>

            <button type="submit" class="btn btn-primary btn-block">Create Account</button>
        </form>

        <div class="auth-link">
            Already have an account? <a href="/login.php">Login here</a>
        </div>
    </div>
</div>

<?php require_once APP_ROOT . '/templates/footer.php'; ?>
