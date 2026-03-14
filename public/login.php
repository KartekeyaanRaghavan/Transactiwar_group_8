<?php
/**
 * Login Page
 *
 * Security measures:
 * - Rate limiting on login attempts (per IP)
 * - Generic error messages (no username/email enumeration)
 * - Timing-safe password comparison (bcrypt)
 * - Session fixation prevention (new token on login)
 * - CSRF protection via cookie-based double-submit pattern (pre-session)
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

// Check for registration success redirect
if (isset($_GET['registered']) && $_GET['registered'] === '1') {
    $successMessage = 'Account created successfully! You can now login.';
}

// SECURITY: Check if CAPTCHA is required (>= 3 failed attempts from this IP)
$clientIP = getClientIP();
$ipFailures = getRecentFailedAttemptCountByIP($clientIP);
$captchaRequired = ($ipFailures >= CAPTCHA_THRESHOLD);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $csrfToken = (string)($_POST['login_csrf_token'] ?? '');

    // SECURITY: Validate login CSRF token (double-submit cookie pattern)
    if (!validateLoginCSRFToken($csrfToken)) {
        $errorMessage = 'Invalid request. Please refresh the page and try again.';
    } elseif (empty($username) || empty($password)) {
        $errorMessage = 'Please enter both username and password.';
    } elseif ($captchaRequired) {
        // SECURITY: Verify CAPTCHA before attempting login
        $captchaAnswer = trim($_POST['captcha_answer'] ?? '');
        $captchaTs     = (string)($_POST['captcha_ts'] ?? '');
        $captchaToken  = (string)($_POST['captcha_token'] ?? '');

        if (empty($captchaAnswer) || !verifyCaptcha($captchaAnswer, $captchaTs, $captchaToken)) {
            $errorMessage = 'Incorrect or expired CAPTCHA. Please try again.';
        } else {
            $result = loginUser($username, $password);

            if ($result['success']) {
                clearLoginCSRFCookie();
                logActivity('login.php (success)', null);
                header('Location: /dashboard.php');
                exit;
            } else {
                $errorMessage = $result['error'];
                logActivity('login.php (failed)', null);
            }
        }
    } else {
        $result = loginUser($username, $password);

        if ($result['success']) {
            clearLoginCSRFCookie();
            logActivity('login.php (success)', null);
            header('Location: /dashboard.php');
            exit;
        } else {
            $errorMessage = $result['error'];
            logActivity('login.php (failed)', null);
        }
    }

    // Re-check after POST (failure may have pushed us over threshold)
    $ipFailures = getRecentFailedAttemptCountByIP($clientIP);
    $captchaRequired = ($ipFailures >= CAPTCHA_THRESHOLD);
}

// Generate CAPTCHA if required
$captcha = $captchaRequired ? generateCaptcha() : null;

// Generate login CSRF token (cookie-based double-submit)
$loginCsrfToken = generateLoginCSRFToken();

// SECURITY: Only log page view on GET — POST outcomes are already logged above
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    logActivity('login.php', null);
}

$pageTitle = 'Login';
require_once APP_ROOT . '/templates/header.php';
?>

<div class="auth-container">
    <div class="card">
        <div class="card-header">
            <h1 class="card-title">Login</h1>
            <p class="card-subtitle">Welcome back to TransactiWar</p>
        </div>

        <form method="POST" action="/login.php" autocomplete="off">
            <!-- SECURITY: Login CSRF token (double-submit cookie pattern) -->
            <input type="hidden" name="login_csrf_token" value="<?php echo sanitizeOutput($loginCsrfToken); ?>">

            <div class="form-group">
                <label for="username" class="form-label">Username</label>
                <input type="text" id="username" name="username" class="form-input"
                       required maxlength="50"
                       placeholder="Enter your username"
                       autofocus>
            </div>

            <div class="form-group">
                <label for="password" class="form-label">Password</label>
                <input type="password" id="password" name="password" class="form-input"
                       required maxlength="72"
                       placeholder="Enter your password">
            </div>

            <?php if ($captcha): ?>
                <!-- SECURITY: Math CAPTCHA shown after <?php echo CAPTCHA_THRESHOLD; ?> failed attempts from this IP -->
                <div class="form-group">
                    <label for="captcha_answer" class="form-label"><?php echo sanitizeOutput($captcha['question']); ?></label>
                    <input type="number" id="captcha_answer" name="captcha_answer" class="form-input"
                           required placeholder="Enter your answer"
                           autocomplete="off">
                    <input type="hidden" name="captcha_ts" value="<?php echo (int)$captcha['timestamp']; ?>">
                    <input type="hidden" name="captcha_token" value="<?php echo sanitizeOutput($captcha['token']); ?>">
                    <div class="form-hint">Please solve this to verify you are human.</div>
                </div>
            <?php endif; ?>

            <button type="submit" class="btn btn-primary btn-block">Login</button>
        </form>

        <div class="auth-link">
            Don't have an account? <a href="/register.php">Register here</a>
        </div>
    </div>
</div>

<?php require_once APP_ROOT . '/templates/footer.php'; ?>
