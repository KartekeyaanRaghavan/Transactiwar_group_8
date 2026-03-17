<?php
/**
 * Login Page
 *
 * Security measures:
 * - Rate limiting on login attempts (per IP)
 * - Generic error messages (no username/email enumeration)
 * - Timing-safe password comparison (Argon2id)
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
        // SECURITY: Verify image CAPTCHA before attempting login
        $captchaAnswer = trim($_POST['captcha_answer'] ?? '');

        if (empty($captchaAnswer) || !verifyCaptcha($captchaAnswer)) {
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

// Cache-busting nonce so the browser always fetches a fresh captcha image
$captchaNonce = $captchaRequired ? random_int(100000, 999999) : null;

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

            <?php if ($captchaNonce): ?>
                <!-- SECURITY: Image CAPTCHA shown after <?php echo CAPTCHA_THRESHOLD; ?> failed attempts from this IP.
                     Answer is stored server-side only — never in the HTML. -->
                <div class="form-group">
                    <label class="form-label">Solve the challenge to continue</label>
                    <img src="/captcha.php?v=<?php echo $captchaNonce; ?>"
                         alt="CAPTCHA challenge"
                         style="display:block;margin-bottom:8px;border:1px solid #ccc;border-radius:4px;">
                    <input type="text" id="captcha_answer" name="captcha_answer" class="form-input"
                           required placeholder="Enter the answer"
                           autocomplete="off" inputmode="numeric">
                    <div class="form-hint">Enter the numeric result of the expression shown above.</div>
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
