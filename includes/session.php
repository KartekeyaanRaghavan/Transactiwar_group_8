<?php
/**
 * Custom Session Management
 *
 * Security design:
 * - Session tokens are generated with cryptographically secure random_bytes (32 bytes = 256 bits)
 * - Only the SHA-256 hash of the token is stored in the database
 *   (if DB is compromised, raw tokens are not exposed)
 * - Sessions are bound to the client's IP address and User-Agent hash
 *   (prevents session hijacking via cookie theft)
 * - Cookies are set with HttpOnly, SameSite=Strict, and Secure (HTTPS enforced)
 * - Sessions expire after a configurable timeout (default 30 minutes)
 * - Session tokens are regenerated on login to prevent session fixation
 * - HMAC-based form integrity tokens for tamper-proofing
 */

require_once __DIR__ . '/../config/database.php';

// Session lifetime in seconds (30 minutes sliding window)
define('SESSION_LIFETIME', 1800);
// Absolute session lifetime — user must re-authenticate after this regardless of activity
define('SESSION_ABSOLUTE_LIFETIME', 28800); // 8 hours
// Token rotation interval — generate a new session token periodically
// Limits the window an attacker can use a stolen token
define('TOKEN_ROTATION_INTERVAL', 600); // 10 minutes
// Maximum concurrent sessions per user (oldest are evicted on new login)
define('MAX_SESSIONS_PER_USER', 5);
define('SESSION_COOKIE_NAME', 'TRANSACTIWAR_SID');

/**
 * Generate a cryptographically secure session token.
 *
 * @return string Hex-encoded token (64 characters)
 */
function generateSessionToken(): string {
    return bin2hex(random_bytes(32));
}

/**
 * Hash a session token for storage.
 *
 * @param string $token Raw session token
 * @return string SHA-256 hash of the token
 */
function hashSessionToken(string $token): string {
    return hash('sha256', $token);
}

/**
 * Get the User-Agent hash for session binding.
 *
 * @return string SHA-256 hash of the User-Agent
 */
function getUserAgentHash(): string {
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    return hash('sha256', $ua);
}

/**
 * Get the client's real IP address.
 * SECURITY NOTE: X-Forwarded-For can be spoofed. In production behind a trusted
 * reverse proxy, you might use it. Here we prefer REMOTE_ADDR for security.
 *
 * @return string Client IP address
 */
function getClientIP(): string {
    // SECURITY: Only trust REMOTE_ADDR as it cannot be spoofed at the TCP level.
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

/**
 * Create a new session for a user.
 *
 * @param int $userId The user ID
 * @return string The raw session token (to be sent as cookie)
 */
function createSession(int $userId): string {
    $pdo = getDBConnection();

    // Generate cryptographically secure token
    $token = generateSessionToken();
    $tokenHash = hashSessionToken($token);

    // Generate CSRF token for this session
    $csrfToken = bin2hex(random_bytes(32));

    $ip = getClientIP();
    $uaHash = getUserAgentHash();
    $expiresAt = date('Y-m-d H:i:s', time() + SESSION_LIFETIME);

    $stmt = $pdo->prepare(
        'INSERT INTO sessions (user_id, session_token_hash, csrf_token, ip_address, user_agent_hash, expires_at)
         VALUES (:user_id, :token_hash, :csrf_token, :ip, :ua_hash, :expires_at)'
    );
    $stmt->execute([
        ':user_id'    => $userId,
        ':token_hash' => $tokenHash,
        ':csrf_token' => $csrfToken,
        ':ip'         => $ip,
        ':ua_hash'    => $uaHash,
        ':expires_at' => $expiresAt,
    ]);

    // SECURITY: Evict oldest sessions if user exceeds MAX_SESSIONS_PER_USER
    $countStmt = $pdo->prepare('SELECT COUNT(*) FROM sessions WHERE user_id = :user_id');
    $countStmt->execute([':user_id' => $userId]);
    $sessionCount = (int)$countStmt->fetchColumn();

    if ($sessionCount > MAX_SESSIONS_PER_USER) {
        $evictCount = $sessionCount - MAX_SESSIONS_PER_USER;
        $evictStmt = $pdo->prepare(
            'DELETE FROM sessions WHERE user_id = :user_id
             ORDER BY expires_at ASC LIMIT :evict_count'
        );
        $evictStmt->bindValue(':user_id', $userId, PDO::PARAM_INT);
        $evictStmt->bindValue(':evict_count', $evictCount, PDO::PARAM_INT);
        $evictStmt->execute();
    }

    // Set the session cookie
    setSessionCookie($token);

    return $token;
}

/**
 * Set the session cookie with secure flags.
 *
 * @param string $token Raw session token
 */
function setSessionCookie(string $token): void {
    // SECURITY: Always true — HTTPS is enforced via Apache redirect + HSTS
    setcookie(SESSION_COOKIE_NAME, $token, [
        'expires'  => time() + SESSION_LIFETIME,
        'path'     => '/',
        'domain'   => '',
        'secure'   => true,
        'httponly'  => true,        // SECURITY: Prevents JavaScript access to cookie (mitigates XSS cookie theft)
        'samesite' => 'Strict',    // SECURITY: Prevents CSRF by not sending cookie on cross-site requests
    ]);
}

/**
 * Validate and retrieve the current session.
 *
 * @return array|null Session data with user info, or null if invalid
 */
function validateSession(): ?array {
    if (!isset($_COOKIE[SESSION_COOKIE_NAME])) {
        return null;
    }

    $token = $_COOKIE[SESSION_COOKIE_NAME];

    // Validate token format: must be exactly 64 hex characters
    if (!preg_match('/\A[0-9a-f]{64}\z/', $token)) {
        // SECURITY: Invalid token format, reject immediately
        destroySessionCookie();
        return null;
    }

    $tokenHash = hashSessionToken($token);
    $pdo = getDBConnection();

    $stmt = $pdo->prepare(
        'SELECT s.*, u.username, u.email, u.balance, u.bio, u.profile_image
         FROM sessions s
         JOIN users u ON s.user_id = u.id
         WHERE s.session_token_hash = :token_hash
         AND s.expires_at > NOW()
         AND s.created_at > DATE_SUB(NOW(), INTERVAL :absolute SECOND)'
    );
    $stmt->execute([':token_hash' => $tokenHash, ':absolute' => SESSION_ABSOLUTE_LIFETIME]);
    $session = $stmt->fetch();

    if (!$session) {
        destroySessionCookie();
        return null;
    }

    // SECURITY: Verify session is bound to the same IP and User-Agent
    $currentIP = getClientIP();
    $currentUAHash = getUserAgentHash();

    if (!hash_equals($session['ip_address'], $currentIP) ||
        !hash_equals($session['user_agent_hash'], $currentUAHash)) {
        // Session hijacking attempt detected - destroy the session
        destroySession($token);
        error_log(sprintf(
            'Session hijacking attempt: user_id=%d, original_ip=%s, current_ip=%s',
            $session['user_id'],
            $session['ip_address'],
            $currentIP
        ));
        return null;
    }

    // Extend session expiry (sliding window)
    $newExpiry = date('Y-m-d H:i:s', time() + SESSION_LIFETIME);
    $updateStmt = $pdo->prepare(
        'UPDATE sessions SET expires_at = :expires_at WHERE session_token_hash = :token_hash'
    );
    $updateStmt->execute([
        ':expires_at' => $newExpiry,
        ':token_hash' => $tokenHash,
    ]);

    // SECURITY: Rotate session token every 10 minutes
    // Limits the window during which a stolen token remains valid.
    $rotatedAt = strtotime($session['token_rotated_at'] ?? $session['created_at']);
    if (time() - $rotatedAt > TOKEN_ROTATION_INTERVAL) {
        $newToken = generateSessionToken();
        $newTokenHash = hashSessionToken($newToken);

        $rotateStmt = $pdo->prepare(
            'UPDATE sessions SET session_token_hash = :new_hash, token_rotated_at = NOW()
             WHERE session_token_hash = :old_hash'
        );
        $rotateStmt->execute([
            ':new_hash' => $newTokenHash,
            ':old_hash' => $tokenHash,
        ]);

        // Set new cookie with rotated token
        setSessionCookie($newToken);
        return $session;
    }

    // Refresh cookie expiry
    setSessionCookie($token);

    return $session;
}

/**
 * Destroy a session (logout).
 *
 * @param string|null $token Raw session token (if null, uses cookie)
 */
function destroySession(?string $token = null): void {
    if ($token === null) {
        $token = $_COOKIE[SESSION_COOKIE_NAME] ?? null;
    }

    if ($token !== null) {
        $tokenHash = hashSessionToken($token);
        $pdo = getDBConnection();

        $stmt = $pdo->prepare('DELETE FROM sessions WHERE session_token_hash = :token_hash');
        $stmt->execute([':token_hash' => $tokenHash]);
    }

    destroySessionCookie();
}

/**
 * Remove the session cookie from the client.
 */
function destroySessionCookie(): void {
    // SECURITY: Always true — HTTPS is enforced via Apache redirect + HSTS
    setcookie(SESSION_COOKIE_NAME, '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'domain'   => '',
        'secure'   => true,
        'httponly'  => true,
        'samesite' => 'Strict',
    ]);
    unset($_COOKIE[SESSION_COOKIE_NAME]);
}

/**
 * Clean up expired sessions (called periodically).
 */
function cleanExpiredSessions(): void {
    $pdo = getDBConnection();
    $stmt = $pdo->prepare('DELETE FROM sessions WHERE expires_at < NOW()');
    $stmt->execute();
}

/**
 * Require authentication. Redirects to login if no valid session.
 *
 * @return array The session data (guaranteed valid)
 */
function requireAuth(): array {
    $session = validateSession();
    if ($session === null) {
        header('Location: /login.php');
        exit;
    }
    return $session;
}

/**
 * Get the CSRF token for the current session.
 *
 * @param array $session Session data from validateSession()
 * @return string CSRF token
 */
function getCSRFToken(array $session): string {
    return $session['csrf_token'];
}

/**
 * Validate a CSRF token from a form submission.
 *
 * @param array  $session        Session data
 * @param string $submittedToken The token from the form
 * @return bool True if valid
 */
function validateCSRFToken(array $session, string $submittedToken): bool {
    // SECURITY: Use hash_equals for timing-safe comparison to prevent timing attacks
    return hash_equals($session['csrf_token'], $submittedToken);
}

/**
 * Generate an HMAC signature for form tamper-proofing.
 * Signs the CSRF token + form action to create a tamper-proof integrity check.
 *
 * @param string $csrfToken The CSRF token
 * @param string $formAction The form action (e.g., 'transfer', 'edit_profile')
 * @return string HMAC-SHA256 hex digest
 */
function generateFormMAC(string $csrfToken, string $formAction): string {
    $data = $csrfToken . '|' . $formAction;
    return hash_hmac('sha256', $data, HMAC_SECRET);
}

/**
 * Verify an HMAC signature for form tamper-proofing.
 *
 * @param string $csrfToken The CSRF token from the session
 * @param string $formAction The expected form action
 * @param string $submittedMAC The HMAC from the form
 * @return bool True if valid (not tampered)
 */
function verifyFormMAC(string $csrfToken, string $formAction, string $submittedMAC): bool {
    $expectedMAC = generateFormMAC($csrfToken, $formAction);
    return hash_equals($expectedMAC, $submittedMAC);
}

/**
 * Generate a pre-session CSRF token for login form (double-submit cookie pattern).
 * Since there's no session before login, we use a cookie-based approach.
 *
 * @return string The CSRF token (also set as a cookie)
 */
function generateLoginCSRFToken(): string {
    $token = bin2hex(random_bytes(32));

    setcookie('LOGIN_CSRF', $token, [
        'expires'  => time() + 600, // 10 minutes
        'path'     => '/',
        'domain'   => '',
        'secure'   => true,
        'httponly'  => true,
        'samesite' => 'Strict',
    ]);

    return $token;
}

/**
 * Validate the login CSRF token (double-submit cookie pattern).
 *
 * @param string $submittedToken Token from the form
 * @return bool True if valid
 */
function validateLoginCSRFToken(string $submittedToken): bool {
    $cookieToken = $_COOKIE['LOGIN_CSRF'] ?? '';
    if (empty($cookieToken) || empty($submittedToken)) {
        return false;
    }
    return hash_equals($cookieToken, $submittedToken);
}

/**
 * Clear the login CSRF cookie after use.
 */
function clearLoginCSRFCookie(): void {
    setcookie('LOGIN_CSRF', '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'domain'   => '',
        'secure'   => true,
        'httponly'  => true,
        'samesite' => 'Strict',
    ]);
    unset($_COOKIE['LOGIN_CSRF']);
}
