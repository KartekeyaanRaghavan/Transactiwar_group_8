<?php
/**
 * Authentication Module
 *
 * Handles user registration, login, and password management.
 *
 * Security:
 * - Passwords hashed with Argon2id (64 MiB memory, 4 iterations, 2 threads)
 * - Timing-safe comparison via password_verify
 * - Dual-layer rate limiting on login attempts (per IP+username and per-username globally)
 * - No information leakage on login failure (generic error message)
 */

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/validation.php';
require_once __DIR__ . '/session.php';

// Argon2id password hashing options (more memory-hard than bcrypt, resists GPU/ASIC attacks)
define('ARGON2ID_MEMORY_COST', 65536); // 64 MiB
define('ARGON2ID_TIME_COST',    4);
define('ARGON2ID_THREADS',      2);
define('ARGON2ID_OPTIONS', [
    'memory_cost' => ARGON2ID_MEMORY_COST,
    'time_cost'   => ARGON2ID_TIME_COST,
    'threads'     => ARGON2ID_THREADS,
]);

// Rate limiting: Layer 1 — per (IP, username) pair, 15-minute window
define('MAX_LOGIN_ATTEMPTS', 5);
define('RATE_LIMIT_WINDOW', 900); // 15 minutes in seconds

// Rate limiting: Layer 2 — per username globally (all IPs), 6-hour window
// Detects distributed brute-force across multiple source IPs
define('MAX_LOGIN_ATTEMPTS_PER_USERNAME', 20);
define('LOGIN_USERNAME_WINDOW', 21600); // 6 hours in seconds

// Rate limiting: max registration attempts per IP per window
define('MAX_REGISTER_ATTEMPTS', 5);
define('REGISTER_RATE_LIMIT_WINDOW', 3600); // 1 hour in seconds

// CAPTCHA: show image CAPTCHA after this many failures from the same IP
define('CAPTCHA_THRESHOLD', 3);
define('CAPTCHA_VALIDITY', 300); // 5 minutes — session answer expires after this

/**
 * Register a new user.
 *
 * @param string $username
 * @param string $email
 * @param string $password
 * @return array ['success' => bool, 'error' => string|null, 'user_id' => int|null]
 */
function registerUser(string $username, string $email, string $password): array {
    $ip = getClientIP();

    // SECURITY: Atomically check and record registration rate limit per IP
    if (checkAndRecordRegisterAttempt($ip)) {
        return ['success' => false, 'error' => 'Too many registration attempts. Please try again later.', 'user_id' => null];
    }

    // Validate inputs
    $usernameResult = validateUsername($username);
    if (!$usernameResult['valid']) {
        return ['success' => false, 'error' => $usernameResult['error'], 'user_id' => null];
    }

    $emailResult = validateEmail($email);
    if (!$emailResult['valid']) {
        return ['success' => false, 'error' => $emailResult['error'], 'user_id' => null];
    }

    $passwordResult = validatePassword($password);
    if (!$passwordResult['valid']) {
        return ['success' => false, 'error' => $passwordResult['error'], 'user_id' => null];
    }

    $pdo = getDBConnection();

    // Check if username or email already exists
    $stmt = $pdo->prepare('SELECT id FROM users WHERE username = :username OR email = :email LIMIT 1');
    $stmt->execute([':username' => $username, ':email' => $email]);

    if ($stmt->fetch()) {
        // SECURITY: Generic message to prevent username/email enumeration
        return ['success' => false, 'error' => 'Username or email is already taken.', 'user_id' => null];
    }

    // Hash password with Argon2id (memory-hard, resists GPU/ASIC brute-force)
    $passwordHash = password_hash($password, PASSWORD_ARGON2ID, ARGON2ID_OPTIONS);

    if ($passwordHash === false) {
        error_log('Password hashing failed during registration');
        return ['success' => false, 'error' => 'Registration failed. Please try again.', 'user_id' => null];
    }

    // Insert user with initial balance of Rs. 100
    $stmt = $pdo->prepare(
        'INSERT INTO users (username, email, password_hash, balance) VALUES (:username, :email, :password_hash, 100.00)'
    );

    try {
        $stmt->execute([
            ':username'      => $username,
            ':email'         => $email,
            ':password_hash' => $passwordHash,
        ]);
        $userId = (int) $pdo->lastInsertId();
        return ['success' => true, 'error' => null, 'user_id' => $userId];
    } catch (PDOException $e) {
        // Handle duplicate key errors (race condition)
        if ($e->getCode() === '23000') {
            return ['success' => false, 'error' => 'Username or email is already taken.', 'user_id' => null];
        }
        error_log('Registration error: ' . $e->getMessage());
        return ['success' => false, 'error' => 'Registration failed. Please try again.', 'user_id' => null];
    }
}

/**
 * Authenticate a user (login).
 *
 * @param string $username
 * @param string $password
 * @return array ['success' => bool, 'error' => string|null, 'token' => string|null]
 */
function loginUser(string $username, string $password): array {
    $ip = getClientIP();

    // SECURITY: Dual-layer atomic rate limit — blocks before any DB user lookup
    // to prevent username enumeration via timing differences.
    if (checkAndRecordLoginAttempt($ip, $username)) {
        return [
            'success' => false,
            'error'   => 'Too many login attempts. Please try again later.',
            'token'   => null,
        ];
    }

    $pdo = getDBConnection();

    $stmt = $pdo->prepare('SELECT id, username, password_hash FROM users WHERE username = :username LIMIT 1');
    $stmt->execute([':username' => $username]);
    $user = $stmt->fetch();

    if (!$user) {
        // SECURITY: Run full Argon2id verification with a dummy hash so timing is
        // identical whether the username exists or not — prevents timing-based
        // username enumeration. Hash format: m=65536,t=4,p=2 (matches ARGON2ID_OPTIONS).
        password_verify($password, '$argon2id$v=19$m=65536,t=4,p=2$YWJjZGVmZ2hpamtsbW5vcA$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY');

        return ['success' => false, 'error' => 'Invalid username or password.', 'token' => null];
    }

    if (!password_verify($password, $user['password_hash'])) {
        return ['success' => false, 'error' => 'Invalid username or password.', 'token' => null];
    }

    // SECURITY: Rehash on-the-fly if algorithm or parameters changed (e.g., bcrypt → Argon2id migration)
    if (password_needs_rehash($user['password_hash'], PASSWORD_ARGON2ID, ARGON2ID_OPTIONS)) {
        $newHash = password_hash($password, PASSWORD_ARGON2ID, ARGON2ID_OPTIONS);
        $updateStmt = $pdo->prepare('UPDATE users SET password_hash = :hash WHERE id = :id');
        $updateStmt->execute([':hash' => $newHash, ':id' => $user['id']]);
    }

    // SECURITY: Do NOT clear rate limit on success — counters expire naturally.
    // Clearing on success is exploitable: attacker logs into own account to reset
    // their IP counter, then resumes brute-force against the target account.

    // Create new session — evicts any existing sessions for this user first
    $token = createSession($user['id']);

    if ($token === null) {
        return [
            'success' => false,
            'error'   => 'Login failed due to a server error. Please try again.',
            'token'   => null,
        ];
    }

    return ['success' => true, 'error' => null, 'token' => $token];
}

/**
 * Atomically check and record a login attempt using dual-layer rate limiting.
 *
 * Layer 1: per (IP, username) — max 5 attempts in 15 minutes.
 *   Blocks credential-stuffing and targeted brute-force from a single IP.
 * Layer 2: per username globally — max 20 attempts in 6 hours.
 *   Blocks distributed brute-force spread across many source IPs.
 *
 * SECURITY: Rate limit counters are NEVER cleared on success. Clearing on
 * success is exploitable: attacker logs into own account to reset their IP
 * counter, then resumes brute-force. Counters expire naturally after the window.
 *
 * @param string $ip       Client IP address
 * @param string $username Username being authenticated
 * @return bool True if rate limited (login should be blocked), false otherwise
 */
function checkAndRecordLoginAttempt(string $ip, string $username): bool {
    $pdo = getDBConnection();

    $pdo->beginTransaction();
    try {
        // Layer 1: per-(IP, username) count in last 15 minutes
        $stmt = $pdo->prepare(
            'SELECT COUNT(*) FROM failed_login_attempts
             WHERE ip_address = :ip AND username = :username
             AND created_at > DATE_SUB(NOW(), INTERVAL :window SECOND)
             FOR UPDATE'
        );
        $stmt->execute([':ip' => $ip, ':username' => $username, ':window' => RATE_LIMIT_WINDOW]);
        if ((int) $stmt->fetchColumn() >= MAX_LOGIN_ATTEMPTS) {
            $pdo->commit();
            return true; // rate limited (Layer 1)
        }

        // Layer 2: per-username global count in last 6 hours
        $stmt2 = $pdo->prepare(
            'SELECT COUNT(*) FROM failed_login_attempts
             WHERE username = :username
             AND created_at > DATE_SUB(NOW(), INTERVAL :window SECOND)
             FOR UPDATE'
        );
        $stmt2->execute([':username' => $username, ':window' => LOGIN_USERNAME_WINDOW]);
        if ((int) $stmt2->fetchColumn() >= MAX_LOGIN_ATTEMPTS_PER_USERNAME) {
            $pdo->commit();
            return true; // rate limited (Layer 2 — distributed attack)
        }

        // Record this attempt
        $pdo->prepare(
            'INSERT INTO failed_login_attempts (ip_address, username) VALUES (:ip, :username)'
        )->execute([':ip' => $ip, ':username' => $username]);

        $pdo->commit();
        return false; // not rate limited
    } catch (PDOException $e) {
        $pdo->rollBack();
        error_log('Login rate limit error: ' . $e->getMessage());
        return true; // fail closed — DB error must not bypass login protection
    }
}

/**
 * Invalidate all active sessions for a user.
 * Call this after a password change to force re-authentication on all devices.
 *
 * @param int $userId
 */
function invalidateAllSessionsForUser(int $userId): void {
    $pdo = getDBConnection();
    $pdo->prepare('DELETE FROM sessions WHERE user_id = :user_id')
        ->execute([':user_id' => $userId]);
}

/**
 * Get the count of recent failed login attempts for a specific IP + username pair.
 * Used for progressive login delay.
 *
 * @param string $ip
 * @param string $username
 * @return int Number of recent failed attempts
 */
function getRecentFailedAttemptCount(string $ip, string $username): int {
    $pdo = getDBConnection();
    $stmt = $pdo->prepare(
        'SELECT COUNT(*) FROM failed_login_attempts
         WHERE ip_address = :ip AND username = :username
         AND created_at > DATE_SUB(NOW(), INTERVAL :window SECOND)'
    );
    $stmt->execute([':ip' => $ip, ':username' => $username, ':window' => RATE_LIMIT_WINDOW]);
    return (int) $stmt->fetchColumn();
}

/**
 * Get the count of recent failed login attempts from an IP across all usernames.
 * Used to decide whether to show CAPTCHA on the login form.
 *
 * @param string $ip
 * @return int Total recent failed attempts from this IP
 */
function getRecentFailedAttemptCountByIP(string $ip): int {
    $pdo = getDBConnection();
    $stmt = $pdo->prepare(
        'SELECT COUNT(*) FROM failed_login_attempts
         WHERE ip_address = :ip
         AND created_at > DATE_SUB(NOW(), INTERVAL :window SECOND)'
    );
    $stmt->execute([':ip' => $ip, ':window' => RATE_LIMIT_WINDOW]);
    return (int) $stmt->fetchColumn();
}

/**
 * Verify a CAPTCHA answer against the server-side session value.
 *
 * The answer is stored in a PHP native session by public/captcha.php and is
 * never sent to the client, so it cannot be read from the HTML and scripted.
 * The answer is cleared after the first verification attempt (one-time use).
 *
 * @param string $userAnswer The user's submitted answer
 * @return bool True if correct and not expired
 */
function verifyCaptcha(string $userAnswer): bool {
    session_name('TWCAP');
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    if (!isset($_SESSION['captcha_answer'], $_SESSION['captcha_ts'])) {
        return false;
    }

    // Check expiry
    if (time() - (int)$_SESSION['captcha_ts'] > CAPTCHA_VALIDITY) {
        unset($_SESSION['captcha_answer'], $_SESSION['captcha_ts']);
        return false;
    }

    $correct = ((int)trim($userAnswer) === (int)$_SESSION['captcha_answer']);

    // One-time use — clear regardless of whether the answer was right or wrong
    unset($_SESSION['captcha_answer'], $_SESSION['captcha_ts']);

    return $correct;
}

function checkAndRecordRegisterAttempt(string $ip): bool {
    $pdo = getDBConnection();

    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare(
            'SELECT id, attempts FROM rate_limits
             WHERE ip_address = :ip AND action = :action
             AND first_attempt > DATE_SUB(NOW(), INTERVAL :window SECOND)
             FOR UPDATE'
        );
        $stmt->execute([
            ':ip'     => $ip,
            ':action' => 'register',
            ':window' => REGISTER_RATE_LIMIT_WINDOW,
        ]);
        $record = $stmt->fetch();

        if ($record && (int) $record['attempts'] >= MAX_REGISTER_ATTEMPTS) {
            $pdo->rollBack();
            return true; // rate limited
        }

        if ($record) {
            $pdo->prepare('UPDATE rate_limits SET attempts = attempts + 1, last_attempt = NOW() WHERE id = :id')
                ->execute([':id' => $record['id']]);
        } else {
            $pdo->prepare('INSERT INTO rate_limits (ip_address, action, attempts, first_attempt) VALUES (:ip, :action, 1, NOW())')
                ->execute([':ip' => $ip, ':action' => 'register']);
        }

        $pdo->commit();
        return false; // not rate limited
    } catch (PDOException $e) {
        $pdo->rollBack();
        error_log('Registration rate limit error: ' . $e->getMessage());
        return true; // fail closed — DB error must not bypass registration protection
    }
}
