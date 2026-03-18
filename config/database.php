<?php
/**
 * Database Configuration
 * Uses PDO with prepared statements to prevent SQL injection.
 * All queries throughout the application MUST use prepared statements.
 *
 * SECURITY: Credentials are loaded ONLY from environment variables.
 * No hardcoded fallbacks — if env vars are missing, the app fails safely.
 */

// SECURITY: Only load from environment variables (set via Docker env_file)
// Fail hard if any variable is missing — no hardcoded fallbacks that leak internals
$dbHost = getenv('DB_HOST');
if ($dbHost === false || $dbHost === '') {
    error_log('FATAL: DB_HOST environment variable is not set');
    die('Application configuration error. Contact administrator.');
}
define('DB_HOST', $dbHost);

$dbName = getenv('DB_NAME');
if ($dbName === false || $dbName === '') {
    error_log('FATAL: DB_NAME environment variable is not set');
    die('Application configuration error. Contact administrator.');
}
define('DB_NAME', $dbName);

$dbUser = getenv('DB_USER');
if ($dbUser === false || $dbUser === '') {
    error_log('FATAL: DB_USER environment variable is not set');
    die('Application configuration error. Contact administrator.');
}
define('DB_USER', $dbUser);

// SECURITY: Fail hard if DB_PASS is missing — never fall back to empty string
$dbPass = getenv('DB_PASS');
if ($dbPass === false || $dbPass === '') {
    error_log('FATAL: DB_PASS environment variable is not set');
    die('Application configuration error. Contact administrator.');
}
// SECURITY: Fail hard if DB_PASS is the known insecure placeholder from docker-compose defaults
if ($dbPass === 'CHANGE_ME_DB') {
    error_log('FATAL: DB_PASS is still the insecure placeholder value "CHANGE_ME_DB"');
    die('Application configuration error: default credentials detected. Contact administrator.');
}
define('DB_PASS', $dbPass);
define('DB_CHARSET', 'utf8mb4');

// HMAC Secret for request integrity verification (tamper-proofing)
// SECURITY: Must be set via environment — a random fallback would change per-request,
// breaking all HMAC verification (form integrity checks would always fail)
$hmacSecret = getenv('HMAC_SECRET');
if ($hmacSecret === false || $hmacSecret === '') {
    error_log('FATAL: HMAC_SECRET environment variable is not set');
    die('Application configuration error. Contact administrator.');
}
define('HMAC_SECRET', $hmacSecret);

/**
 * Get PDO database connection.
 * Uses singleton pattern to avoid multiple connections.
 *
 * Security: PDO with ERRMODE_EXCEPTION and EMULATE_PREPARES disabled
 * ensures real prepared statements are used (not emulated), which provides
 * stronger SQL injection protection.
 *
 * @return PDO
 */
function getDBConnection(): PDO {
    static $pdo = null;

    if ($pdo === null) {
        $dsn = sprintf(
            'mysql:host=%s;dbname=%s;charset=%s',
            DB_HOST,
            DB_NAME,
            DB_CHARSET
        );

        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            // SECURITY: Disable emulated prepares to use real prepared statements
            // This ensures MySQL handles parameter binding, preventing SQL injection
            PDO::ATTR_EMULATE_PREPARES   => false,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            // SECURITY: Disable multi-statement queries to prevent stacked injection
            PDO::MYSQL_ATTR_MULTI_STATEMENTS => false,
        ];

        try {
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        } catch (PDOException $e) {
            // SECURITY: Never expose database error details to the user
            error_log('Database connection failed: ' . $e->getMessage());
            die('A database error occurred. Please try again later.');
        }
    }

    return $pdo;
}
