<?php
/**
 * Activity Logger
 *
 * Logs user activity as required: <Webpage, Username, Timestamp, Client's IP Address>
 * All page accesses are logged for security auditing.
 */

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/session.php';

/**
 * Log user activity.
 *
 * @param string     $page     The page being accessed
 * @param array|null $session  Session data (null for unauthenticated users)
 */
function logActivity(string $page, ?array $session = null): void {
    try {
        $pdo = getDBConnection();

        $userId   = $session['user_id'] ?? null;
        $username = $session['username'] ?? null;
        $ip       = getClientIP();
        $ua       = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

        // Truncate user agent to prevent excessively long entries
        if (mb_strlen($ua, 'UTF-8') > 500) {
            $ua = mb_substr($ua, 0, 500, 'UTF-8');
        }

        $stmt = $pdo->prepare(
            'INSERT INTO activity_log (user_id, username, page, ip_address, user_agent)
             VALUES (:user_id, :username, :page, :ip, :ua)'
        );
        $stmt->execute([
            ':user_id'  => $userId,
            ':username' => $username,
            ':page'     => $page,
            ':ip'       => $ip,
            ':ua'       => $ua,
        ]);
    } catch (PDOException $e) {
        // SECURITY: Don't let logging failures break the application
        // But do log to error log for investigation
        error_log('Activity logging failed: ' . $e->getMessage());
    }
}
