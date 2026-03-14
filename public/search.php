<?php
/**
 * User Search Page
 *
 * Search for users by username or user ID.
 * Requires authentication.
 *
 * Security:
 * - Search input validated and sanitized
 * - SQL injection prevented via prepared statements with LIKE wildcard escaping
 * - XSS prevented via output encoding
 * - Per-IP rate limiting to prevent search abuse and data enumeration
 * - Results capped at 5 per request
 */

define('APP_ROOT', dirname(__DIR__));

require_once APP_ROOT . '/includes/security_headers.php';
require_once APP_ROOT . '/includes/session.php';
require_once APP_ROOT . '/includes/validation.php';
require_once APP_ROOT . '/includes/logger.php';
require_once APP_ROOT . '/includes/functions.php';

setSecurityHeaders();

$session = requireAuth();

$currentUser = getUserById($session['user_id']);
if ($currentUser) {
    $session['balance'] = $currentUser['balance'];
}

$searchQuery = '';
$results = [];
$searched = false;
$errorMessage = '';

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['q'])) {
    $searched = true;

    // SECURITY: Atomically check and record search rate limit per IP
    // (single transaction with FOR UPDATE eliminates the old TOCTOU race)
    $ip = getClientIP();
    if (checkAndRecordSearchAttempt($ip)) {
        $errorMessage = 'Too many search requests. Please wait a moment before searching again.';
    } else {
        $queryResult = validateSearchQuery((string)$_GET['q']);

        if (!$queryResult['valid']) {
            $errorMessage = $queryResult['error'];
        } else {
            $searchQuery = $queryResult['query'];
            // SECURITY: Results capped at 5 to limit data enumeration
            $results = searchUsers($searchQuery, 5);
        }
    }
}

logActivity('search.php' . ($searchQuery ? ' (query: ' . sanitizeOutput($searchQuery) . ')' : ''), $session);

$pageTitle = 'Search Users';
require_once APP_ROOT . '/templates/header.php';
?>

<div class="card">
    <div class="card-header">
        <h1 class="card-title">Search Users</h1>
        <p class="card-subtitle">Find users by username or user ID</p>
    </div>

    <form method="GET" action="/search.php" class="search-form">
        <input type="text" name="q" class="form-input"
               value="<?php echo sanitizeOutput($searchQuery); ?>"
               placeholder="Enter username or user ID..."
               maxlength="100"
               required
               autofocus>
        <button type="submit" class="btn btn-primary">Search</button>
    </form>

    <?php if ($searched): ?>
        <?php if (!empty($results)): ?>
            <p class="search-results-count">
                Found <?php echo count($results); ?> result<?php echo count($results) !== 1 ? 's' : ''; ?>
                for "<?php echo sanitizeOutput($searchQuery); ?>"
            </p>
            <div class="user-list">
                <?php foreach ($results as $resultUser): ?>
                    <div class="user-card">
                        <div class="user-card-info">
                            <?php if ($resultUser['profile_image']): ?>
                                <img src="/image.php?file=<?php echo sanitizeOutput($resultUser['profile_image']); ?>"
                                     alt="" class="user-card-avatar">
                            <?php else: ?>
                                <div class="user-card-avatar-placeholder">
                                    <?php echo strtoupper(mb_substr($resultUser['username'], 0, 1, 'UTF-8')); ?>
                                </div>
                            <?php endif; ?>
                            <div class="user-card-details">
                                <h3><?php echo sanitizeOutput($resultUser['username']); ?></h3>
                                <span class="user-id-small">ID: #<?php echo (int) $resultUser['id']; ?></span>
                            </div>
                        </div>
                        <div class="user-card-actions">
                            <a href="/view_profile.php?id=<?php echo (int) $resultUser['id']; ?>"
                               class="btn btn-outline btn-sm">
                                View Profile
                            </a>
                            <?php if ((int) $resultUser['id'] !== (int) $session['user_id']): ?>
                                <a href="/transfer.php?to=<?php echo (int) $resultUser['id']; ?>"
                                   class="btn btn-success btn-sm">
                                    Send Money
                                </a>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php else: ?>
            <div class="empty-state">
                <h3>No users found</h3>
                <p>No results matching "<?php echo sanitizeOutput($searchQuery); ?>"</p>
            </div>
        <?php endif; ?>
    <?php endif; ?>
</div>

<?php require_once APP_ROOT . '/templates/footer.php'; ?>
