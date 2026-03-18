<?php
/**
 * User Search Page
 *
 * Search for users by username with paginated results.
 * Requires authentication.
 *
 * Security:
 * - Search input validated and sanitized
 * - SQL injection prevented via prepared statements with LIKE wildcard escaping
 * - XSS prevented via output encoding
 * - Per-IP rate limiting to prevent search abuse and data enumeration
 * - Page parameter validated as bounded positive integer
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

define('SEARCH_PER_PAGE', 5);
define('SEARCH_MAX_PAGE', 500); // prevents absurdly large OFFSET values

$searchQuery = '';
$results     = [];
$searched    = false;
$errorMessage = '';
$totalResults = 0;
$totalPages   = 0;
$currentPage  = 1;

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['q'])) {
    $searched = true;

    // SECURITY: Validate and clamp page number — prevents negative/huge OFFSETs
    $currentPage = max(1, min(SEARCH_MAX_PAGE, (int)($_GET['page'] ?? 1)));

    // SECURITY: Atomically check and record search rate limit per IP
    $ip = getClientIP();
    if (checkAndRecordSearchAttempt($ip)) {
        $errorMessage = 'Too many search requests. Please wait a moment before searching again.';
    } else {
        $queryResult = validateSearchQuery((string)$_GET['q']);

        if (!$queryResult['valid']) {
            $errorMessage = $queryResult['error'];
        } else {
            $searchQuery  = $queryResult['query'];
            $totalResults = countSearchResults($searchQuery);
            $totalPages   = (int) ceil($totalResults / SEARCH_PER_PAGE);

            // Clamp page to valid range after knowing total
            if ($totalPages > 0) {
                $currentPage = min($currentPage, $totalPages);
            }

            $offset  = ($currentPage - 1) * SEARCH_PER_PAGE;
            $results = searchUsers($searchQuery, SEARCH_PER_PAGE, $offset);
        }
    }
}

// NOTE: No HTML encoding here — logActivity stores raw data in the DB.
logActivity('search.php' . ($searchQuery ? ' (query: ' . $searchQuery . ')' : ''), $session);

$pageTitle = 'Search Users';
require_once APP_ROOT . '/templates/header.php';
?>

<div class="card">
    <div class="card-header">
        <h1 class="card-title">Search Users</h1>
        <p class="card-subtitle">Find users by username</p>
    </div>

    <form method="GET" action="/search.php" class="search-form">
        <input type="text" name="q" class="form-input"
               value="<?php echo sanitizeOutput($searchQuery); ?>"
               placeholder="Enter username..."
               maxlength="100"
               required
               autofocus>
        <button type="submit" class="btn btn-primary">Search</button>
    </form>

    <?php if ($searched): ?>
        <?php if ($errorMessage): ?>
            <div class="alert alert-error"><?php echo sanitizeOutput($errorMessage); ?></div>
        <?php elseif (!empty($results)): ?>
            <p class="search-results-count">
                Found <?php echo $totalResults; ?> result<?php echo $totalResults !== 1 ? 's' : ''; ?>
                for "<?php echo sanitizeOutput($searchQuery); ?>"
                &mdash; Page <?php echo $currentPage; ?> of <?php echo $totalPages; ?>
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
                                <?php if (!empty($resultUser['display_name'])): ?>
                                    <span class="user-display-name"><?php echo sanitizeOutput($resultUser['display_name']); ?></span>
                                <?php endif; ?>
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

            <?php if ($totalPages > 1): ?>
                <div class="pagination">
                    <?php
                    $baseUrl = '/search.php?q=' . urlencode($searchQuery) . '&page=';
                    ?>

                    <?php if ($currentPage > 1): ?>
                        <a href="<?php echo sanitizeOutput($baseUrl . ($currentPage - 1)); ?>"
                           class="btn btn-outline btn-sm">&laquo; Prev</a>
                    <?php else: ?>
                        <span class="btn btn-outline btn-sm btn-disabled">&laquo; Prev</span>
                    <?php endif; ?>

                    <?php
                    // Show up to 7 page buttons, centred on current page
                    $window = 3;
                    $pageStart = max(1, $currentPage - $window);
                    $pageEnd   = min($totalPages, $currentPage + $window);

                    if ($pageStart > 1): ?>
                        <a href="<?php echo sanitizeOutput($baseUrl . 1); ?>"
                           class="btn btn-outline btn-sm">1</a>
                        <?php if ($pageStart > 2): ?>
                            <span class="pagination-ellipsis">&hellip;</span>
                        <?php endif; ?>
                    <?php endif; ?>

                    <?php for ($p = $pageStart; $p <= $pageEnd; $p++): ?>
                        <?php if ($p === $currentPage): ?>
                            <span class="btn btn-primary btn-sm"><?php echo $p; ?></span>
                        <?php else: ?>
                            <a href="<?php echo sanitizeOutput($baseUrl . $p); ?>"
                               class="btn btn-outline btn-sm"><?php echo $p; ?></a>
                        <?php endif; ?>
                    <?php endfor; ?>

                    <?php if ($pageEnd < $totalPages): ?>
                        <?php if ($pageEnd < $totalPages - 1): ?>
                            <span class="pagination-ellipsis">&hellip;</span>
                        <?php endif; ?>
                        <a href="<?php echo sanitizeOutput($baseUrl . $totalPages); ?>"
                           class="btn btn-outline btn-sm"><?php echo $totalPages; ?></a>
                    <?php endif; ?>

                    <?php if ($currentPage < $totalPages): ?>
                        <a href="<?php echo sanitizeOutput($baseUrl . ($currentPage + 1)); ?>"
                           class="btn btn-outline btn-sm">Next &raquo;</a>
                    <?php else: ?>
                        <span class="btn btn-outline btn-sm btn-disabled">Next &raquo;</span>
                    <?php endif; ?>
                </div>
            <?php endif; ?>

        <?php else: ?>
            <div class="empty-state">
                <h3>No users found</h3>
                <p>No results matching "<?php echo sanitizeOutput($searchQuery); ?>"</p>
            </div>
        <?php endif; ?>
    <?php endif; ?>
</div>

<?php require_once APP_ROOT . '/templates/footer.php'; ?>
