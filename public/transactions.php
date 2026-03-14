<?php
/**
 * Transaction History Page
 *
 * Displays full transaction history with pagination.
 * Requires authentication.
 *
 * Security:
 * - Pagination parameters validated as integers
 * - All output is XSS-safe
 * - Only shows transactions involving the current user
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

// SECURITY: Rate limit page-view requests to prevent DoS on DB-intensive pages
if (checkAndRecordPageViewAttempt($session['user_id'])) {
    http_response_code(429);
    exit('Too many requests. Please wait a moment and try again.');
}

// Pagination
$perPage = 20;
$page = max(1, (int) ($_GET['page'] ?? 1));
$offset = ($page - 1) * $perPage;

// Get transactions
$transactions = getTransactionHistory($session['user_id'], $perPage + 1, $offset);

// Check if there's a next page
$hasNextPage = count($transactions) > $perPage;
if ($hasNextPage) {
    array_pop($transactions); // Remove the extra record
}

logActivity('transactions.php', $session);

$pageTitle = 'Transaction History';
require_once APP_ROOT . '/templates/header.php';
?>

<div class="card">
    <div class="card-header">
        <h1 class="card-title">Transaction History</h1>
        <p class="card-subtitle">Complete history of your sent and received transactions</p>
    </div>

    <?php if (empty($transactions)): ?>
        <div class="empty-state">
            <h3>No transactions yet</h3>
            <p>Your transaction history will appear here once you send or receive money.</p>
            <a href="/transfer.php" class="btn btn-primary btn-mt">Make a Transfer</a>
        </div>
    <?php else: ?>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Date</th>
                        <th>Type</th>
                        <th>User</th>
                        <th>Amount</th>
                        <th>Comment</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($transactions as $txn): ?>
                        <?php $isSender = ((int) $txn['sender_id'] === (int) $session['user_id']); ?>
                        <tr>
                            <td>#<?php echo (int) $txn['id']; ?></td>
                            <td><?php echo sanitizeOutput(formatTimestamp($txn['created_at'])); ?></td>
                            <td>
                                <span class="<?php echo $isSender ? 'badge-sent' : 'badge-received'; ?>">
                                    <?php echo $isSender ? 'SENT' : 'RECEIVED'; ?>
                                </span>
                            </td>
                            <td>
                                <?php if ($isSender): ?>
                                    <a href="/view_profile.php?id=<?php echo (int) $txn['receiver_id']; ?>">
                                        <?php echo sanitizeOutput($txn['receiver_username']); ?>
                                    </a>
                                <?php else: ?>
                                    <a href="/view_profile.php?id=<?php echo (int) $txn['sender_id']; ?>">
                                        <?php echo sanitizeOutput($txn['sender_username']); ?>
                                    </a>
                                <?php endif; ?>
                            </td>
                            <td class="<?php echo $isSender ? 'amount-sent' : 'amount-received'; ?>">
                                <?php echo $isSender ? '-' : '+'; ?><?php echo formatCurrency((float) $txn['amount']); ?>
                            </td>
                            <td>
                                <?php if (!empty($txn['comment'])): ?>
                                    <span class="comment-text" title="<?php echo sanitizeOutput($txn['comment']); ?>">
                                        <?php echo sanitizeOutput($txn['comment']); ?>
                                    </span>
                                <?php else: ?>
                                    <span class="text-muted">—</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <!-- Pagination -->
        <div class="pagination">
            <?php if ($page > 1): ?>
                <a href="/transactions.php?page=<?php echo $page - 1; ?>" class="btn btn-outline">Previous</a>
            <?php endif; ?>
            <span class="btn btn-outline cursor-default">Page <?php echo $page; ?></span>
            <?php if ($hasNextPage): ?>
                <a href="/transactions.php?page=<?php echo $page + 1; ?>" class="btn btn-outline">Next</a>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</div>

<?php require_once APP_ROOT . '/templates/footer.php'; ?>
