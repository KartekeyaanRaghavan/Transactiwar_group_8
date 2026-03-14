<?php
/**
 * Dashboard Page
 *
 * Shows user overview: balance, recent transactions, quick actions.
 * Requires authentication.
 */

define('APP_ROOT', dirname(__DIR__));

require_once APP_ROOT . '/includes/security_headers.php';
require_once APP_ROOT . '/includes/session.php';
require_once APP_ROOT . '/includes/validation.php';
require_once APP_ROOT . '/includes/logger.php';
require_once APP_ROOT . '/includes/functions.php';

setSecurityHeaders();

// Require authentication
$session = requireAuth();

// Get fresh user data
$user = getUserById($session['user_id']);
if (!$user) {
    destroySession();
    header('Location: /login.php');
    exit;
}

// Update session balance for navbar display
$session['balance'] = $user['balance'];

// SECURITY: Rate limit page-view requests to prevent DoS on DB-intensive pages
if (checkAndRecordPageViewAttempt($session['user_id'])) {
    http_response_code(429);
    exit('Too many requests. Please wait a moment and try again.');
}

// Get recent transactions
$recentTransactions = getTransactionHistory($session['user_id'], 5);

// Log activity
logActivity('dashboard.php', $session);

// Periodically clean expired sessions (1% chance per request to avoid performance impact)
if (random_int(1, 100) === 1) {
    cleanExpiredSessions();
}

$pageTitle = 'Dashboard';
require_once APP_ROOT . '/templates/header.php';
?>

<h1 class="page-title">
    Welcome, <?php echo sanitizeOutput($user['username']); ?>!
</h1>

<div class="dashboard-stats">
    <div class="stat-card">
        <div class="stat-value balance"><?php echo formatCurrency((float) $user['balance']); ?></div>
        <div class="stat-label">Current Balance</div>
    </div>
    <div class="stat-card">
        <div class="stat-value">#<?php echo (int) $user['id']; ?></div>
        <div class="stat-label">Your User ID</div>
    </div>
    <div class="stat-card">
        <div class="stat-value email"><?php echo sanitizeOutput($user['email']); ?></div>
        <div class="stat-label">Email</div>
    </div>
</div>

<div class="quick-actions">
    <a href="/transfer.php" class="btn btn-primary btn-block btn-padded">Transfer Money</a>
    <a href="/search.php" class="btn btn-outline btn-block btn-padded">Search Users</a>
    <a href="/profile.php" class="btn btn-outline btn-block btn-padded">My Profile</a>
</div>

<div class="card">
    <div class="card-header">
        <h2 class="card-title">Recent Transactions</h2>
    </div>

    <?php if (empty($recentTransactions)): ?>
        <div class="empty-state">
            <h3>No transactions yet</h3>
            <p>Start by transferring money to another user.</p>
        </div>
    <?php else: ?>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Type</th>
                        <th>User</th>
                        <th>Amount</th>
                        <th>Comment</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($recentTransactions as $txn): ?>
                        <?php $isSender = ((int) $txn['sender_id'] === (int) $session['user_id']); ?>
                        <tr>
                            <td><?php echo sanitizeOutput(formatTimestamp($txn['created_at'])); ?></td>
                            <td><?php echo $isSender ? 'Sent' : 'Received'; ?></td>
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
                                    <?php
                                    // Show comment only to receiver (or sender who wrote it)
                                    // The comment is visible to the receiver as per requirements
                                    ?>
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
        <div class="view-all">
            <a href="/transactions.php" class="btn btn-outline">View All Transactions</a>
        </div>
    <?php endif; ?>
</div>

<?php require_once APP_ROOT . '/templates/footer.php'; ?>
