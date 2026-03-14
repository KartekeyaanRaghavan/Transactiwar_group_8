<?php
/**
 * My Profile Page
 *
 * Displays the current user's profile with option to edit.
 * Requires authentication.
 */

define('APP_ROOT', dirname(__DIR__));

require_once APP_ROOT . '/includes/security_headers.php';
require_once APP_ROOT . '/includes/session.php';
require_once APP_ROOT . '/includes/validation.php';
require_once APP_ROOT . '/includes/logger.php';
require_once APP_ROOT . '/includes/functions.php';

setSecurityHeaders();

$session = requireAuth();

// Get fresh user data
$user = getUserById($session['user_id']);
if (!$user) {
    destroySession();
    header('Location: /login.php');
    exit;
}

$session['balance'] = $user['balance'];

// SECURITY: Rate limit page-view requests to prevent DoS on DB-intensive pages
if (checkAndRecordPageViewAttempt($session['user_id'])) {
    http_response_code(429);
    exit('Too many requests. Please wait a moment and try again.');
}

logActivity('profile.php', $session);

$pageTitle = 'My Profile';
require_once APP_ROOT . '/templates/header.php';
?>

<div class="card">
    <div class="card-header card-header-flex">
        <h1 class="card-title">My Profile</h1>
        <a href="/edit_profile.php" class="btn btn-primary">Edit Profile</a>
    </div>

    <div class="profile-header">
        <?php if ($user['profile_image']): ?>
            <img src="/image.php?file=<?php echo sanitizeOutput($user['profile_image']); ?>"
                 alt="Profile picture" class="profile-avatar">
        <?php else: ?>
            <div class="profile-avatar-placeholder">
                <?php echo strtoupper(mb_substr($user['username'], 0, 1, 'UTF-8')); ?>
            </div>
        <?php endif; ?>

        <div class="profile-info">
            <h2><?php echo sanitizeOutput($user['username']); ?></h2>
            <p class="user-id">User ID: #<?php echo (int) $user['id']; ?></p>
            <p class="user-email"><?php echo sanitizeOutput($user['email']); ?></p>
        </div>
    </div>

    <div class="stats-grid-2">
        <div class="stat-card">
            <div class="stat-value balance"><?php echo formatCurrency((float) $user['balance']); ?></div>
            <div class="stat-label">Balance</div>
        </div>
        <div class="stat-card">
            <div class="stat-value stat-value-sm"><?php echo sanitizeOutput(formatTimestamp($user['created_at'])); ?></div>
            <div class="stat-label">Member Since</div>
        </div>
    </div>

    <h3 class="section-title">Biography</h3>
    <?php if (!empty($user['bio'])): ?>
        <div class="profile-bio"><?php echo sanitizeOutput($user['bio']); ?></div>
    <?php else: ?>
        <div class="profile-bio profile-bio-empty">No biography added yet. Click "Edit Profile" to add one.</div>
    <?php endif; ?>
</div>

<?php require_once APP_ROOT . '/templates/footer.php'; ?>
