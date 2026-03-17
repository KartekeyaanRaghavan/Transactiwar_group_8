<?php
/**
 * View Another User's Profile
 *
 * Displays a public profile of another user.
 * Requires authentication.
 *
 * Security:
 * - User ID is validated as integer, output is XSS-safe.
 * - IDOR protection: email is only visible for the logged-in user's own profile.
 *   Other users can only see username, bio, profile image, and account age.
 */

define('APP_ROOT', dirname(__DIR__));

require_once APP_ROOT . '/includes/security_headers.php';
require_once APP_ROOT . '/includes/session.php';
require_once APP_ROOT . '/includes/validation.php';
require_once APP_ROOT . '/includes/logger.php';
require_once APP_ROOT . '/includes/functions.php';

setSecurityHeaders();

$session = requireAuth();

if (checkAndRecordProfileViewAttempt($session['user_id'])) {
    http_response_code(429);
    $pageTitle = 'Too Many Requests';
    require_once APP_ROOT . '/templates/header.php';
    echo '<div class="card"><div class="empty-state"><h3>Too many requests</h3><p>Please wait before viewing more profiles.</p></div></div>';
    require_once APP_ROOT . '/templates/footer.php';
    exit;
}

// Get fresh balance for navbar
$currentUser = getUserById($session['user_id']);
if ($currentUser) {
    $session['balance'] = $currentUser['balance'];
}

$errorMessage = '';
$profileUser = null;

// Validate user ID from query parameter
$userIdParam = $_GET['id'] ?? '';
$idResult = validateUserId($userIdParam);

if (!$idResult['valid']) {
    $errorMessage = 'Invalid user ID.';
} else {
    $profileUser = getUserById($idResult['id']);
    if (!$profileUser) {
        $errorMessage = 'User not found.';
    }
}

// SECURITY: Determine if this is the user's own profile
$isOwnProfile = ($profileUser && (int)$profileUser['id'] === (int)$session['user_id']);

logActivity('view_profile.php' . ($profileUser ? ' (user: ' . $profileUser['username'] . ')' : ''), $session);

$pageTitle = $profileUser ? $profileUser['username'] . "'s Profile" : 'User Profile';
require_once APP_ROOT . '/templates/header.php';
?>

<?php if ($errorMessage): ?>
    <div class="card">
        <div class="empty-state">
            <h3><?php echo sanitizeOutput($errorMessage); ?></h3>
            <p><a href="/search.php">Search for users</a></p>
        </div>
    </div>
<?php else: ?>
    <div class="card">
        <div class="card-header card-header-flex">
            <h1 class="card-title"><?php echo sanitizeOutput($profileUser['username']); ?>'s Profile</h1>
            <?php if (!$isOwnProfile): ?>
                <a href="/transfer.php?to=<?php echo (int) $profileUser['id']; ?>"
                   class="btn btn-success">Send Money</a>
            <?php else: ?>
                <a href="/edit_profile.php" class="btn btn-primary">Edit Profile</a>
            <?php endif; ?>
        </div>

        <div class="profile-header">
            <?php if ($profileUser['profile_image']): ?>
                <img src="/image.php?file=<?php echo sanitizeOutput($profileUser['profile_image']); ?>"
                     alt="Profile picture" class="profile-avatar">
            <?php else: ?>
                <div class="profile-avatar-placeholder">
                    <?php echo strtoupper(mb_substr($profileUser['username'], 0, 1, 'UTF-8')); ?>
                </div>
            <?php endif; ?>

            <div class="profile-info">
                <h2><?php echo sanitizeOutput($profileUser['username']); ?></h2>
                <p class="user-id">User ID: #<?php echo (int) $profileUser['id']; ?></p>
                <?php if ($isOwnProfile): ?>
                    <!-- SECURITY: Email only visible on own profile (IDOR fix) -->
                    <p class="user-email"><?php echo sanitizeOutput($profileUser['email']); ?></p>
                <?php endif; ?>
                <p class="member-since">
                    Member since <?php echo sanitizeOutput(formatTimestamp($profileUser['created_at'])); ?>
                </p>
            </div>
        </div>

        <h3 class="section-title">Biography</h3>
        <?php if (!empty($profileUser['bio'])): ?>
            <div class="profile-bio"><?php echo sanitizeOutput($profileUser['bio']); ?></div>
        <?php else: ?>
            <div class="profile-bio profile-bio-empty">This user hasn't added a biography yet.</div>
        <?php endif; ?>
    </div>
<?php endif; ?>

<?php require_once APP_ROOT . '/templates/footer.php'; ?>
