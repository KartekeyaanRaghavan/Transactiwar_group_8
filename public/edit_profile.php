<?php
/**
 * Edit Profile Page
 *
 * Allows users to update their email, bio, and profile image.
 * Username cannot be changed (as per requirements).
 *
 * Security measures:
 * - CSRF protection on form
 * - HMAC-based tamper-proofing
 * - Input validation on all fields
 * - Secure file upload handling (GD re-processing)
 * - XSS prevention via output encoding
 */

define('APP_ROOT', dirname(__DIR__));

require_once APP_ROOT . '/includes/security_headers.php';
require_once APP_ROOT . '/includes/session.php';
require_once APP_ROOT . '/includes/validation.php';
require_once APP_ROOT . '/includes/logger.php';
require_once APP_ROOT . '/includes/functions.php';

setSecurityHeaders();

$session = requireAuth();

$user = getUserById($session['user_id']);
if (!$user) {
    destroySession();
    header('Location: /login.php');
    exit;
}

$session['balance'] = $user['balance'];

$errorMessage = '';
$successMessage = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // SECURITY: Validate CSRF token
    $csrfToken = (string)($_POST['csrf_token'] ?? '');
    if (!validateCSRFToken($session, $csrfToken)) {
        $errorMessage = 'Invalid request. Please try again.';
    } else {
        // SECURITY: Verify HMAC form integrity (tamper-proofing)
        $formMAC = (string)($_POST['form_mac'] ?? '');
        if (!verifyFormMAC($session['csrf_token'], 'edit_profile', $formMAC)) {
            $errorMessage = 'Invalid request. Please try again.';
            error_log('HMAC tamper detected on edit_profile form from IP: ' . getClientIP());
        } else {
            $email = trim($_POST['email'] ?? '');
            $bio   = $_POST['bio'] ?? '';

            // Validate email
            $emailResult = validateEmail($email);
            if (!$emailResult['valid']) {
                $errorMessage = $emailResult['error'];
            } else {
                // Validate bio
                $bioResult = validateText($bio, 10000);
                if (!$bioResult['valid']) {
                    $errorMessage = $bioResult['error'];
                } else {
                    // Update profile
                    $updateResult = updateProfile($session['user_id'], $email, $bioResult['text']);
                    if ($updateResult['success']) {
                        $successMessage = 'Profile updated successfully!';

                        // Handle profile image upload if provided
                        if (isset($_FILES['profile_image']) && $_FILES['profile_image']['error'] !== UPLOAD_ERR_NO_FILE) {
                            $uploadResult = uploadProfileImage($session['user_id'], $_FILES['profile_image']);
                            if (!$uploadResult['success']) {
                                $errorMessage = 'Profile updated but image upload failed: ' . $uploadResult['error'];
                            } else {
                                $successMessage = 'Profile and image updated successfully!';
                            }
                        }

                        // Refresh user data
                        $user = getUserById($session['user_id']);
                    } else {
                        $errorMessage = $updateResult['error'];
                    }
                }
            }
        }
    }
}

logActivity('edit_profile.php', $session);

$csrfToken = getCSRFToken($session);
// SECURITY: Generate HMAC for form tamper-proofing
$formMAC = generateFormMAC($csrfToken, 'edit_profile');

$pageTitle = 'Edit Profile';
require_once APP_ROOT . '/templates/header.php';
?>

<div class="form-container">
    <div class="card">
        <div class="card-header">
            <h1 class="card-title">Edit Profile</h1>
            <p class="card-subtitle">Update your personal details. Username cannot be changed.</p>
        </div>

        <form method="POST" action="/edit_profile.php" enctype="multipart/form-data" novalidate>
            <!-- SECURITY: CSRF token to prevent cross-site request forgery -->
            <input type="hidden" name="csrf_token" value="<?php echo sanitizeOutput($csrfToken); ?>">
            <!-- SECURITY: HMAC form integrity token (tamper-proofing) -->
            <input type="hidden" name="form_mac" value="<?php echo sanitizeOutput($formMAC); ?>">

            <div class="form-group">
                <label class="form-label">Username</label>
                <input type="text" class="form-input" value="<?php echo sanitizeOutput($user['username']); ?>" disabled>
                <div class="form-hint">Username cannot be changed.</div>
            </div>

            <div class="form-group">
                <label for="email" class="form-label">Email</label>
                <input type="email" id="email" name="email" class="form-input"
                       value="<?php echo sanitizeOutput($user['email']); ?>"
                       required maxlength="255">
            </div>

            <div class="form-group">
                <label for="bio" class="form-label">Biography</label>
                <textarea id="bio" name="bio" class="form-textarea"
                          maxlength="10000"
                          placeholder="Tell us about yourself..."
                          rows="6"><?php echo sanitizeOutput($user['bio'] ?? ''); ?></textarea>
                <div class="form-hint">Max 10,000 characters.</div>
            </div>

            <div class="form-group">
                <label for="profile_image" class="form-label">Profile Image</label>
                <?php if ($user['profile_image']): ?>
                    <div class="image-preview-row">
                        <img src="/image.php?file=<?php echo sanitizeOutput($user['profile_image']); ?>"
                             alt="Current profile image"
                             class="profile-image-preview">
                        <span class="image-label">Current image</span>
                    </div>
                <?php endif; ?>
                <div class="file-input-wrapper">
                    <input type="file" id="profile_image" name="profile_image"
                           accept="image/jpeg,image/png,image/gif,image/webp">
                </div>
                <div class="form-hint">Max 2MB. Allowed: JPEG, PNG, GIF, WebP. Images are re-processed for security.</div>
            </div>

            <div class="btn-group">
                <button type="submit" class="btn btn-primary btn-flex-grow">Save Changes</button>
                <a href="/profile.php" class="btn btn-outline">Cancel</a>
            </div>
        </form>
    </div>
</div>

<?php require_once APP_ROOT . '/templates/footer.php'; ?>
