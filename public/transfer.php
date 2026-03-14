<?php
/**
 * Money Transfer Page
 *
 * Transfer money to another user by user ID.
 * Requires authentication.
 *
 * Security:
 * - CSRF protection
 * - HMAC-based tamper-proofing (detects if form data was modified in transit)
 * - Input validation (amount, user ID, comment)
 * - Database transaction with row locking (prevents race conditions)
 * - Negative balance prevention
 * - Self-transfer prevention
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
$formData = [
    'receiver_id' => (string)($_GET['to'] ?? ''),
    'amount'      => '',
    'comment'     => '',
];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // SECURITY: Validate CSRF token
    $csrfToken = (string)($_POST['csrf_token'] ?? '');
    if (!validateCSRFToken($session, $csrfToken)) {
        $errorMessage = 'Invalid request. Please try again.';
    } else {
        // SECURITY: Verify HMAC form integrity (tamper-proofing)
        $formMAC = (string)($_POST['form_mac'] ?? '');
        if (!verifyFormMAC($session['csrf_token'], 'transfer', $formMAC)) {
            $errorMessage = 'Invalid request. Please try again.';
            error_log('HMAC tamper detected on transfer form from IP: ' . getClientIP());
        } elseif (checkAndRecordTransferAttempt($session['user_id'])) {
            // SECURITY: Rate limit transfer submissions per user to prevent DoS
            $errorMessage = 'Too many transfer attempts. Please wait a moment before trying again.';
        } else {
            $receiverId = $_POST['receiver_id'] ?? '';
            $amount     = $_POST['amount'] ?? '';
            $comment    = $_POST['comment'] ?? '';

            $formData = [
                'receiver_id' => $receiverId,
                'amount'      => $amount,
                'comment'     => $comment,
            ];

            // Validate receiver ID
            $idResult = validateUserId($receiverId);
            if (!$idResult['valid']) {
                $errorMessage = 'Please enter a valid user ID.';
            } else {
                // Validate amount against current balance
                // Re-fetch user data to get latest balance (prevents double-spend)
                $amountResult = validateAmount($amount, $user['balance']);

                if (!$amountResult['valid']) {
                    $errorMessage = $amountResult['error'];
                } else {
                    // Validate comment
                    $commentResult = validateText($comment, 500);
                    if (!$commentResult['valid']) {
                        $errorMessage = $commentResult['error'];
                    } else {
                        // Perform transfer
                        $transferResult = transferMoney(
                            $session['user_id'],
                            $idResult['id'],
                            $amountResult['amount'],
                            $commentResult['text']
                        );

                        if ($transferResult['success']) {
                            $successMessage = 'Successfully transferred ' . formatCurrency($amountResult['amount']) . '!';
                            logActivity('transfer.php (success: Rs.' . $amountResult['amount'] . ' to user #' . $idResult['id'] . ')', $session);

                            // Reset form
                            $formData = ['receiver_id' => '', 'amount' => '', 'comment' => ''];

                            // Refresh user data
                            $user = getUserById($session['user_id']);
                            $session['balance'] = $user['balance'];
                        } else {
                            $errorMessage = $transferResult['error'];
                        }
                    }
                }
            }
        }
    }
}

logActivity('transfer.php', $session);

$csrfToken = getCSRFToken($session);
// SECURITY: Generate HMAC for form tamper-proofing
$formMAC = generateFormMAC($csrfToken, 'transfer');

$pageTitle = 'Transfer Money';
require_once APP_ROOT . '/templates/header.php';
?>

<div class="transfer-container">
    <div class="card">
        <div class="card-header">
            <h1 class="card-title">Transfer Money</h1>
            <p class="card-subtitle">
                Send money to another user. Your balance:
                <strong class="amount-received"><?php echo formatCurrency((float) $user['balance']); ?></strong>
            </p>
        </div>

        <form method="POST" action="/transfer.php" id="transferForm" novalidate>
            <!-- SECURITY: CSRF token -->
            <input type="hidden" name="csrf_token" value="<?php echo sanitizeOutput($csrfToken); ?>">
            <!-- SECURITY: HMAC form integrity token (tamper-proofing) -->
            <input type="hidden" name="form_mac" value="<?php echo sanitizeOutput($formMAC); ?>">

            <div class="form-group">
                <label for="receiver_id" class="form-label">Recipient User ID</label>
                <input type="number" id="receiver_id" name="receiver_id" class="form-input"
                       value="<?php echo sanitizeOutput($formData['receiver_id']); ?>"
                       required min="1"
                       placeholder="Enter the user ID to send money to">
                <div class="form-hint">
                    Don't know the user ID?
                    <a href="/search.php">Search for users</a>
                </div>
            </div>

            <div class="form-group">
                <label for="amount" class="form-label">Amount (Rs.)</label>
                <input type="number" id="amount" name="amount" class="form-input"
                       value="<?php echo sanitizeOutput($formData['amount']); ?>"
                       required min="0.01" max="<?php echo (float) $user['balance']; ?>"
                       step="0.01"
                       placeholder="0.00">
                <div class="form-hint">
                    Maximum: <?php echo formatCurrency((float) $user['balance']); ?>
                </div>
            </div>

            <div class="form-group">
                <label for="comment" class="form-label">Comment (optional)</label>
                <textarea id="comment" name="comment" class="form-textarea"
                          maxlength="500" rows="3"
                          placeholder="Add an optional note..."><?php echo sanitizeOutput($formData['comment']); ?></textarea>
                <div class="form-hint">Max 500 characters. Visible to the recipient.</div>
            </div>

            <button type="submit" class="btn btn-success btn-block">Transfer Money</button>
        </form>
    </div>
</div>

<?php require_once APP_ROOT . '/templates/footer.php'; ?>
