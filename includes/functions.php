<?php
/**
 * Common Utility Functions
 */

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/validation.php';

/**
 * Get user by ID.
 *
 * @param int $userId
 * @return array|null
 */
function getUserById(int $userId): ?array {
    $pdo = getDBConnection();
    $stmt = $pdo->prepare(
        'SELECT id, username, display_name, email, balance, bio, profile_image, created_at, updated_at
         FROM users WHERE id = :id LIMIT 1'
    );
    $stmt->execute([':id' => $userId]);
    $user = $stmt->fetch();
    return $user ?: null;
}

/**
 * Count total users matching a search query.
 * Used to calculate pagination totals without fetching all rows.
 *
 * @param string $query Search query (plain, not yet LIKE-escaped)
 * @return int Total matching user count
 */
function countSearchResults(string $query): int {
    $pdo = getDBConnection();
    $escapedQuery = str_replace(['%', '_'], ['\\%', '\\_'], $query);
    $stmt = $pdo->prepare('SELECT COUNT(*) FROM users WHERE username LIKE :query');
    $stmt->bindValue(':query', '%' . $escapedQuery . '%', PDO::PARAM_STR);
    $stmt->execute();
    return (int) $stmt->fetchColumn();
}

/**
 * Search users by username (partial match).
 * SECURITY: Results limited to prevent data enumeration.
 * SECURITY: No email or balance returned — only non-sensitive display fields.
 * SECURITY: Search is username-only (no numeric ID lookup) to prevent sequential
 *           user enumeration by guessing integer IDs.
 *
 * @param string $query  Search query
 * @param int    $limit  Results per page (default 5)
 * @param int    $offset Row offset for pagination (default 0)
 * @return array List of matching users (only non-sensitive fields)
 */
function searchUsers(string $query, int $limit = 5, int $offset = 0): array {
    $pdo = getDBConnection();

    // SECURITY: Escape LIKE wildcards in user input to prevent wildcard injection
    $escapedQuery = str_replace(['%', '_'], ['\\%', '\\_'], $query);

    // SECURITY: Using prepared statements with LIKE and parameter binding
    // SECURITY: Not returning email, balance, or password_hash in search results
    $stmt = $pdo->prepare(
        'SELECT id, username, display_name, profile_image
         FROM users WHERE username LIKE :query
         ORDER BY username ASC LIMIT :limit OFFSET :offset'
    );
    $stmt->bindValue(':query',  '%' . $escapedQuery . '%', PDO::PARAM_STR);
    $stmt->bindValue(':limit',  $limit,  PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    $stmt->execute();

    return $stmt->fetchAll();
}

// Upload rate limiting: max uploads per user per window
define('MAX_UPLOAD_ATTEMPTS', 10);
define('UPLOAD_RATE_LIMIT_WINDOW', 3600); // 1 hour in seconds

/**
 * Atomically check and record a search attempt.
 * Uses SELECT ... FOR UPDATE inside a transaction to eliminate the TOCTOU
 * race between the old separate isSearchRateLimited / recordSearchAttempt calls.
 *
 * @param string $ip Client IP address
 * @return bool True if rate limited (search should be blocked), false otherwise
 */
function checkAndRecordSearchAttempt(string $ip): bool {
    $pdo = getDBConnection();

    // Clean up old records outside the transaction (non-critical)
    $pdo->prepare(
        'DELETE FROM search_rate_limits WHERE window_start < DATE_SUB(NOW(), INTERVAL 60 SECOND)'
    )->execute();

    $pdo->beginTransaction();
    try {
        // Lock all rows for this IP in the window — prevents concurrent inserts/updates
        $stmt = $pdo->prepare(
            'SELECT id, search_count FROM search_rate_limits
             WHERE ip_address = :ip
             AND window_start > DATE_SUB(NOW(), INTERVAL 60 SECOND)
             FOR UPDATE'
        );
        $stmt->execute([':ip' => $ip]);
        $rows = $stmt->fetchAll();

        $total = (int) array_sum(array_column($rows, 'search_count'));

        if ($total >= 10) {
            $pdo->rollBack();
            return true; // rate limited
        }

        if (!empty($rows)) {
            $pdo->prepare('UPDATE search_rate_limits SET search_count = search_count + 1 WHERE id = :id')
                ->execute([':id' => $rows[count($rows) - 1]['id']]);
        } else {
            $pdo->prepare(
                'INSERT INTO search_rate_limits (ip_address, search_count, window_start) VALUES (:ip, 1, NOW())'
            )->execute([':ip' => $ip]);
        }

        $pdo->commit();
        return false; // not rate limited
    } catch (PDOException $e) {
        $pdo->rollBack();
        error_log('Search rate limit error: ' . $e->getMessage());
        return true; // fail closed — DB error must not bypass search protection
    }
}

// Transfer rate limiting: max transfers per user per window
define('MAX_TRANSFER_ATTEMPTS', 10);
define('TRANSFER_RATE_LIMIT_WINDOW', 60); // 10 per minute per user

// Daily transfer velocity limits (cumulative, per calendar-rolling 24 hours)
define('MAX_TRANSFERS_PER_DAY',    10);
define('MAX_DAILY_TRANSFER_AMOUNT', 10000.00);

/**
 * Atomically check and record a profile image upload attempt.
 * Uses SELECT ... FOR UPDATE inside a transaction to eliminate TOCTOU.
 *
 * @param int $userId
 * @return bool True if rate limited (upload should be blocked)
 */
function checkAndRecordUploadAttempt(int $userId): bool {
    $pdo = getDBConnection();
    $identifier = 'user:' . $userId;

    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare(
            'SELECT id, attempts FROM rate_limits
             WHERE ip_address = :identifier AND action = :action
             AND first_attempt > DATE_SUB(NOW(), INTERVAL :window SECOND)
             FOR UPDATE'
        );
        $stmt->execute([
            ':identifier' => $identifier,
            ':action'     => 'upload',
            ':window'     => UPLOAD_RATE_LIMIT_WINDOW,
        ]);
        $record = $stmt->fetch();

        if ($record && (int) $record['attempts'] >= MAX_UPLOAD_ATTEMPTS) {
            $pdo->rollBack();
            return true; // rate limited
        }

        if ($record) {
            $pdo->prepare('UPDATE rate_limits SET attempts = attempts + 1, last_attempt = NOW() WHERE id = :id')
                ->execute([':id' => $record['id']]);
        } else {
            $pdo->prepare('INSERT INTO rate_limits (ip_address, action, attempts, first_attempt) VALUES (:identifier, :action, 1, NOW())')
                ->execute([':identifier' => $identifier, ':action' => 'upload']);
        }

        $pdo->commit();
        return false; // not rate limited
    } catch (PDOException $e) {
        $pdo->rollBack();
        error_log('Upload rate limit error: ' . $e->getMessage());
        return true; // fail closed — DB error must not bypass upload protection
    }
}

/**
 * Atomically check and record a transfer attempt.
 * Uses SELECT ... FOR UPDATE inside a transaction to eliminate TOCTOU.
 *
 * @param int $userId
 * @return bool True if rate limited (transfer should be blocked)
 */
function checkAndRecordTransferAttempt(int $userId): bool {
    $pdo = getDBConnection();
    $identifier = 'user:' . $userId;

    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare(
            'SELECT id, attempts FROM rate_limits
             WHERE ip_address = :identifier AND action = :action
             AND first_attempt > DATE_SUB(NOW(), INTERVAL :window SECOND)
             FOR UPDATE'
        );
        $stmt->execute([
            ':identifier' => $identifier,
            ':action'     => 'transfer',
            ':window'     => TRANSFER_RATE_LIMIT_WINDOW,
        ]);
        $record = $stmt->fetch();

        if ($record && (int) $record['attempts'] >= MAX_TRANSFER_ATTEMPTS) {
            $pdo->rollBack();
            return true; // rate limited
        }

        if ($record) {
            $pdo->prepare('UPDATE rate_limits SET attempts = attempts + 1, last_attempt = NOW() WHERE id = :id')
                ->execute([':id' => $record['id']]);
        } else {
            $pdo->prepare('INSERT INTO rate_limits (ip_address, action, attempts, first_attempt) VALUES (:identifier, :action, 1, NOW())')
                ->execute([':identifier' => $identifier, ':action' => 'transfer']);
        }

        $pdo->commit();
        return false; // not rate limited
    } catch (PDOException $e) {
        $pdo->rollBack();
        error_log('Transfer rate limit error: ' . $e->getMessage());
        return true; // fail closed — DB error must not bypass transfer protection
    }
}

// Page-view rate limiting: authenticated pages (dashboard, profile, transactions)
define('MAX_PAGE_VIEW_ATTEMPTS', 60);
define('PAGE_VIEW_RATE_LIMIT_WINDOW', 60); // 60 page-loads per minute per user

// Profile-view rate limiting: stricter limit to prevent user ID enumeration
define('MAX_PROFILE_VIEW_ATTEMPTS', 20);
define('PROFILE_VIEW_RATE_LIMIT_WINDOW', 60); // 20 profile views per minute per user

/**
 * Atomically check and record a page-view request for authenticated read-only pages.
 * Prevents enumeration and DoS on pages that trigger DB queries.
 * Uses SELECT ... FOR UPDATE inside a transaction to eliminate TOCTOU.
 *
 * @param int $userId Authenticated user ID
 * @return bool True if rate limited (request should be blocked)
 */
function checkAndRecordPageViewAttempt(int $userId): bool {
    $pdo = getDBConnection();
    $identifier = 'user:' . $userId;

    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare(
            'SELECT id, attempts FROM rate_limits
             WHERE ip_address = :identifier AND action = :action
             AND first_attempt > DATE_SUB(NOW(), INTERVAL :window SECOND)
             FOR UPDATE'
        );
        $stmt->execute([
            ':identifier' => $identifier,
            ':action'     => 'page_view',
            ':window'     => PAGE_VIEW_RATE_LIMIT_WINDOW,
        ]);
        $record = $stmt->fetch();

        if ($record && (int) $record['attempts'] >= MAX_PAGE_VIEW_ATTEMPTS) {
            $pdo->rollBack();
            return true; // rate limited
        }

        if ($record) {
            $pdo->prepare('UPDATE rate_limits SET attempts = attempts + 1, last_attempt = NOW() WHERE id = :id')
                ->execute([':id' => $record['id']]);
        } else {
            $pdo->prepare('INSERT INTO rate_limits (ip_address, action, attempts, first_attempt) VALUES (:identifier, :action, 1, NOW())')
                ->execute([':identifier' => $identifier, ':action' => 'page_view']);
        }

        $pdo->commit();
        return false; // not rate limited
    } catch (PDOException $e) {
        $pdo->rollBack();
        error_log('Page-view rate limit error: ' . $e->getMessage());
        return false; // fail open on error
    }
}

/**
 * Atomically check and record a profile-view request.
 * Stricter than the general page-view limit to prevent sequential user ID enumeration.
 * Uses SELECT ... FOR UPDATE inside a transaction to eliminate TOCTOU.
 *
 * @param int $userId Authenticated user ID
 * @return bool True if rate limited (request should be blocked)
 */
function checkAndRecordProfileViewAttempt(int $userId): bool {
    $pdo = getDBConnection();
    $identifier = 'user:' . $userId;

    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare(
            'SELECT id, attempts FROM rate_limits
             WHERE ip_address = :identifier AND action = :action
             AND first_attempt > DATE_SUB(NOW(), INTERVAL :window SECOND)
             FOR UPDATE'
        );
        $stmt->execute([
            ':identifier' => $identifier,
            ':action'     => 'profile_view',
            ':window'     => PROFILE_VIEW_RATE_LIMIT_WINDOW,
        ]);
        $record = $stmt->fetch();

        if ($record && (int) $record['attempts'] >= MAX_PROFILE_VIEW_ATTEMPTS) {
            $pdo->rollBack();
            return true; // rate limited
        }

        if ($record) {
            $pdo->prepare('UPDATE rate_limits SET attempts = attempts + 1, last_attempt = NOW() WHERE id = :id')
                ->execute([':id' => $record['id']]);
        } else {
            $pdo->prepare('INSERT INTO rate_limits (ip_address, action, attempts, first_attempt) VALUES (:identifier, :action, 1, NOW())')
                ->execute([':identifier' => $identifier, ':action' => 'profile_view']);
        }

        $pdo->commit();
        return false; // not rate limited
    } catch (PDOException $e) {
        $pdo->rollBack();
        error_log('Profile-view rate limit error: ' . $e->getMessage());
        return true; // fail closed — DB error must not bypass enumeration protection
    }
}

/**
 * Transfer money between users.
 *
 * @param int    $senderId
 * @param int    $receiverId
 * @param string $amount
 * @param string $comment Optional comment
 * @return array ['success' => bool, 'error' => string|null]
 */
function transferMoney(int $senderId, int $receiverId, string $amount, string $comment = ''): array {
    if ($senderId === $receiverId) {
        return ['success' => false, 'error' => 'You cannot transfer money to yourself.'];
    }

    if ($amount <= 0) {
        return ['success' => false, 'error' => 'Amount must be greater than zero.'];
    }

    $pdo = getDBConnection();

    try {
        $amountCents   = toCents($amount);
        $maxDailyCents = toCents(MAX_DAILY_TRANSFER_AMOUNT);

        // SECURITY: Use database transaction with row-level locking to prevent race conditions
        // SELECT ... FOR UPDATE locks the rows until the transaction completes
        $pdo->beginTransaction();

        // SECURITY FIX: Bidirectional Deadlock Prevention
        // Lock both rows in ascending ID order to prevent bidirectional deadlocks.
        $firstId  = min($senderId, $receiverId);
        $secondId = max($senderId, $receiverId);

        $lockStmt = $pdo->prepare('SELECT id, balance FROM users WHERE id = :id FOR UPDATE');

        $lockStmt->execute([':id' => $firstId]);
        $firstUser = $lockStmt->fetch();

        $lockStmt->execute([':id' => $secondId]);
        $secondUser = $lockStmt->fetch();

        $sender   = ($firstId === $senderId)   ? $firstUser  : $secondUser;
        $receiver = ($firstId === $receiverId) ? $firstUser  : $secondUser;

        if (!$sender) {
            $pdo->rollBack();
            return ['success' => false, 'error' => 'Sender account not found.'];
        }

        $senderBalanceCents = toCents($sender['balance']);
        if ($senderBalanceCents < $amountCents) {
            $pdo->rollBack();
            return ['success' => false, 'error' => 'Insufficient balance.'];
        }

        // SECURITY FIX: Daily velocity limit checked INSIDE the transaction (after FOR UPDATE locks)
        // Prevents concurrent requests from both passing the check and both committing.
        $velocityStmt = $pdo->prepare(
            'SELECT COUNT(*) as daily_count, COALESCE(SUM(amount), 0) as daily_total
             FROM transactions
             WHERE sender_id = :sender_id
               AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)'
        );
        $velocityStmt->execute([':sender_id' => $senderId]);
        $velocityResult = $velocityStmt->fetch();

        if ((int)$velocityResult['daily_count'] >= MAX_TRANSFERS_PER_DAY) {
            $pdo->rollBack();
            return ['success' => false, 'error' => 'Daily transfer limit reached (max ' . MAX_TRANSFERS_PER_DAY . ' transfers per day). Please try again tomorrow.'];
        }

        $dailySentCents = toCents($velocityResult['daily_total']);
        if ($dailySentCents + $amountCents > $maxDailyCents) {
            $pdo->rollBack();
            $effectiveRemainingCents = $maxDailyCents - $dailySentCents;
            if ($effectiveRemainingCents <= 0) {
                return ['success' => false, 'error' => 'Daily outflow limit of ' . formatCurrency(MAX_DAILY_TRANSFER_AMOUNT) . ' reached. Please try again tomorrow.'];
            } else {
                return ['success' => false, 'error' => 'Daily outflow limit would be exceeded. You can send up to ' . formatCurrency($effectiveRemainingCents / 100) . ' more today.'];
            }
        }

        if (!$receiver) {
            $pdo->rollBack();
            return ['success' => false, 'error' => 'Recipient account not found.'];
        }

        // Deduct from sender
        $deductStmt = $pdo->prepare('UPDATE users SET balance = balance - :amount WHERE id = :id');
        $deductStmt->execute([':amount' => $amount, ':id' => $senderId]);

        // Credit to receiver
        $creditStmt = $pdo->prepare('UPDATE users SET balance = balance + :amount WHERE id = :id');
        $creditStmt->execute([':amount' => $amount, ':id' => $receiverId]);

        // Record the transaction
        $txnStmt = $pdo->prepare(
            'INSERT INTO transactions (sender_id, receiver_id, amount, comment)
             VALUES (:sender_id, :receiver_id, :amount, :comment)'
        );
        $txnStmt->execute([
            ':sender_id'   => $senderId,
            ':receiver_id' => $receiverId,
            ':amount'      => $amount,
            ':comment'     => $comment,
        ]);

        $pdo->commit();
        return ['success' => true, 'error' => null];
    } catch (PDOException $e) {
        $pdo->rollBack();
        error_log('Transfer error: ' . $e->getMessage());
        return ['success' => false, 'error' => 'Transfer failed. Please try again.'];
    }
}

/**
 * Get transaction history for a user.
 *
 * @param int $userId
 * @param int $limit
 * @param int $offset
 * @return array
 */
function getTransactionHistory(int $userId, int $limit = 50, int $offset = 0): array {
    $pdo = getDBConnection();

    $stmt = $pdo->prepare(
        'SELECT t.id, t.sender_id, t.receiver_id, t.amount, t.comment, t.created_at,
                s.username AS sender_username, r.username AS receiver_username
         FROM transactions t
         JOIN users s ON t.sender_id = s.id
         JOIN users r ON t.receiver_id = r.id
         WHERE t.sender_id = :user_id1 OR t.receiver_id = :user_id2
         ORDER BY t.created_at DESC
         LIMIT :limit OFFSET :offset'
    );
    $stmt->bindValue(':user_id1', $userId, PDO::PARAM_INT);
    $stmt->bindValue(':user_id2', $userId, PDO::PARAM_INT);
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    $stmt->execute();

    return $stmt->fetchAll();
}

/**
 * Update user profile.
 *
 * @param int    $userId
 * @param string $email
 * @param string $bio
 * @return array ['success' => bool, 'error' => string|null]
 */
function updateProfile(int $userId, string $email, string $bio): array {
    $pdo = getDBConnection();

    // Check if email is taken by another user
    $stmt = $pdo->prepare('SELECT id FROM users WHERE email = :email AND id != :user_id LIMIT 1');
    $stmt->execute([':email' => $email, ':user_id' => $userId]);

    if ($stmt->fetch()) {
        return ['success' => false, 'error' => 'Unable to update profile. Please check your details and try again.'];
    }

    $updateStmt = $pdo->prepare(
        'UPDATE users SET email = :email, bio = :bio, updated_at = NOW() WHERE id = :id'
    );

    try {
        $updateStmt->execute([
            ':email' => $email,
            ':bio'   => $bio,
            ':id'    => $userId,
        ]);
        return ['success' => true, 'error' => null];
    } catch (PDOException $e) {
        if ($e->getCode() === '23000') {
            return ['success' => false, 'error' => 'This email is already in use.'];
        }
        error_log('Profile update error: ' . $e->getMessage());
        return ['success' => false, 'error' => 'Profile update failed. Please try again.'];
    }
}

/**
 * Handle profile image upload securely.
 * SECURITY: Images are re-processed through GD library to strip ALL embedded
 * code, metadata, EXIF data, and polyglot payloads. The original uploaded file
 * is never served directly.
 *
 * @param int   $userId
 * @param array $file $_FILES entry
 * @return array ['success' => bool, 'error' => string|null, 'filename' => string|null]
 */
function uploadProfileImage(int $userId, array $file): array {
    // SECURITY: Atomically check and record upload rate limit per user
    if (checkAndRecordUploadAttempt($userId)) {
        return ['success' => false, 'error' => 'Too many image uploads. Please wait before trying again.', 'filename' => null];
    }

    // Validate the image
    $validation = validateImageUpload($file);
    if (!$validation['valid']) {
        return ['success' => false, 'error' => $validation['error'], 'filename' => null];
    }

    // SECURITY: Generate a random filename to prevent path traversal and file overwrite attacks
    $newFilename = bin2hex(random_bytes(16)) . '.png'; // Always save as PNG after re-processing

    $uploadDir = '/var/www/uploads/profiles/';

    // Ensure upload directory exists
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0755, true);
    }

    $destination = $uploadDir . $newFilename;

    // SECURITY: Re-process the image through GD library
    // This creates a brand new image from the pixel data, stripping ALL metadata,
    // embedded PHP code, polyglot payloads, and EXIF data.
    $sourceImage = null;
    $mimeType = (new finfo(FILEINFO_MIME_TYPE))->file($file['tmp_name']);

    switch ($mimeType) {
        case 'image/jpeg':
            $sourceImage = @imagecreatefromjpeg($file['tmp_name']);
            break;
        case 'image/png':
            $sourceImage = @imagecreatefrompng($file['tmp_name']);
            break;
        case 'image/gif':
            $sourceImage = @imagecreatefromgif($file['tmp_name']);
            break;
        case 'image/webp':
            $sourceImage = @imagecreatefromwebp($file['tmp_name']);
            break;
        default:
            return ['success' => false, 'error' => 'Unsupported image format.', 'filename' => null];
    }

    if (!$sourceImage) {
        return ['success' => false, 'error' => 'Failed to process image. The file may be corrupted.', 'filename' => null];
    }

    // Create a clean new image (strips all metadata and embedded code)
    $width = imagesx($sourceImage);
    $height = imagesy($sourceImage);

    // Limit dimensions to prevent memory exhaustion
    $maxDim = 1024;
    if ($width > $maxDim || $height > $maxDim) {
        $ratio = min($maxDim / $width, $maxDim / $height);
        $newWidth = (int)($width * $ratio);
        $newHeight = (int)($height * $ratio);

        $resized = imagecreatetruecolor($newWidth, $newHeight);
        // Preserve transparency
        imagealphablending($resized, false);
        imagesavealpha($resized, true);
        imagecopyresampled($resized, $sourceImage, 0, 0, 0, 0, $newWidth, $newHeight, $width, $height);
        imagedestroy($sourceImage);
        $sourceImage = $resized;
    }

    // Save as PNG (lossless, clean format)
    imagealphablending($sourceImage, false);
    imagesavealpha($sourceImage, true);
    $saved = imagepng($sourceImage, $destination, 6); // Compression level 6
    imagedestroy($sourceImage);

    if (!$saved) {
        error_log('Failed to save re-processed image for user ' . $userId);
        return ['success' => false, 'error' => 'Failed to save image. Please try again.', 'filename' => null];
    }

    // Set proper permissions on the saved file
    chmod($destination, 0644);

    // Remove old profile image if exists
    $pdo = getDBConnection();
    $stmt = $pdo->prepare('SELECT profile_image FROM users WHERE id = :id');
    $stmt->execute([':id' => $userId]);
    $user = $stmt->fetch();

    if ($user && $user['profile_image']) {
        $oldFile = $uploadDir . $user['profile_image'];
        // SECURITY: Verify the old file is within the upload directory before deleting
        $realUploadDir = realpath($uploadDir);
        $realOldFile = realpath($oldFile);
        if ($realOldFile && strpos($realOldFile, $realUploadDir) === 0) {
            @unlink($oldFile);
        }
    }

    // Update database
    $updateStmt = $pdo->prepare('UPDATE users SET profile_image = :image WHERE id = :id');
    $updateStmt->execute([':image' => $newFilename, ':id' => $userId]);

    return ['success' => true, 'error' => null, 'filename' => $newFilename];
}

/**
 * Format currency amount.
 *
 * @param float $amount
 * @return string
 */
function formatCurrency(float $amount): string {
    return 'Rs. ' . number_format($amount, 2);
}

/**
 * Format a timestamp for display.
 *
 * @param string $timestamp
 * @return string
 */
function formatTimestamp(string $timestamp): string {
    return date('M d, Y h:i A', strtotime($timestamp));
}
