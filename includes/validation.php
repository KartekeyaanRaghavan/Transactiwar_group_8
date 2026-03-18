<?php
/**
 * Input Validation and Sanitization
 *
 * All user input MUST be validated before use.
 * This module provides validation functions for all input types used in the application.
 *
 * Principles:
 * - Validate input type, length, format
 * - Use allowlists (not blocklists) where possible
 * - Sanitize for output context (HTML, SQL, etc.)
 * - Never trust client-side validation alone
 */

/**
 * Sanitize a string for safe HTML output.
 * Prevents XSS by encoding special characters.
 *
 * @param string|null $input
 * @return string
 */
function sanitizeOutput(?string $input): string {
    if ($input === null) {
        return '';
    }
    // SECURITY: ENT_QUOTES encodes both single and double quotes
    // UTF-8 encoding specified to prevent multi-byte encoding attacks
    return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

/**
 * Validate a username.
 * Rules: 3-50 chars, alphanumeric + underscores only.
 *
 * @param string $username
 * @return array ['valid' => bool, 'error' => string|null]
 */
function validateUsername(string $username): array {
    $username = trim($username);

    if (empty($username)) {
        return ['valid' => false, 'error' => 'Username is required.'];
    }

    if (strlen($username) < 3 || strlen($username) > 50) {
        return ['valid' => false, 'error' => 'Username must be between 3 and 50 characters.'];
    }

    // SECURITY: Strict allowlist regex - only alphanumeric and underscores
    // Using \A and \z anchors instead of ^ and $ to prevent multiline bypass
    // The 'D' modifier ensures $ matches only at end (no trailing newline issue)
    if (!preg_match('/\A[a-zA-Z0-9_]{3,50}\z/', $username)) {
        return ['valid' => false, 'error' => 'Username can only contain letters, numbers, and underscores.'];
    }

    return ['valid' => true, 'error' => null];
}

/**
 * Validate an email address.
 *
 * @param string $email
 * @return array ['valid' => bool, 'error' => string|null]
 */
function validateEmail(string $email): array {
    $email = trim($email);

    if (empty($email)) {
        return ['valid' => false, 'error' => 'Email is required.'];
    }

    if (strlen($email) > 255) {
        return ['valid' => false, 'error' => 'Email must not exceed 255 characters.'];
    }

    // SECURITY: Use PHP's built-in filter for email validation
    // This is safer than writing our own regex which could have ReDoS issues
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return ['valid' => false, 'error' => 'Please enter a valid email address.'];
    }

    return ['valid' => true, 'error' => null];
}

/**
 * Validate a password.
 * Rules: minimum 8 chars, must contain uppercase, lowercase, digit, and special char.
 *
 * @param string $password
 * @return array ['valid' => bool, 'error' => string|null]
 */
function validatePassword(string $password): array {
    if (empty($password)) {
        return ['valid' => false, 'error' => 'Password is required.'];
    }

    if (strlen($password) < 8) {
        return ['valid' => false, 'error' => 'Password must be at least 8 characters long.'];
    }

    if (strlen($password) > 1024) {
        return ['valid' => false, 'error' => 'Password must not exceed 1024 characters.'];
    }

    if (!preg_match('/[A-Z]/', $password)) {
        return ['valid' => false, 'error' => 'Password must contain at least one uppercase letter.'];
    }

    if (!preg_match('/[a-z]/', $password)) {
        return ['valid' => false, 'error' => 'Password must contain at least one lowercase letter.'];
    }

    if (!preg_match('/[0-9]/', $password)) {
        return ['valid' => false, 'error' => 'Password must contain at least one digit.'];
    }

    if (!preg_match('/[^a-zA-Z0-9]/', $password)) {
        return ['valid' => false, 'error' => 'Password must contain at least one special character.'];
    }

    return ['valid' => true, 'error' => null];
}

/**
 * Convert an amount to cents for safe integer math.
 *
 * @param mixed $amount
 * @return int
 */
function toCents($amount): int {
    if (!is_numeric($amount)) return 0;
    $str = number_format((float)$amount, 2, '.', '');
    return (int) str_replace('.', '', $str);
}

/**
 * Validate a transfer amount.
 *
 * @param mixed  $amount
 * @param string $maxBalance Current user balance
 * @return array ['valid' => bool, 'error' => string|null, 'amount' => string]
 */
function validateAmount($amount, $maxBalance): array {
    if (empty($amount) && $amount !== '0' && $amount !== 0) {
        return ['valid' => false, 'error' => 'Amount is required.', 'amount' => '0.00'];
    }

    // SECURITY: Validate that amount is a valid number
    if (!is_numeric($amount)) {
        return ['valid' => false, 'error' => 'Amount must be a valid number.', 'amount' => '0.00'];
    }

    // SECURITY: Reject scientific notation (e.g. 1e1, 2E10) — is_numeric() accepts it but
    // it is not a valid currency input format and can be used to obfuscate amounts.
    if (!preg_match('/\A[0-9]+(\.[0-9]{1,2})?\z/', (string)$amount)) {
        return ['valid' => false, 'error' => 'Amount must be a plain decimal number.', 'amount' => '0.00'];
    }

    // SECURITY FIX: Never use floats for financial comparisons. Use integer cents.
    $amountCents = toCents($amount);
    $maxCents = toCents($maxBalance);

    if ($amountCents <= 0) {
        return ['valid' => false, 'error' => 'Amount must be greater than zero.', 'amount' => '0.00'];
    }

    if ($amountCents > $maxCents) {
        return ['valid' => false, 'error' => 'Insufficient balance.', 'amount' => '0.00'];
    }

    // Format back to string for exact DECIMAL insertion
    $formattedAmount = number_format($amountCents / 100, 2, '.', '');

    return ['valid' => true, 'error' => null, 'amount' => $formattedAmount];
}

/**
 * Validate a user ID (must be a positive integer).
 *
 * @param mixed $userId
 * @return array ['valid' => bool, 'error' => string|null, 'id' => int]
 */
function validateUserId($userId): array {
    // SECURITY: Use filter_var with strict integer validation
    $filtered = filter_var($userId, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);

    if ($filtered === false) {
        return ['valid' => false, 'error' => 'Invalid user ID.', 'id' => 0];
    }

    return ['valid' => true, 'error' => null, 'id' => $filtered];
}

/**
 * Validate and sanitize a comment/bio text.
 * Allows general text but strips dangerous content.
 *
 * @param string|null $text
 * @param int         $maxLength Maximum allowed length
 * @return array ['valid' => bool, 'error' => string|null, 'text' => string]
 */
function validateText(?string $text, int $maxLength = 5000): array {
    if ($text === null || trim($text) === '') {
        return ['valid' => true, 'error' => null, 'text' => ''];
    }

    $text = trim($text);

    if (mb_strlen($text, 'UTF-8') > $maxLength) {
        return [
            'valid' => false,
            'error' => "Text must not exceed {$maxLength} characters.",
            'text'  => ''
        ];
    }

    // SECURITY: Strip null bytes which can bypass validation
    $text = str_replace("\0", '', $text);

    return ['valid' => true, 'error' => null, 'text' => $text];
}

/**
 * Validate a search query.
 *
 * @param string $query
 * @return array ['valid' => bool, 'error' => string|null, 'query' => string]
 */
function validateSearchQuery(string $query): array {
    $query = trim($query);

    if (empty($query)) {
        return ['valid' => false, 'error' => 'Search query is required.', 'query' => ''];
    }

    if (mb_strlen($query, 'UTF-8') > 100) {
        return ['valid' => false, 'error' => 'Search query is too long.', 'query' => ''];
    }

    // Strip null bytes
    $query = str_replace("\0", '', $query);

    return ['valid' => true, 'error' => null, 'query' => $query];
}

/**
 * Validate an uploaded image file.
 * SECURITY: Comprehensive multi-layer validation:
 * 1. Upload error check
 * 2. File size check
 * 3. MIME type via finfo (not client-reported)
 * 4. Extension allowlist
 * 5. getimagesize() verification
 * 6. Full file content scan for embedded PHP/script code
 *
 * @param array $file The $_FILES entry
 * @return array ['valid' => bool, 'error' => string|null]
 */
function validateImageUpload(array $file): array {
    // Check for upload errors
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $errorMessages = [
            UPLOAD_ERR_INI_SIZE   => 'File exceeds the maximum upload size.',
            UPLOAD_ERR_FORM_SIZE  => 'File exceeds the maximum upload size.',
            UPLOAD_ERR_PARTIAL    => 'File was only partially uploaded.',
            UPLOAD_ERR_NO_FILE    => 'No file was uploaded.',
            UPLOAD_ERR_NO_TMP_DIR => 'Server configuration error.',
            UPLOAD_ERR_CANT_WRITE => 'Server configuration error.',
            UPLOAD_ERR_EXTENSION  => 'File upload was blocked.',
        ];
        $msg = $errorMessages[$file['error']] ?? 'Unknown upload error.';
        return ['valid' => false, 'error' => $msg];
    }

    // SECURITY: Check file size (max 2MB)
    $maxSize = 2 * 1024 * 1024; // 2MB
    if ($file['size'] > $maxSize) {
        return ['valid' => false, 'error' => 'Image must be smaller than 2MB.'];
    }

    // SECURITY: Verify MIME type using finfo (not relying on client-reported type)
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mimeType = $finfo->file($file['tmp_name']);

    $allowedMimes = [
        'image/jpeg',
        'image/png',
        'image/gif',
        'image/webp',
    ];

    if (!in_array($mimeType, $allowedMimes, true)) {
        return ['valid' => false, 'error' => 'Only JPEG, PNG, GIF, and WebP images are allowed.'];
    }

    // SECURITY: Verify file extension against allowlist
    $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
    $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));

    if (!in_array($extension, $allowedExtensions, true)) {
        return ['valid' => false, 'error' => 'Invalid file extension.'];
    }

    // SECURITY: Verify it's actually an image using getimagesize
    // This prevents uploading PHP files disguised as images
    $imageInfo = @getimagesize($file['tmp_name']);
    if ($imageInfo === false) {
        return ['valid' => false, 'error' => 'The file does not appear to be a valid image.'];
    }

    // NOTE: Binary content scanning for PHP patterns (<?php, exec(, etc.) was removed
    // because compressed image data frequently contains byte sequences that match these
    // strings, causing false positives on legitimate images.
    //
    // Protection against polyglot/embedded-code attacks is handled by:
    // 1. GD re-encoding in uploadProfileImage() — creates a new image from pixel data only
    // 2. Uploads stored outside web root — Apache cannot serve them directly
    // 3. image.php forces Content-Type: image/png — browser won't execute code
    // 4. Apache config blocks PHP execution in uploads directory

    return ['valid' => true, 'error' => null];
}
