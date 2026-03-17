<?php
/**
 * CAPTCHA Image Endpoint
 *
 * Generates a distorted GD image of a math challenge.
 * The answer is stored server-side in a PHP native session — it is never sent to the client.
 * Supports +, -, and × operations to prevent trivial scripted solving.
 *
 * Security:
 * - Rate limited per IP (30 requests per minute) to prevent DoS via CPU-intensive GD rendering
 */

define('APP_ROOT', dirname(__DIR__));

require_once APP_ROOT . '/config/database.php';

// SECURITY: Rate limit captcha generation per IP to prevent DoS
// Each request creates a GD image (CPU cost) and a PHP session file (disk I/O)
$captchaIp = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$captchaRateLimited = false;

try {
    $pdo = getDBConnection();
    $pdo->beginTransaction();

    $stmt = $pdo->prepare(
        'SELECT id, attempts FROM rate_limits
         WHERE ip_address = :ip AND action = :action
         AND first_attempt > DATE_SUB(NOW(), INTERVAL 60 SECOND)
         FOR UPDATE'
    );
    $stmt->execute([':ip' => $captchaIp, ':action' => 'captcha']);
    $record = $stmt->fetch();

    if ($record && (int)$record['attempts'] >= 30) {
        $captchaRateLimited = true;
    } elseif ($record) {
        $pdo->prepare('UPDATE rate_limits SET attempts = attempts + 1, last_attempt = NOW() WHERE id = :id')
            ->execute([':id' => $record['id']]);
    } else {
        $pdo->prepare('INSERT INTO rate_limits (ip_address, action, attempts, first_attempt) VALUES (:ip, :action, 1, NOW())')
            ->execute([':ip' => $captchaIp, ':action' => 'captcha']);
    }

    $pdo->commit();
} catch (PDOException $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    // Fail open — don't block captcha if rate limiting DB fails
}

if ($captchaRateLimited) {
    http_response_code(429);
    // Return a 1x1 transparent PNG instead of generating an expensive image
    header('Content-Type: image/png');
    header('Cache-Control: no-store');
    $tiny = imagecreatetruecolor(1, 1);
    imagesavealpha($tiny, true);
    $transparent = imagecolorallocatealpha($tiny, 0, 0, 0, 127);
    imagefill($tiny, 0, 0, $transparent);
    imagepng($tiny);
    imagedestroy($tiny);
    exit;
}

// Dedicated session name to avoid conflicts with the app's DB-based session system
session_name('TWCAP');
// SECURITY: Harden the CAPTCHA session cookie — mirror the main session cookie flags.
// Without these, the TWCAP cookie is sent over plain HTTP, exposing the session ID
// to network-level attackers who could then forge CAPTCHA answers.
session_set_cookie_params([
    'lifetime' => 600,          // 10 minutes (matches CAPTCHA_VALIDITY + margin)
    'path'     => '/',
    'domain'   => '',
    'secure'   => true,         // HTTPS only — prevents leakage over HTTP
    'httponly'  => true,         // No JavaScript access
    'samesite' => 'Strict',     // No cross-site sending
]);
session_start();

// Generate a question with a random operation
$op = ['+', '-', 'x'][random_int(0, 2)];

switch ($op) {
    case '+':
        $a      = random_int(10, 50);
        $b      = random_int(10, 50);
        $answer = $a + $b;
        break;
    case '-':
        $a      = random_int(20, 60);
        $b      = random_int(1, $a);
        $answer = $a - $b;
        break;
    default: // x (multiply)
        $a      = random_int(2, 12);
        $b      = random_int(2, 9);
        $answer = $a * $b;
        break;
}

$label = "{$a} {$op} {$b} = ?";

// Store answer server-side — never sent to client
$_SESSION['captcha_answer'] = $answer;
$_SESSION['captcha_ts']     = time();

// --- Build GD image ---
$width  = 200;
$height = 60;
$img    = imagecreatetruecolor($width, $height);

// Off-white background with slight random tint to vary the image
$bg = imagecolorallocate($img, random_int(235, 255), random_int(235, 255), random_int(235, 255));
imagefill($img, 0, 0, $bg);

// Noise: scattered pixels
for ($i = 0; $i < 900; $i++) {
    $col = imagecolorallocate($img, random_int(140, 210), random_int(140, 210), random_int(140, 210));
    imagesetpixel($img, random_int(0, $width - 1), random_int(0, $height - 1), $col);
}

// Noise: diagonal lines crossing the text area
for ($i = 0; $i < 7; $i++) {
    $col = imagecolorallocate($img, random_int(160, 210), random_int(160, 210), random_int(160, 210));
    imageline(
        $img,
        random_int(0, $width),  random_int(0, $height),
        random_int(0, $width),  random_int(0, $height),
        $col
    );
}

// Draw each character individually at a slightly randomised Y offset and colour
// so the text baseline is not a straight, parseable line
$font   = 5; // largest built-in GD font, no TTF file required
$charW  = imagefontwidth($font);
$charH  = imagefontheight($font);
$chars  = str_split($label);
$startX = (int)(($width - count($chars) * $charW) / 2);
$baseY  = (int)(($height - $charH) / 2);

foreach ($chars as $i => $ch) {
    $col = imagecolorallocate($img, random_int(0, 70), random_int(0, 70), random_int(0, 70));
    $y   = $baseY + random_int(-5, 5);
    imagestring($img, $font, $startX + $i * $charW, $y, $ch, $col);
}

// Output as PNG — no caching so each page load gets a fresh challenge
header('Content-Type: image/png');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

imagepng($img);
imagedestroy($img);
