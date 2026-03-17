<?php
/**
 * Secure Image Serving Script
 *
 * Serves profile images from outside the web root.
 * Images are stored in /var/www/uploads/profiles/ (not publicly accessible directly).
 *
 * Security:
 * - Filename validated against strict allowlist (32 hex chars + .png only)
 * - Path traversal prevented via realpath() confinement check
 * - Content-Type forced to image/png regardless of filename
 */

define('UPLOAD_DIR', '/var/www/uploads/profiles/');

$file = $_GET['file'] ?? '';

// SECURITY: Strict allowlist — only accept filenames we generate ourselves:
// 32 hex chars (bin2hex(random_bytes(16))) followed by .png
if (!preg_match('/\A[0-9a-f]{32}\.png\z/', $file)) {
    http_response_code(400);
    exit;
}

$path = UPLOAD_DIR . $file;

// SECURITY: Confirm resolved path is within the upload directory
$realUploadDir = realpath(UPLOAD_DIR);
$realPath      = realpath($path);

if ($realPath === false || $realUploadDir === false || strpos($realPath, $realUploadDir . DIRECTORY_SEPARATOR) !== 0) {
    http_response_code(404);
    exit;
}

if (!is_file($realPath)) {
    http_response_code(404);
    exit;
}

// SECURITY: Force content type — never trust the file extension for serving
header('Content-Type: image/png');
header('Content-Length: ' . filesize($realPath));
// SECURITY: Use no-cache + ETag instead of a long max-age so that profile image
// updates are reflected immediately. The browser revalidates each time but avoids
// re-downloading if the file hasn't changed (304 Not Modified).
$etag = '"' . md5($realPath . filemtime($realPath) . filesize($realPath)) . '"';
header('Cache-Control: no-cache, private');
header('ETag: ' . $etag);
header('X-Content-Type-Options: nosniff');

// Return 304 if the client already has the current version
if (isset($_SERVER['HTTP_IF_NONE_MATCH']) && trim($_SERVER['HTTP_IF_NONE_MATCH']) === $etag) {
    http_response_code(304);
    exit;
}

readfile($realPath);
