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
header('Cache-Control: max-age=86400, private');
header('X-Content-Type-Options: nosniff');

readfile($realPath);
