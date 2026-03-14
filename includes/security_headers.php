<?php
/**
 * Security Headers
 * Sets HTTP security headers on every response to mitigate common attacks.
 */

/**
 * Apply all security headers.
 * Call this at the very beginning of every page before any output.
 */
function setSecurityHeaders(): void {
    // Prevent MIME type sniffing
    header('X-Content-Type-Options: nosniff');

    // Prevent clickjacking
    header('X-Frame-Options: DENY');

    // Enable XSS filter in older browsers
    header('X-XSS-Protection: 1; mode=block');

    // Referrer policy: only send origin for cross-origin requests
    header('Referrer-Policy: strict-origin-when-cross-origin');

    // SECURITY: HSTS — Force HTTPS for all future requests
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');

    // Content Security Policy: restrict resource loading
    // No 'unsafe-inline' — all styles are in external CSS files (style.css utility classes)
    // Google Fonts allowed for Inter font family
    header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'");

    // Permissions policy
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');

    // Cache control for sensitive pages
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
}
