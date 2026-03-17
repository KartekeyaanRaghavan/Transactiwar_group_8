# TransactiWar - Secure Banking Web Application

**CS6903: Network Security, 2025-26**
**Indian Institute of Technology Hyderabad**
**Group No. 8**

| Name | Roll Number |
|------|-------------|
| Kartekeyaan Raghavan | CS25MTECH14019 |
| Rohit Sinha | CS25MTECH11018 |
| Shinde Atharv Suhas | CS25MTECH11006 |
| Shivansh Agarwal | CS25MTECH14013 |
| Dayyala Vamsi Krishna | CS25MTECH11027 |

## Github repo: (check here for latest updates)
https://github.com/cs25mtech14019-maker/Transactiwar_group_8.git

## Overview

TransactiWar is a secure money transfer web application built for the CS6903 Network Security course. It implements user authentication, profile management, money transfers, and activity logging with a strong focus on defensive web security.

## Features

- User registration and login with secure session management
- Profile management (email, bio, profile image upload)
- Money transfers between users with optional comments
- User search by username or user ID
- Transaction history with pagination
- Activity logging (page, username, timestamp, IP)
- CAPTCHA on login after repeated failed attempts
- Two-phase transfer flow with HMAC tamper-proofing

## Technology Stack

- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Backend**: PHP 8.2 (no frameworks)
- **Database**: MySQL 8.0
- **Server**: Apache 2.4 with self-signed TLS
- **Containerization**: Docker + Docker Compose

## Quick Start (Docker)

### Prerequisites
- Docker Engine 20.10+
- Docker Compose 2.0+

### Setup & Run

1. Navigate to the project directory:
   ```bash
   cd transactiwar
   ```

2. Build and start:
   ```bash
   docker compose up --build -d
   ```

3. Wait for services to initialize (~30 seconds):
   ```bash
   docker compose logs -f web
   ```
   Look for "Starting Apache..." in the output.

4. Create test accounts:
   ```bash
   docker exec transactiwar-web php /var/www/html/create_accounts.php
   ```

5. Open in browser: https://localhost:8443
   (Accept the self-signed certificate warning.)

### Stopping

```bash
docker compose down
```

To also wipe database data:
```bash
docker compose down -v
```

## Test Accounts
It will be created with the help of create_accounts.php upon the running the command: docker exec transactiwar-web php /var/www/html/create_accounts.php

## Project Structure

```
transactiwar/
├── config/
│   └── database.php              # Database connection (PDO)
├── includes/
│   ├── auth.php                  # Authentication, rate limiting, CAPTCHA
│   ├── functions.php             # Core logic (transfer, search, profile)
│   ├── logger.php                # Activity logging
│   ├── security_headers.php      # HTTP security headers
│   ├── session.php               # Custom session management
│   └── validation.php            # Input validation & sanitization
├── templates/
│   ├── header.php                # Page header
│   └── footer.php                # Page footer
├── public/                       # Apache document root
│   ├── index.php                 # Landing page
│   ├── register.php              # User registration
│   ├── login.php                 # Login (with CAPTCHA support)
│   ├── logout.php                # Logout
│   ├── dashboard.php             # User dashboard
│   ├── profile.php               # Own profile
│   ├── edit_profile.php          # Edit profile
│   ├── view_profile.php          # View another user's profile
│   ├── search.php                # User search
│   ├── transfer.php              # Money transfer (2-phase)
│   ├── transactions.php          # Transaction history
│   ├── image.php                 # Secure image proxy
│   ├── css/style.css             # Styles
│   └── js/app.js                 # Client-side JS
├── init.sql                      # Database schema + cleanup events
├── create_accounts.php           # Test account seeder
├── Dockerfile
├── docker-compose.yml
├── apache.conf                   # Apache vhost (HTTPS)
├── wait-for-db.sh                # Startup script
└── README.md
```

## Security Measures

### Authentication & Brute-Force Protection
- Passwords hashed with Argon2id (64 MiB memory, 4 iterations, 2 threads)
- Transparent rehashing on login if hash parameters change (e.g. migrating from bcrypt)
- Dual-layer rate limiting:
  - Layer 1: max 5 attempts per (IP, username) pair in a 15-minute window
  - Layer 2: max 20 attempts per username globally (all IPs) in a 6-hour window
- Rate limit counters are never cleared on success (prevents reset-by-login-to-own-account attacks)
- Progressive server-side delay on failed login (up to 5 seconds)
- HMAC-signed math CAPTCHA shown after 3 failed attempts from the same IP
- Generic error messages on failure to prevent username/email enumeration
- Dummy Argon2id hash verification on non-existent usernames to prevent timing-based enumeration

### Session Management
- Custom database-backed sessions (no PHP native sessions)
- 32-byte cryptographically secure tokens via `random_bytes`
- Only the SHA-256 hash of the token is stored in the database
- Sessions bound to client IP and User-Agent hash
- Sliding window expiry (30 minutes idle) and absolute lifetime (8 hours)
- Session token rotation every 10 minutes
- Max 5 concurrent sessions per user (oldest evicted on new login)
- Cookies set with HttpOnly, Secure, SameSite=Strict

### Transfer Security
- Two-phase commit: validated transfer intent stored in `pending_transfers` table, consumed by single-use nonce
- HMAC-based form integrity tokens prevent parameter tampering between form render and submission
- Integer-cents arithmetic internally to avoid floating-point rounding errors
- Deadlock prevention via ordered row locking (lower user ID locked first)
- Daily transfer velocity limit per user
- Self-transfer blocked server-side

### CSRF Protection
- Session-based CSRF tokens on all state-changing forms (post-login)
- Cookie-based double-submit pattern for pre-session forms (login, registration)
- Timing-safe comparison via `hash_equals`

### File Uploads
- Uploaded images stored outside the web root (`/var/www/uploads/profiles/`)
- Served through a PHP proxy (`image.php`) that forces `Content-Type: image/png` and `X-Content-Type-Options: nosniff`
- GD library re-encoding strips any embedded code or metadata from uploaded images
- Validation: upload error check, 2 MB size limit, MIME via `finfo`, extension allowlist (jpg, jpeg, png, gif), `getimagesize()` verification
- Random hex filenames (no user-controlled paths)
- Apache configured to block PHP execution in the uploads directory

### Input Validation & Output Encoding
- Server-side validation on all inputs
- Real prepared statements for all SQL queries (PDO with emulation disabled)
- All output encoded with `htmlspecialchars()` to prevent XSS
- Regex patterns use `\A` and `\z` anchors to prevent multiline bypass

### HTTP Security Headers
- Content-Security-Policy (restricts script/style/image sources)
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Referrer-Policy: strict-origin-when-cross-origin
- Strict-Transport-Security (HSTS)
- Cache-Control: no-store

### Server Hardening
- HTTPS enforced with HTTP-to-HTTPS redirect
- PHP dangerous functions disabled (`exec`, `system`, `passthru`, etc.)
- Apache directory listing disabled
- Server tokens and signature hidden
- Config and includes directories not web-accessible
- Database user has only SELECT, INSERT, UPDATE, DELETE privileges (no DDL)
- Automated MySQL events clean up expired sessions, rate limits, and old logs

## References

- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PHP password_hash documentation: https://www.php.net/manual/en/function.password-hash.php
- PDO Prepared Statements: https://www.php.net/manual/en/pdo.prepared-statements.php
- Content Security Policy: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
- OWASP CSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
