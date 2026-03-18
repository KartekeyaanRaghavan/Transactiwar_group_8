-- TransactiWar Database Schema
-- Phase 1: Secure Web Application

CREATE DATABASE IF NOT EXISTS transactiwar;
USE transactiwar;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    balance DECIMAL(15,2) NOT NULL DEFAULT 100.00 CHECK (balance >= 0),
    display_name VARCHAR(255) DEFAULT NULL,
    bio TEXT DEFAULT NULL,
    profile_image VARCHAR(255) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_username (username),
    INDEX idx_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Sessions table (custom session management)
-- We store the SHA-256 hash of the session token, not the token itself.
-- This way, even if the DB is compromised, attackers cannot hijack active sessions.
CREATE TABLE IF NOT EXISTS sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    session_token_hash VARCHAR(64) NOT NULL UNIQUE,
    csrf_token VARCHAR(64) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    token_rotated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_session_token (session_token_hash),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Transactions table
CREATE TABLE IF NOT EXISTS transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    amount DECIMAL(15,2) NOT NULL,
    comment TEXT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_sender (sender_id),
    INDEX idx_receiver (receiver_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Activity log table
CREATE TABLE IF NOT EXISTS activity_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT DEFAULT NULL,
    username VARCHAR(50) DEFAULT NULL,
    page VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user_activity (user_id),
    INDEX idx_timestamp (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Rate limiting table (to prevent brute force attacks)
CREATE TABLE IF NOT EXISTS rate_limits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    action VARCHAR(50) NOT NULL,
    attempts INT NOT NULL DEFAULT 1,
    first_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_rate_limit (ip_address, action)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Search rate limiting table (per-IP throttling for search queries)
CREATE TABLE IF NOT EXISTS search_rate_limits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    search_count INT NOT NULL DEFAULT 1,
    window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_search_rate (ip_address, window_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Failed login attempts table (dual-layer brute-force protection)
-- Tracks per-(IP, username) and per-username-global attempt counts.
-- Records expire naturally via evt_cleanup_failed_logins — never cleared on success.
CREATE TABLE IF NOT EXISTS failed_login_attempts (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45)  NOT NULL,
    username   VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_fla_ip_user (ip_address, username),
    INDEX idx_fla_username (username),
    INDEX idx_fla_created  (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Pending transfers table (DB intent binding — 2-phase commit tamper-proofing)
-- Phase 1: validated transfer intent stored here; Phase 2: consumed by nonce.
-- Prevents parameter tampering between form submission and execution.
CREATE TABLE IF NOT EXISTS pending_transfers (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    sender_id   INT           NOT NULL,
    receiver_id INT           NOT NULL,
    amount      DECIMAL(15,2) NOT NULL,
    comment     TEXT          DEFAULT NULL,
    nonce       VARCHAR(64)   NOT NULL UNIQUE,
    used        TINYINT(1)    NOT NULL DEFAULT 0,
    created_at  TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    expires_at  TIMESTAMP     NOT NULL,
    FOREIGN KEY (sender_id)   REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_pt_nonce   (nonce),
    INDEX idx_pt_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- SECURITY: Restrict database user privileges
-- Only grant the minimum permissions needed by the application
-- No DROP, ALTER, CREATE, or GRANT privileges
GRANT SELECT, INSERT, UPDATE, DELETE ON transactiwar.* TO 'transactiwar_user'@'%';
FLUSH PRIVILEGES;

-- MySQL auto-cleanup events (requires EVENT privilege — run as DB admin, not transactiwar_user)
-- Enable event scheduler if not already enabled
SET GLOBAL event_scheduler = ON;

CREATE EVENT IF NOT EXISTS evt_cleanup_sessions
    ON SCHEDULE EVERY 1 HOUR
    DO DELETE FROM sessions WHERE expires_at < NOW();

CREATE EVENT IF NOT EXISTS evt_cleanup_rate_limits
    ON SCHEDULE EVERY 1 HOUR
    DO DELETE FROM rate_limits WHERE first_attempt < DATE_SUB(NOW(), INTERVAL 2 HOUR);

CREATE EVENT IF NOT EXISTS evt_cleanup_failed_logins_old
    ON SCHEDULE EVERY 6 HOUR
    DO DELETE FROM failed_login_attempts WHERE created_at < DATE_SUB(NOW(), INTERVAL 6 HOUR);

CREATE EVENT IF NOT EXISTS evt_cleanup_search_rate_limits
    ON SCHEDULE EVERY 10 MINUTE
    DO DELETE FROM search_rate_limits WHERE window_start < DATE_SUB(NOW(), INTERVAL 10 MINUTE);

CREATE EVENT IF NOT EXISTS evt_cleanup_failed_logins
    ON SCHEDULE EVERY 1 HOUR
    DO DELETE FROM failed_login_attempts WHERE created_at < DATE_SUB(NOW(), INTERVAL 7 DAY);

CREATE EVENT IF NOT EXISTS evt_cleanup_pending_transfers
    ON SCHEDULE EVERY 5 MINUTE
    DO DELETE FROM pending_transfers WHERE expires_at < DATE_SUB(NOW(), INTERVAL 1 HOUR);

CREATE EVENT IF NOT EXISTS evt_cleanup_activity_log
    ON SCHEDULE EVERY 1 DAY
    DO DELETE FROM activity_log WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY);
