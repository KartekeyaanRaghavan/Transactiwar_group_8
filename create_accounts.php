<?php
/**
 * Account Creation Script
 *
 * Creates test accounts automatically for evaluation purposes.
 * Run this script from the command line:
 *   php create_accounts.php
 *
 * Or via Docker:
 *   docker exec transactiwar-web php /var/www/html/create_accounts.php
 *
 * Passwords are read from environment variables so they are never
 * hardcoded in the source. Set them before running:
 *
 *   TEST_PASS_ALICE=... TEST_PASS_BOB=... php create_accounts.php
 *
 * If not set, random secure passwords are generated and printed once.
 */

// Prevent web access
if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    die('This script can only be run from the command line.');
}

require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/includes/auth.php';

function resolvePassword(string $envKey): string {
    $val = getenv($envKey);
    if ($val !== false && $val !== '') {
        return $val;
    }
    // Generate a random password that meets the complexity rules
    $chars  = 'abcdefghijklmnopqrstuvwxyz';
    $upper  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $digits = '0123456789';
    $special = '!@#$%^&*';
    $all = $chars . $upper . $digits . $special;
    $password  = $chars[random_int(0, strlen($chars) - 1)];
    $password .= $upper[random_int(0, strlen($upper) - 1)];
    $password .= $digits[random_int(0, strlen($digits) - 1)];
    $password .= $special[random_int(0, strlen($special) - 1)];
    for ($i = 0; $i < 8; $i++) {
        $password .= $all[random_int(0, strlen($all) - 1)];
    }
    return str_shuffle($password);
}

$accounts = [
    ['username' => 'alice',   'email' => 'alice@transactiwar.test',   'env' => 'TEST_PASS_ALICE'],
    ['username' => 'bob',     'email' => 'bob@transactiwar.test',     'env' => 'TEST_PASS_BOB'],
    ['username' => 'charlie', 'email' => 'charlie@transactiwar.test', 'env' => 'TEST_PASS_CHARLIE'],
    ['username' => 'dave',    'email' => 'dave@transactiwar.test',    'env' => 'TEST_PASS_DAVE'],
    ['username' => 'eve',     'email' => 'eve@transactiwar.test',     'env' => 'TEST_PASS_EVE'],
];

echo "TransactiWar - Account Creation Script\n";
echo "=======================================\n\n";

$pdo = getDBConnection();
$created = [];

foreach ($accounts as $account) {
    $stmt = $pdo->prepare('SELECT id FROM users WHERE username = :username');
    $stmt->execute([':username' => $account['username']]);

    if ($stmt->fetch()) {
        echo "[SKIP] User '{$account['username']}' already exists.\n";
        continue;
    }

    $password = resolvePassword($account['env']);

    // Hash with Argon2id to match the main application
    $passwordHash = password_hash($password, PASSWORD_ARGON2ID, ARGON2ID_OPTIONS);

    $stmt = $pdo->prepare(
        'INSERT INTO users (username, email, password_hash, balance) VALUES (:username, :email, :password_hash, 100.00)'
    );

    try {
        $stmt->execute([
            ':username'      => $account['username'],
            ':email'         => $account['email'],
            ':password_hash' => $passwordHash,
        ]);
        $userId = $pdo->lastInsertId();
        $created[] = ['username' => $account['username'], 'password' => $password];
        echo "[OK] Created user '{$account['username']}' (ID: {$userId})\n";
    } catch (PDOException $e) {
        echo "[ERROR] Failed to create user '{$account['username']}': {$e->getMessage()}\n";
    }
}

echo "\n=======================================\n";
echo "Account creation complete!\n";

if (!empty($created)) {
    echo "\nCredentials (save these now — they will not be shown again):\n";
    foreach ($created as $c) {
        echo "  Username: {$c['username']} | Password: {$c['password']}\n";
    }
}

echo "\nEach account starts with Rs. 100.00 balance.\n";
echo "Change passwords immediately after deployment.\n";
