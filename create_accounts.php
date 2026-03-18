<?php
/**
 * Account Seeding Script
 *
 * Reads Phase2.csv, hashes each password with Argon2id, and inserts accounts
 * into the database. Safe to run multiple times — existing accounts are skipped.
 * Deletes the CSV after seeding so plaintext passwords do not persist on disk.
 *
 * Run automatically on container startup via wait-for-db.sh.
 * Can also be run manually:
 *   docker exec transactiwar-web php /var/www/html/create_accounts.php
 */

// Prevent web access
if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    die('This script can only be run from the command line.');
}

require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/includes/auth.php';

$csvPath = __DIR__ . '/Phase2.csv';

echo "TransactiWar - Account Seeding\n";
echo "================================\n\n";

if (!file_exists($csvPath)) {
    echo "CSV not found — accounts already seeded on a previous run.\n";
    exit(0);
}

$handle = fopen($csvPath, 'r');
if ($handle === false) {
    echo "[ERR] Cannot open Phase2.csv\n";
    exit(1);
}

$pdo = getDBConnection();
$created = 0;
$skipped = 0;
$errors  = 0;

$checkStmt  = $pdo->prepare('SELECT id FROM users WHERE username = :username');
$insertStmt = $pdo->prepare(
    'INSERT INTO users (username, email, display_name, password_hash, balance)
     VALUES (:username, :email, :display_name, :password_hash, 100.00)'
);

// Skip header row
fgetcsv($handle);

while (($row = fgetcsv($handle)) !== false) {
    // Expect: username, email, Name, password
    if (count($row) < 4) {
        echo "[WARN] Skipping malformed row: " . implode(',', $row) . "\n";
        continue;
    }

    $username    = trim($row[0]);
    $email       = trim($row[1]);
    $displayName = trim($row[2]);
    $password    = $row[3]; // Do not trim — preserve exact password

    if ($username === '' || $email === '' || $password === '') {
        echo "[WARN] Skipping row with empty required field.\n";
        continue;
    }

    $checkStmt->execute([':username' => $username]);
    if ($checkStmt->fetch()) {
        echo "[SKIP] {$username} already exists.\n";
        $skipped++;
        continue;
    }

    // Hash with Argon2id — plaintext password is never written to the DB
    $hash = password_hash($password, PASSWORD_ARGON2ID, ARGON2ID_OPTIONS);

    try {
        $insertStmt->execute([
            ':username'      => $username,
            ':email'         => $email,
            ':display_name'  => $displayName !== '' ? $displayName : null,
            ':password_hash' => $hash,
        ]);
        echo "[OK]   {$username} created (ID: {$pdo->lastInsertId()})\n";
        $created++;
    } catch (PDOException $e) {
        echo "[ERR]  {$username}: {$e->getMessage()}\n";
        $errors++;
    }
}

fclose($handle);

// Delete the CSV so plaintext passwords do not persist in the container
if (@unlink($csvPath)) {
    echo "\n[SEC] Phase2.csv deleted from container (passwords hashed and stored).\n";
} else {
    echo "\n[WARN] Could not delete Phase2.csv — please remove it manually.\n";
}

echo "\n================================\n";
echo "Done. Created: {$created}, Skipped: {$skipped}, Errors: {$errors}\n";
echo "Each new account starts with Rs. 100.00 balance.\n";
