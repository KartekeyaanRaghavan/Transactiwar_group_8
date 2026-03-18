#!/bin/bash
# Wait for MySQL to be ready before starting Apache
# Uses PHP PDO to test the connection (same method the app uses)

set -e

echo "Waiting for MySQL to be ready..."

MAX_RETRIES=30
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    # Use PHP to test the database connection (same as the app uses)
    if php -r "
        try {
            new PDO(
                'mysql:host=' . getenv('DB_HOST') . ';dbname=' . getenv('DB_NAME') . ';charset=utf8mb4',
                getenv('DB_USER'),
                getenv('DB_PASS'),
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
            );
            echo 'OK';
            exit(0);
        } catch (PDOException \$e) {
            exit(1);
        }
    " 2>/dev/null | grep -q "OK"; then
        echo "MySQL is ready!"
        break
    fi

    RETRY_COUNT=$((RETRY_COUNT + 1))
    echo "MySQL is not ready yet... retrying in 2 seconds ($RETRY_COUNT/$MAX_RETRIES)"
    sleep 2
done

if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
    echo "ERROR: MySQL did not become ready in time. Starting Apache anyway..."
fi

# Initialize database tables (safe to run multiple times due to IF NOT EXISTS)
# echo "Ensuring database tables exist..."
# php -r "
#     try {
#         \$pdo = new PDO(
#             'mysql:host=' . getenv('DB_HOST') . ';charset=utf8mb4',
#             getenv('DB_USER'),
#             getenv('DB_PASS'),
#             [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
#         );
#         \$sql = file_get_contents('/var/www/html/init.sql');
#         \$pdo->exec(\$sql);
#         echo \"Database tables initialized successfully.\n\";
#     } catch (PDOException \$e) {
#         echo \"Database init note: \" . \$e->getMessage() . \"\n\";
#     }
# " 2>&1 || true

echo "Seeding accounts from Phase2.csv..."
php /var/www/html/create_accounts.php

echo "Starting Apache..."
exec apache2-foreground
