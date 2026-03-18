# TransactiWar - Secure Banking Application
# PHP 8.2 + Apache + MySQL Client + TLS

FROM php:8.2-apache

# Install required PHP extensions and utilities
RUN apt-get update && apt-get install -y \
    libpng-dev \
    libjpeg-dev \
    libwebp-dev \
    libfreetype6-dev \
    default-mysql-client \
    openssl \
    && docker-php-ext-configure gd --with-freetype --with-jpeg --with-webp \
    && docker-php-ext-install gd pdo pdo_mysql \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Enable Apache modules (including SSL and rewrite)
RUN a2enmod rewrite headers ssl

# SECURITY: Generate self-signed TLS certificate for HTTPS
# This ensures all traffic is encrypted and tamper-proof
RUN mkdir -p /etc/apache2/ssl && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/apache2/ssl/server.key \
    -out /etc/apache2/ssl/server.crt \
    -subj "/C=IN/ST=Telangana/L=Hyderabad/O=TransactiWar/OU=CS6903/CN=transactiwar.local" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:10.96.0.74" && \
    chmod 600 /etc/apache2/ssl/server.key && \
    chmod 644 /etc/apache2/ssl/server.crt

# Copy Apache configuration
COPY apache.conf /etc/apache2/sites-available/000-default.conf

# Copy application code
COPY . /var/www/html/
# SECURITY: Remove infrastructure and dev files from the web root — pulled in by
# the bulk COPY above. These are not needed at runtime and must not be readable
# via any PHP include or path traversal vulnerability (open_basedir covers
# /var/www/html, so PHP can read these unless explicitly removed).
RUN rm -f /var/www/html/wait-for-db.sh \
          /var/www/html/init.sql \
          /var/www/html/create_accounts.php \
          /var/www/html/Dockerfile \
          /var/www/html/docker-compose.yml \
          /var/www/html/apache.conf \
          /var/www/html/.dockerignore \
          /var/www/html/.gitignore \
          /var/www/html/toDo.txt \
          /var/www/html/Transactiwar.docx

# Set the document root to the public directory
ENV APACHE_DOCUMENT_ROOT /var/www/html/public

# SECURITY: Create uploads directory OUTSIDE the web root
# Files here cannot be accessed directly via Apache — served only through image.php
RUN mkdir -p /var/www/uploads/profiles \
    && chown -R www-data:www-data /var/www/uploads \
    && chmod -R 755 /var/www/uploads

# SECURITY: Set proper permissions
# Config and includes should not be writable by web server
RUN chown -R root:root /var/www/html/config /var/www/html/includes /var/www/html/templates \
    && chmod -R 644 /var/www/html/config/*.php \
    && chmod -R 644 /var/www/html/includes/*.php \
    && chmod -R 644 /var/www/html/templates/*.php

# SECURITY: Remove .env from the container (it's loaded via env_file in docker-compose)
RUN rm -f /var/www/html/.env

# SECURITY: Disable PHP functions that are dangerous
# Note: We keep most functions enabled but disable the most dangerous ones
RUN echo "disable_functions = exec,passthru,shell_exec,system,proc_open,popen,parse_ini_file,show_source,mail,pcntl_exec,dl,putenv,proc_nice,proc_get_status" >> /usr/local/etc/php/conf.d/security.ini \
    && echo "expose_php = Off" >> /usr/local/etc/php/conf.d/security.ini \
    && echo "display_errors = Off" >> /usr/local/etc/php/conf.d/security.ini \
    && echo "log_errors = On" >> /usr/local/etc/php/conf.d/security.ini \
    && echo "error_log = /var/log/php_errors.log" >> /usr/local/etc/php/conf.d/security.ini \
    && echo "session.cookie_httponly = 1" >> /usr/local/etc/php/conf.d/security.ini \
    && echo "session.cookie_samesite = Strict" >> /usr/local/etc/php/conf.d/security.ini \
    && echo "session.use_strict_mode = 1" >> /usr/local/etc/php/conf.d/security.ini \
    && echo "upload_max_filesize = 2M" >> /usr/local/etc/php/conf.d/security.ini \
    && echo "post_max_size = 3M" >> /usr/local/etc/php/conf.d/security.ini \
    && echo "max_input_time = 30" >> /usr/local/etc/php/conf.d/security.ini \
    && echo "max_execution_time = 30" >> /usr/local/etc/php/conf.d/security.ini \
    && echo "memory_limit = 64M" >> /usr/local/etc/php/conf.d/security.ini \
    && echo "open_basedir = /var/www/html:/var/www/uploads:/tmp" >> /usr/local/etc/php/conf.d/security.ini

# Copy the wait-for-db script
COPY wait-for-db.sh /usr/local/bin/wait-for-db.sh
RUN chmod +x /usr/local/bin/wait-for-db.sh

EXPOSE 80 443

CMD ["wait-for-db.sh"]
