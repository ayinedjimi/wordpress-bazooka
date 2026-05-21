#!/bin/bash
# Run this AFTER docker compose up -d and waiting 30 seconds.
# Usage: wsl -e bash -c "cd /mnt/c/WORDPRESSBAZOOKA/testlab && bash setup-after.sh"

CONTAINER="testlab-wordpress-1"
echo "[BAZOOKA LAB] Setting up vulnerable WordPress..."

# Install WP-CLI inside the container
docker exec $CONTAINER bash -c "curl -sO https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && chmod +x wp-cli.phar && mv wp-cli.phar /usr/local/bin/wp"

# Install WordPress
docker exec $CONTAINER wp core install \
    --url="http://localhost:8888" \
    --title="BAZOOKA Vulnerable Lab" \
    --admin_user=admin \
    --admin_password="BazookaTest2026!" \
    --admin_email="admin@bazooka-lab.local" \
    --allow-root

# Create users
docker exec $CONTAINER wp user create editor "editor@bazooka-lab.local" --role=editor --user_pass="Editor2026!" --allow-root
docker exec $CONTAINER wp user create author "author@bazooka-lab.local" --role=author --user_pass="Author2026!" --allow-root

# Enable registration
docker exec $CONTAINER wp option update users_can_register 1 --allow-root
docker exec $CONTAINER wp option update default_role subscriber --allow-root

# Create content
docker exec $CONTAINER wp post create --post_title="Article confidentiel" --post_content="Donnees sensibles ici." --post_status=publish --allow-root
docker exec $CONTAINER wp post create --post_title="Draft secret" --post_content="Brouillon confidentiel." --post_status=draft --allow-root
docker exec $CONTAINER wp post create --post_type=page --post_title="Contact" --post_content="Formulaire." --post_status=publish --allow-root
docker exec $CONTAINER wp post create --post_type=page --post_title="Mentions Legales" --post_content="SARL Test Corp." --post_status=publish --allow-root

# Install plugins
echo "[BAZOOKA LAB] Installing plugins..."
docker exec $CONTAINER wp plugin install contact-form-7 --version=5.8.1 --activate --allow-root
docker exec $CONTAINER wp plugin install updraftplus --activate --allow-root
docker exec $CONTAINER wp plugin install classic-editor --activate --allow-root
docker exec $CONTAINER wp plugin install redirection --activate --allow-root
docker exec $CONTAINER wp plugin install duplicate-post --activate --allow-root

# Enable debug
docker exec $CONTAINER wp config set WP_DEBUG true --raw --allow-root
docker exec $CONTAINER wp config set WP_DEBUG_LOG true --raw --allow-root
docker exec $CONTAINER wp config set WP_DEBUG_DISPLAY false --raw --allow-root

# Create vulnerable files
echo "[BAZOOKA LAB] Creating vulnerable files..."
docker exec $CONTAINER bash -c 'echo "ref: refs/heads/main" > /var/www/html/.git/HEAD'
docker exec $CONTAINER bash -c 'mkdir -p /var/www/html/.git && echo "[core]
	repositoryformatversion = 0
[remote \"origin\"]
	url = https://github.com/bazooka-lab/wp-site.git" > /var/www/html/.git/config'

docker exec $CONTAINER bash -c 'echo "DB_NAME=wp_vulntest
DB_USER=wp_admin
DB_PASSWORD=S3cretDB_Pass!
DB_HOST=db:3306
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" > /var/www/html/.env'

docker exec $CONTAINER bash -c 'mkdir -p /var/www/html/wp-content/uploads && echo "Options +Indexes" > /var/www/html/wp-content/uploads/.htaccess'
docker exec $CONTAINER bash -c 'mkdir -p /var/www/html/wp-content/updraft'

docker exec $CONTAINER bash -c 'echo "[31-Mar-2026 10:15:33 UTC] PHP Warning: Undefined variable in /var/www/html/wp-includes/class-wpdb.php on line 1988
[31-Mar-2026 10:15:34 UTC] WordPress database error User wp_admin max_user_connections for query INSERT INTO wp_litespeed_url
[31-Mar-2026 10:18:45 UTC] PHP Notice: SMTP password=TestSMTP123! on smtp.gmail.com:587" > /var/www/html/wp-content/debug.log'

# Enable CORS via .htaccess
docker exec $CONTAINER bash -c 'a2enmod headers 2>/dev/null; cat >> /var/www/html/.htaccess << "HTEOF"

# CORS wildcard (BAZOOKA TEST - intentional vuln)
<IfModule mod_headers.c>
    SetEnvIf Origin "^(.*)$" ORIGIN=$0
    Header always set Access-Control-Allow-Origin "%{ORIGIN}e" env=ORIGIN
    Header always set Access-Control-Allow-Credentials "true"
    Header always set Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS"
    Header always set Access-Control-Allow-Headers "Authorization, X-WP-Nonce, Content-Type"
</IfModule>
HTEOF'

# Restart Apache to pick up mod_headers
docker exec $CONTAINER bash -c 'a2enmod headers && apache2ctl graceful' 2>/dev/null

# Fix permissions
docker exec $CONTAINER chown -R www-data:www-data /var/www/html

echo ""
echo "[BAZOOKA LAB] Setup complete!"
echo "  WordPress: http://localhost:8888"
echo "  Admin:     admin / BazookaTest2026!"
echo "  phpMyAdmin: http://localhost:8889 (root/rootpass123)"
echo ""
echo "  Vulnerabilities installed:"
echo "    - .git exposed"
echo "    - .env with credentials"
echo "    - debug.log with secrets"
echo "    - CORS wildcard"
echo "    - Directory listing on uploads"
echo "    - 3 users enumerable via REST API"
echo "    - XML-RPC enabled with multicall"
echo "    - Registration open"
echo "    - Contact Form 7 v5.8.1 (old)"
echo "    - UpdraftPlus backup dir"
echo "    - No security headers"
echo "    - No rate limiting"
echo "    - Debug mode ON"
