#!/bin/bash
# WordPress Vulnerable Lab Setup Script
# Waits for WP to be ready, then installs it with intentional vulnerabilities.

echo "[BAZOOKA LAB] Waiting for WordPress to be ready..."
sleep 15

# Check if WP is already installed
if wp core is-installed --path=/var/www/html --allow-root 2>/dev/null; then
    echo "[BAZOOKA LAB] WordPress already installed."
else
    # Install WP-CLI
    curl -sO https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
    chmod +x wp-cli.phar
    mv wp-cli.phar /usr/local/bin/wp

    echo "[BAZOOKA LAB] Installing WordPress..."
    wp core install \
        --url="http://localhost:8888" \
        --title="BAZOOKA Vulnerable Lab" \
        --admin_user=admin \
        --admin_password="BazookaTest2026!" \
        --admin_email="admin@bazooka-lab.local" \
        --path=/var/www/html \
        --allow-root

    # Create additional users
    wp user create editor "editor@bazooka-lab.local" --role=editor --user_pass="Editor2026!" --path=/var/www/html --allow-root
    wp user create author "author@bazooka-lab.local" --role=author --user_pass="Author2026!" --path=/var/www/html --allow-root

    # Enable user registration with subscriber role
    wp option update users_can_register 1 --path=/var/www/html --allow-root
    wp option update default_role subscriber --path=/var/www/html --allow-root

    # Create some content
    wp post create --post_title="Article de test - Confidentiel" --post_content="Ce document contient des informations sensibles." --post_status=publish --path=/var/www/html --allow-root
    wp post create --post_title="Draft secret" --post_content="Ceci est un brouillon qui ne devrait pas etre visible." --post_status=draft --path=/var/www/html --allow-root
    wp post create --post_title="Page privee" --post_content="Contenu prive avec des credentials." --post_status=private --path=/var/www/html --allow-root

    # Create pages
    wp post create --post_type=page --post_title="Contact" --post_content="Formulaire de contact." --post_status=publish --path=/var/www/html --allow-root
    wp post create --post_type=page --post_title="Mentions Legales" --post_content="SARL Test Corp, SIRET 12345678900001." --post_status=publish --path=/var/www/html --allow-root

    # Install vulnerable plugins (old versions)
    echo "[BAZOOKA LAB] Installing plugins..."
    wp plugin install contact-form-7 --version=5.8.1 --activate --path=/var/www/html --allow-root
    wp plugin install updraftplus --activate --path=/var/www/html --allow-root
    wp plugin install wp-file-manager --version=6.9 --activate --path=/var/www/html --allow-root
    wp plugin install classic-editor --activate --path=/var/www/html --allow-root
    wp plugin install duplicate-post --activate --path=/var/www/html --allow-root
    wp plugin install redirection --activate --path=/var/www/html --allow-root

    # Enable debug logging
    echo "[BAZOOKA LAB] Enabling debug mode..."
    wp config set WP_DEBUG true --raw --path=/var/www/html --allow-root
    wp config set WP_DEBUG_LOG true --raw --path=/var/www/html --allow-root
    wp config set WP_DEBUG_DISPLAY false --raw --path=/var/www/html --allow-root

    # Enable XML-RPC (already enabled by default)
    echo "[BAZOOKA LAB] XML-RPC is enabled by default."

    # Enable directory listing on uploads
    echo "Options +Indexes" > /var/www/html/wp-content/uploads/.htaccess

    # Create an updraft directory
    mkdir -p /var/www/html/wp-content/updraft
    echo "backup placeholder" > /var/www/html/wp-content/updraft/test-backup.txt

    # Fix permissions
    chown -R www-data:www-data /var/www/html

    echo "[BAZOOKA LAB] Setup complete!"
    echo "[BAZOOKA LAB] Admin: admin / BazookaTest2026!"
    echo "[BAZOOKA LAB] URL: http://localhost:8888"
fi
