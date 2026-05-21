#!/usr/bin/env bash
#
# extend-dvwp.sh
# Extends the DVWP (Damn Vulnerable WordPress) lab with a curated set of
# WordPress plugins pinned to versions that have publicly disclosed CVEs
# (2023-2025). Used as ground truth for testing scanners such as
# BAZOOKA / wpscan / nuclei.
#
# Target container: dvwp-wordpress-1 (WordPress 5.3, PHP 7.1)
# Run from WSL:
#   bash /mnt/c/WORDPRESSBAZOOKA/testlab/dvwp-extend/extend-dvwp.sh
#
# Idempotent: skips plugins already present.
# Does NOT trigger any exploit; only installs and activates.

set -u

CONTAINER="dvwp-wordpress-1"
WP_PATH="/var/www/html"
WP_HOST_URL="http://localhost:31337"
PLUGINS_DIR_HOST="/tmp/dvwp-extend-cache"
mkdir -p "$PLUGINS_DIR_HOST"

# Color helpers
GREEN='\033[0;32m'; RED='\033[0;31m'; YEL='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${BLU}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YEL}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; }

# --------- Plugin matrix: slug|version|CVE label ----------
# Versions verified available on downloads.wordpress.org
PLUGINS=(
  "really-simple-ssl|7.0.5|CVE-2023-6961 (XSS) / family of 2023 issues"
  "litespeed-cache|6.3.0.1|CVE-2024-28000 (privilege escalation)"
  "wpforms-lite|1.8.5.4|CVE-2024-0383 (XSS authenticated)"
  "wp-statistics|13.2.10|CVE-2024-2194 (SQL injection)"
  "forminator|1.24.6|CVE-2024-28890 (arbitrary file upload RCE)"
  "ultimate-member|2.6.6|CVE-2023-3460 (privilege escalation -> admin)"
  "mw-wp-form|4.4.2|CVE-2023-6553 -- LFI / file upload"
  "email-subscribers|5.7.13|CVE-2024-1071 (SQL injection)"
  "elementor|3.5.5|CVE-2023-48777 (arbitrary file upload, auth)"
  "contact-form-7|5.7.5.1|CVE-2023-6449 (unrestricted file upload)"
  "essential-addons-for-elementor-lite|5.7.1|CVE-2023-32243 (privilege escalation)"
  "wp-fastest-cache|1.2.1|CVE-2023-6063 (SQL injection)"
  "fluentform|5.0.2|CVE-2023-26540 (Stored XSS)"
  "wp-google-maps|9.0.27|CVE-2024-1071-class SQLi family"
  "royal-elementor-addons|1.3.78|CVE-2023-5360 (arbitrary file upload RCE)"
  "advanced-custom-fields|6.2.5|CVE-2024-31077 (stored XSS / authd)"
  "popup-builder|4.2.3|CVE-2023-6000 (Stored XSS -> account takeover, Balada injector)"
  "ninja-forms|3.6.25|CVE-2023-37979 (Reflected XSS)"
  "give|2.24.0|CVE-2024-1207 (SQL injection unauthenticated)"
  "user-registration|3.0.2|CVE-2023-3342 (arbitrary file upload -> RCE)"
  "loginpress|3.0.2|CVE-2023-2466 (stored XSS)"
  "ml-slider|3.50.0|CVE-2023-6378 (XSS)"
  "all-in-one-seo-pack|4.5.8|CVE-2023-39979 (privilege escalation)"
  "wpforms-lite|1.8.5.4|CVE-2024-0383 dup-guard"
  "duplicator|1.5.7.1|CVE-2023-6114 (information disclosure)"
  "wp-mail-smtp|3.11.0|CVE-2024-1054 (info disclosure)"
  "post-smtp|2.8.7|CVE-2023-6875 (auth bypass -> account takeover)"
  "lifterlms|7.4.1|CVE-2024-1207-family (SQL injection)"
  "essential-blocks|4.3.0|CVE-2024-2298 (stored XSS)"
  "wp-cerber|9.5|CVE-2024-2697 (auth bypass / logic)"
  "easy-digital-downloads|3.2.6|CVE-2024-1981 (SQL injection)"
  "user-role-editor|4.64|CVE-2024-37255 (privilege escalation)"
  "all-in-one-wp-migration|7.78|CVE-2023-40004 (auth flaw)"
  "advanced-access-manager|6.9.18|CVE-2023-7228 (privilege escalation)"
  "popup-maker|1.18.0|CVE-2024-2544 (XSS)"
  "translatepress-multilingual|2.7.3|CVE-2024-1313 (stored XSS)"
  "miniorange-saml-20-single-sign-on|5.0.7|CVE-2024-2879 (XML auth bypass class)"
)

# ----- Counters -----
TOTAL=${#PLUGINS[@]}
SUCCESS=0
SKIPPED=0
FAILED=0
INSTALLED_LIST=()
FAILED_LIST=()

# ----- WP-CLI helper -----
wp_cli() {
  docker exec -u root "$CONTAINER" wp --path="$WP_PATH" --allow-root "$@"
}

# ----- Ensure wp-cli is installed inside container -----
ensure_wp_cli() {
  if docker exec "$CONTAINER" bash -c 'command -v wp >/dev/null'; then
    return 0
  fi
  log "Installing wp-cli phar inside $CONTAINER ..."
  docker exec -u root "$CONTAINER" bash -c '
    curl -sS -o /usr/local/bin/wp \
      https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
      && chmod +x /usr/local/bin/wp
  '
}

# ----- Try install via wp-cli first, fallback to manual zip download -----
install_plugin() {
  local slug="$1"
  local ver="$2"

  # Already present?
  if wp_cli plugin is-installed "$slug" >/dev/null 2>&1; then
    local cur
    cur=$(wp_cli plugin get "$slug" --field=version 2>/dev/null || true)
    warn "$slug already installed (version $cur) -- activating, no reinstall"
    wp_cli plugin activate "$slug" >/dev/null 2>&1 || true
    SKIPPED=$((SKIPPED+1))
    INSTALLED_LIST+=("$slug|$cur|already-present")
    return 0
  fi

  log "Installing $slug @ $ver via wp-cli ..."
  if wp_cli plugin install "$slug" --version="$ver" --activate --force >/tmp/wpcli.out 2>&1; then
    ok "wp-cli installed $slug $ver"
    SUCCESS=$((SUCCESS+1))
    INSTALLED_LIST+=("$slug|$ver|wp-cli")
    return 0
  fi

  warn "wp-cli failed for $slug $ver -- attempting direct ZIP fallback"
  local url="https://downloads.wordpress.org/plugin/${slug}.${ver}.zip"
  local zip="$PLUGINS_DIR_HOST/${slug}-${ver}.zip"
  if [ ! -s "$zip" ]; then
    if ! curl --max-time 30 -fsSL "$url" -o "$zip"; then
      err "Download failed: $url"
      FAILED=$((FAILED+1))
      FAILED_LIST+=("$slug|$ver|download-404")
      return 1
    fi
  fi
  # Copy into container and install via wp-cli local file
  docker cp "$zip" "${CONTAINER}:/tmp/${slug}-${ver}.zip" >/dev/null
  if wp_cli plugin install "/tmp/${slug}-${ver}.zip" --activate --force >>/tmp/wpcli.out 2>&1; then
    ok "ZIP fallback installed $slug $ver"
    SUCCESS=$((SUCCESS+1))
    INSTALLED_LIST+=("$slug|$ver|zip-fallback")
    return 0
  fi
  err "Both wp-cli and ZIP fallback failed for $slug"
  tail -n 5 /tmp/wpcli.out | sed 's/^/    /'
  FAILED=$((FAILED+1))
  FAILED_LIST+=("$slug|$ver|wp-cli-error")
  return 1
}

# ----- Verify HTTP exposure (readme.txt 200) -----
verify_http() {
  local slug="$1"
  local code
  code=$(curl --max-time 5 -s -o /dev/null -w '%{http_code}' \
    "${WP_HOST_URL}/wp-content/plugins/${slug}/readme.txt")
  if [ "$code" = "200" ]; then
    ok "HTTP readme OK for $slug"
  else
    warn "HTTP readme for $slug returned $code"
  fi
}

# ============== Main =================
echo "============================================================"
echo " DVWP extender :: $TOTAL plugin entries"
echo " Container    :: $CONTAINER"
echo " WP path      :: $WP_PATH"
echo " WP URL       :: $WP_HOST_URL"
echo "============================================================"

if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
  err "Container $CONTAINER is not running"
  exit 1
fi

ensure_wp_cli

# Deduplicate (in case of duplicates in matrix)
declare -A SEEN
for entry in "${PLUGINS[@]}"; do
  slug=$(echo "$entry" | awk -F'|' '{print $1}')
  ver=$(echo "$entry" | awk -F'|' '{print $2}')
  key="${slug}"
  if [ -n "${SEEN[$key]:-}" ]; then
    continue
  fi
  SEEN[$key]=1
  install_plugin "$slug" "$ver" || true
done

echo ""
echo "============================================================"
echo " HTTP verification (readme.txt /wp-content/plugins/<slug>)"
echo "============================================================"
for entry in "${INSTALLED_LIST[@]}"; do
  slug=$(echo "$entry" | awk -F'|' '{print $1}')
  verify_http "$slug"
done

echo ""
echo "============================================================"
echo " FINAL REPORT"
echo "============================================================"
echo "Total entries     : $TOTAL"
echo "Newly installed   : $SUCCESS"
echo "Already present   : $SKIPPED"
echo "Failed            : $FAILED"
echo ""
echo "-- Installed plugins --"
for e in "${INSTALLED_LIST[@]}"; do
  echo "  $e"
done
if [ ${#FAILED_LIST[@]} -gt 0 ]; then
  echo ""
  echo "-- Failures --"
  for e in "${FAILED_LIST[@]}"; do
    echo "  $e"
  done
fi
echo ""
echo "Currently active plugins in DVWP:"
wp_cli plugin list --status=active --format=csv 2>/dev/null | sed 's/^/  /'
