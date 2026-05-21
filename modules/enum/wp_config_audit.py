"""Audit wp-config constants from leaked data (debug.log, .env)."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

# Default WordPress secret keys shipped in wp-config-sample.php
DEFAULT_AUTH_KEYS = [
    "put your unique phrase here",
    "define('AUTH_KEY',         'put your unique phrase here');",
]

# Constants to check with expected-safe values
CONFIG_CHECKS = [
    {
        "constant": "WP_DEBUG",
        "bad_pattern": r"define\s*\(\s*['\"]WP_DEBUG['\"]\s*,\s*true\s*\)",
        "title": "WP_DEBUG active en production",
        "severity": Severity.HIGH,
        "description": "WP_DEBUG est defini a true, exposant des erreurs PHP en production.",
        "remediation": "Definir WP_DEBUG a false dans wp-config.php pour la production.",
        "cwe": "CWE-209",
    },
    {
        "constant": "WP_DEBUG_LOG",
        "bad_pattern": r"define\s*\(\s*['\"]WP_DEBUG_LOG['\"]\s*,\s*true\s*\)",
        "title": "WP_DEBUG_LOG active — fichier de log expose",
        "severity": Severity.HIGH,
        "description": "WP_DEBUG_LOG est active, ecrivant les erreurs dans un fichier accessible.",
        "remediation": "Desactiver WP_DEBUG_LOG ou definir un chemin hors du webroot.",
        "cwe": "CWE-532",
    },
    {
        "constant": "WP_DEBUG_DISPLAY",
        "bad_pattern": r"define\s*\(\s*['\"]WP_DEBUG_DISPLAY['\"]\s*,\s*true\s*\)",
        "title": "WP_DEBUG_DISPLAY active — erreurs affichees aux visiteurs",
        "severity": Severity.HIGH,
        "description": "WP_DEBUG_DISPLAY est active, affichant les erreurs PHP aux visiteurs.",
        "remediation": "Desactiver WP_DEBUG_DISPLAY en production.",
        "cwe": "CWE-209",
    },
    {
        "constant": "DISALLOW_FILE_EDIT",
        "bad_pattern": None,  # Absence is the issue
        "good_pattern": r"define\s*\(\s*['\"]DISALLOW_FILE_EDIT['\"]\s*,\s*true\s*\)",
        "title": "DISALLOW_FILE_EDIT non defini — editeur de fichiers actif",
        "severity": Severity.MEDIUM,
        "description": "L'editeur de fichiers integre de WordPress est actif (DISALLOW_FILE_EDIT non defini a true).",
        "remediation": "Ajouter define('DISALLOW_FILE_EDIT', true); dans wp-config.php.",
        "cwe": "CWE-732",
    },
    {
        "constant": "DISALLOW_FILE_MODS",
        "bad_pattern": None,
        "good_pattern": r"define\s*\(\s*['\"]DISALLOW_FILE_MODS['\"]\s*,\s*true\s*\)",
        "title": "DISALLOW_FILE_MODS non defini — installation de plugins/themes autorisee",
        "severity": Severity.LOW,
        "description": "DISALLOW_FILE_MODS n'est pas defini, permettant l'installation de plugins/themes depuis l'admin.",
        "remediation": "Ajouter define('DISALLOW_FILE_MODS', true); pour un environnement plus securise.",
        "cwe": "CWE-732",
    },
    {
        "constant": "DB_HOST",
        "bad_pattern": r"define\s*\(\s*['\"]DB_HOST['\"]\s*,\s*['\"](?!localhost|127\.0\.0\.1)([^'\"]+)['\"]\s*\)",
        "title": "DB_HOST pointe vers un hote distant",
        "severity": Severity.MEDIUM,
        "description": "La base de donnees est hebergee sur un serveur distant, augmentant la surface d'attaque.",
        "remediation": "Verifier que la connexion DB utilise TLS et que le port est restreint par firewall.",
        "cwe": "CWE-319",
    },
]


class WPConfigAuditModule(BazookaModule):
    name = "enum.wp_config_audit"
    phase = "enum"
    description = "Audit wp-config constants from leaked data"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()

        # Collect leaked config content from previous module results
        leaked_content = ""

        # Check for debug.log content captured by debug_log module
        debug_log_accessible = ctx.data.get("debug_log_accessible", False)
        if debug_log_accessible:
            # Retrieve debug.log — it may have config snippets
            base = ctx.target.url
            wp_content = ctx.target.wp_content_path
            debug_url = f"{base}{wp_content}debug.log"
            resp = await session.get(debug_url, use_cache=True)
            if resp.status_code == 200:
                leaked_content += resp.text[:2_000_000]

        # Check for .env content
        env_content = ctx.data.get("env_content", "")
        if env_content:
            leaked_content += "\n" + env_content

        # Check for wp-config.php backup content
        config_content = ctx.data.get("wp_config_content", "")
        if config_content:
            leaked_content += "\n" + config_content

        # Also try common wp-config backup paths
        if not leaked_content:
            base = ctx.target.url
            backup_paths = [
                "/wp-config.php.bak",
                "/wp-config.php.old",
                "/wp-config.php.save",
                "/wp-config.php.swp",
                "/wp-config.php~",
                "/wp-config.bak",
                "/wp-config.txt",
                "/.env",
            ]
            for path in backup_paths:
                resp = await session.get(f"{base}{path}")
                if resp.status_code == 200 and len(resp.text) > 50:
                    # Validate it looks like config content
                    if any(kw in resp.text for kw in [
                        "DB_NAME", "DB_USER", "DB_PASSWORD", "AUTH_KEY",
                        "WP_DEBUG", "table_prefix", "define(",
                    ]):
                        leaked_content += "\n" + resp.text[:500_000]
                        result.add_finding(Finding(
                            id="ENUM-CFG-BACKUP",
                            title=f"Fichier de configuration backup accessible: {path}",
                            severity=Severity.CRITICAL,
                            cvss_score=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            confidence=Confidence.CONFIRMED,
                            finding_type=FindingType.INFORMATION_DISCLOSURE,
                            description=f"Le fichier {path} est accessible et contient la configuration WordPress.",
                            evidence=Evidence(
                                request=f"GET {base}{path}",
                                response_status=200,
                                response_body_excerpt=resp.text[:200],
                            ),
                            impact="Exposition complete des credentials de base de donnees et clefs secretes.",
                            remediation=f"Supprimer immediatement {path} du serveur.",
                            compliance=Compliance(owasp_2021="A05:2021", cwe="CWE-530"),
                            phase="enum",
                            module=self.name,
                        ))

        if not leaked_content:
            result.status = "skipped"
            result.add_data("skipped_reason", "No leaked configuration data available")
            return result

        finding_count = 0

        # Check for default auth keys (CRITICAL)
        for default_key in DEFAULT_AUTH_KEYS:
            if default_key in leaked_content:
                finding_count += 1
                result.add_finding(Finding(
                    id=f"ENUM-CFG-{finding_count:03d}",
                    title="Clefs d'authentification WordPress par defaut!",
                    severity=Severity.CRITICAL,
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    confidence=Confidence.CONFIRMED,
                    finding_type=FindingType.MISCONFIGURATION,
                    description=(
                        "Les clefs d'authentification (AUTH_KEY, SECURE_AUTH_KEY, etc.) "
                        "utilisent les valeurs par defaut. Toutes les sessions et cookies "
                        "peuvent etre forges."
                    ),
                    evidence=Evidence(
                        request="Configuration leak analysis",
                        response_body_excerpt="AUTH_KEY = 'put your unique phrase here'",
                    ),
                    impact="Un attaquant peut forger des cookies d'admin et prendre le controle total.",
                    remediation="Generer de nouvelles clefs via https://api.wordpress.org/secret-key/1.1/salt/",
                    compliance=Compliance(owasp_2021="A02:2021", cwe="CWE-1188"),
                    phase="enum",
                    module=self.name,
                ))
                break  # One finding for all default keys

        # Run each config check
        for check in CONFIG_CHECKS:
            bad_pattern = check.get("bad_pattern")
            good_pattern = check.get("good_pattern")
            is_bad = False

            if bad_pattern:
                if re.search(bad_pattern, leaked_content, re.IGNORECASE):
                    is_bad = True
            elif good_pattern:
                # Bad if the good pattern is NOT found (absence = misconfiguration)
                # Only flag if we have actual wp-config content (not just debug.log)
                if "define(" in leaked_content and not re.search(good_pattern, leaked_content, re.IGNORECASE):
                    is_bad = True

            if is_bad:
                finding_count += 1
                result.add_finding(Finding(
                    id=f"ENUM-CFG-{finding_count:03d}",
                    title=check["title"],
                    severity=check["severity"],
                    cvss_score=7.5 if check["severity"] == Severity.HIGH else 5.0,
                    confidence=Confidence.CONFIRMED,
                    finding_type=FindingType.MISCONFIGURATION,
                    description=check["description"],
                    evidence=Evidence(
                        request="Configuration leak analysis",
                        response_body_excerpt=f"Constant: {check['constant']}",
                    ),
                    remediation=check["remediation"],
                    compliance=Compliance(owasp_2021="A05:2021", cwe=check["cwe"]),
                    phase="enum",
                    module=self.name,
                ))

        result.add_data("config_issues_found", finding_count)
        result.add_data("leaked_content_size", len(leaked_content))

        return result
