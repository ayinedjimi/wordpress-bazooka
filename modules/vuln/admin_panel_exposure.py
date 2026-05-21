"""Exposed admin panel and sensitive configuration detection module.

Detects publicly accessible administration interfaces (phpMyAdmin, Adminer),
server status pages (Apache mod_status), and exposed configuration files.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

# (path, description, severity, content_signatures, category)
# content_signatures: at least one must be present in body for a confirmed finding
ADMIN_PANELS = [
    # Admin panels — CRITICAL
    (
        "/phpmyadmin/",
        "phpMyAdmin panel",
        Severity.CRITICAL,
        ["phpMyAdmin", "phpmyadmin", "pma_", "login_form"],
        "admin_panel",
    ),
    (
        "/pma/",
        "phpMyAdmin panel (alias)",
        Severity.CRITICAL,
        ["phpMyAdmin", "phpmyadmin", "pma_", "login_form"],
        "admin_panel",
    ),
    (
        "/adminer.php",
        "Adminer database manager",
        Severity.CRITICAL,
        ["Adminer", "adminer", "login-driver", "Login - Adminer"],
        "admin_panel",
    ),
    (
        "/adminer/",
        "Adminer directory",
        Severity.CRITICAL,
        ["Adminer", "adminer", "login-driver", "Login - Adminer"],
        "admin_panel",
    ),
    # Server status — HIGH
    (
        "/server-status",
        "Apache mod_status (server status)",
        Severity.HIGH,
        ["Apache Server Status", "Server Version", "Current Time", "Total Accesses"],
        "server_status",
    ),
    (
        "/server-info",
        "Apache mod_info (server information)",
        Severity.HIGH,
        ["Apache Server Information", "Server Version", "Module Name"],
        "server_status",
    ),
    # Exposed configs — MEDIUM/HIGH
    (
        "/debug.log",
        "Debug log at site root",
        Severity.HIGH,
        ["PHP Warning", "PHP Notice", "PHP Fatal", "Stack trace", "WordPress database error"],
        "config_file",
    ),
    (
        "/_wpeprivate/config.json",
        "WP Engine private config",
        Severity.CRITICAL,
        ['"password"', '"user"', '"wp_', "wpeprivate"],
        "config_file",
    ),
    (
        "/wp-config.bak",
        "wp-config backup file",
        Severity.CRITICAL,
        ["DB_NAME", "DB_USER", "DB_PASSWORD", "AUTH_KEY", "table_prefix"],
        "config_file",
    ),
    (
        "/nginx.conf",
        "nginx configuration exposed",
        Severity.MEDIUM,
        ["server {", "server_name", "location", "proxy_pass", "listen"],
        "config_file",
    ),
    (
        "/web.config",
        "IIS web.config exposed",
        Severity.MEDIUM,
        ["<configuration>", "<system.webServer>", "connectionString", "<appSettings>"],
        "config_file",
    ),
    (
        "/.htaccess",
        "Apache .htaccess exposed (should be 403)",
        Severity.MEDIUM,
        ["RewriteEngine", "RewriteRule", "RewriteCond", "AuthType", "Deny from", "Order"],
        "config_file",
    ),
]


class AdminPanelExposureModule(BazookaModule):
    name = "vuln.admin_panel_exposure"
    phase = "vuln"
    description = "Exposed admin panel and configuration detection"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        finding_count = 0

        for path, description, severity, signatures, category in ADMIN_PANELS:
            url = f"{base}{path}"
            try:
                resp = await session.get(url, use_cache=True)
            except Exception:
                continue

            # We only care about 200 OK responses with matching content
            if resp.status_code != 200:
                continue

            body = ""
            try:
                body = resp.text[:10000]
            except Exception:
                continue

            # Validate at least one content signature is present
            body_lower = body.lower()
            matched_sigs = [sig for sig in signatures if sig.lower() in body_lower]
            if not matched_sigs:
                continue

            finding_count += 1

            cvss = (
                9.8 if severity == Severity.CRITICAL
                else 7.5 if severity == Severity.HIGH
                else 5.3
            )

            if category == "admin_panel":
                impact = (
                    "Interface d'administration de base de donnees accessible publiquement. "
                    "Un attaquant peut tenter un brute-force des credentials ou exploiter "
                    "des vulnerabilites connues pour obtenir un acces complet a la base de donnees."
                )
                remediation = (
                    "Restreindre l'acces par IP via .htaccess ou firewall. "
                    "Deplacer le panel sur un sous-domaine interne. "
                    "Proteger par authentification supplementaire. "
                    "Idealement, supprimer l'acces web et utiliser SSH tunnel."
                )
            elif category == "server_status":
                impact = (
                    "Fuite d'informations sur le serveur: version Apache, uptime, "
                    "requetes en cours, adresses IP des clients, URLs accedees. "
                    "Facilite la reconnaissance et le ciblage d'attaques."
                )
                remediation = (
                    "Desactiver mod_status/mod_info en production ou restreindre "
                    "l'acces via 'Require ip' dans la configuration Apache."
                )
            else:  # config_file
                impact = (
                    "Fichier de configuration expose pouvant contenir des credentials, "
                    "des chemins serveur, ou des regles de securite internes."
                )
                remediation = (
                    "Bloquer l'acces aux fichiers de configuration via le serveur web. "
                    "Supprimer les fichiers inutiles du webroot."
                )

            result.add_finding(Finding(
                id=f"VULN-ADMIN-{finding_count:03d}",
                title=f"{description} detecte: {path}",
                severity=severity,
                cvss_score=cvss,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if severity == Severity.CRITICAL
                           else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION
                if category in ("admin_panel", "server_status")
                else FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"{description} accessible a {url} (HTTP {resp.status_code}). "
                    f"Signatures detectees: {', '.join(matched_sigs[:3])}."
                ),
                evidence=Evidence(
                    request=f"GET {url}",
                    response_status=resp.status_code,
                    response_body_excerpt=body[:200],
                ),
                impact=impact,
                remediation=remediation,
                compliance=Compliance(
                    owasp_2021="A05:2021 - Security Misconfiguration",
                    cwe="CWE-200" if category != "admin_panel" else "CWE-284",
                    mitre_attack="T1190 - Exploit Public-Facing Application"
                    if category == "admin_panel"
                    else None,
                ),
                references=[
                    "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                ],
                phase="vuln",
                module=self.name,
                tags=[category, "exposure", path.strip("/").replace("/", "-")],
            ))

        return result
