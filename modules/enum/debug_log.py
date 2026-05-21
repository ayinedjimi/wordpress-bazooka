"""Debug.log analysis — download, search for credentials, paths, DB info."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

SECRET_PATTERNS = [
    (r"DB_PASSWORD\s*[=:]\s*['\"]?([^'\"\s]+)", "DB_PASSWORD", Severity.CRITICAL),
    (r"DB_USER\s*[=:]\s*['\"]?([^'\"\s]+)", "DB_USER", Severity.HIGH),
    (r"DB_NAME\s*[=:]\s*['\"]?([^'\"\s]+)", "DB_NAME", Severity.MEDIUM),
    (r"DB_HOST\s*[=:]\s*['\"]?([^'\"\s]+)", "DB_HOST", Severity.MEDIUM),
    (r"\$P\$[A-Za-z0-9./]{31}", "phpass hash", Severity.CRITICAL),
    (r"user_pass\s*[=:]\s*['\"]?([^'\"\s]+)", "user_pass", Severity.CRITICAL),
    (r"SMTP.*password\s*[=:]\s*['\"]?([^'\"\s]+)", "SMTP password", Severity.CRITICAL),
    (r"auth_cookie\s*[=:]\s*['\"]?([^'\"\s]+)", "auth_cookie", Severity.HIGH),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key", Severity.CRITICAL),
    (r"AIza[0-9A-Za-z_-]{35}", "Google API Key", Severity.HIGH),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT Token", Severity.HIGH),
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Secret Key", Severity.CRITICAL),
]

PATH_PATTERNS = [
    (r"(/var/www/[^\s:\"']+)", "Server path"),
    (r"(/home/[^\s:\"']+)", "Home directory"),
    (r"table_prefix\s*=\s*['\"]([^'\"]+)", "Table prefix"),
]


class DebugLogModule(BazookaModule):
    name = "enum.debug_log"
    phase = "enum"
    description = "WordPress debug.log analysis for credentials and secrets"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        wp_content = ctx.target.wp_content_path
        debug_url = f"{base}{wp_content}debug.log"

        resp = await session.get(debug_url, use_cache=False)
        if resp.status_code != 200:
            result.add_data("debug_log_accessible", False)
            return result

        body = resp.text
        size = len(resp.content)

        # Validate it's a real debug log, not a WAF page
        is_debug_log = any(sig in body for sig in [
            "PHP Warning", "PHP Notice", "PHP Fatal", "PHP Deprecated",
            "Stack trace", "WordPress database error", "wp-includes",
            "on line", "Undefined", "Call to undefined",
        ])
        if not is_debug_log:
            return result

        result.add_data("debug_log_accessible", True)
        result.add_data("debug_log_size", size)

        result.add_finding(Finding(
            id="ENUM-DBG-001",
            title=f"debug.log accessible ({size // 1024} KB)",
            severity=Severity.HIGH,
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            confidence=Confidence.CONFIRMED,
            finding_type=FindingType.INFORMATION_DISCLOSURE,
            description=f"Le fichier debug.log ({size:,} bytes) est accessible publiquement a {debug_url}.",
            evidence=Evidence(
                request=f"GET {debug_url}",
                response_status=200,
                response_body_excerpt=body[:300],
            ),
            impact="Expose des erreurs PHP, chemins serveur, noms de DB, potentiellement des credentials.",
            remediation="Desactiver WP_DEBUG en production. Supprimer debug.log. Bloquer l'acces via .htaccess.",
            compliance=Compliance(owasp_2021="A05:2021", cwe="CWE-532"),
            phase="enum", module=self.name,
        ))

        # Search for secrets (limit to first 2MB to avoid memory issues)
        search_text = body[:2_000_000]
        secrets_found: list[tuple[str, str]] = []

        for pattern, label, severity in SECRET_PATTERNS:
            matches = re.findall(pattern, search_text, re.IGNORECASE)
            if matches:
                secrets_found.append((label, matches[0] if isinstance(matches[0], str) else str(matches[0])))
                result.add_finding(Finding(
                    id=f"ENUM-DBG-SEC-{len(secrets_found):02d}",
                    title=f"Secret trouve dans debug.log: {label}",
                    severity=severity,
                    cvss_score=9.8 if severity == Severity.CRITICAL else 7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    confidence=Confidence.CONFIRMED,
                    finding_type=FindingType.INFORMATION_DISCLOSURE,
                    description=f"{label} trouve dans debug.log.",
                    evidence=Evidence(
                        request=f"GET {debug_url}",
                        response_status=200,
                        response_body_excerpt=f"[REDACTED] Pattern: {label}",
                    ),
                    impact=f"Credential/secret expose: {label}.",
                    remediation="Supprimer immediatement debug.log. Changer les credentials compromises.",
                    compliance=Compliance(owasp_2021="A02:2021", cwe="CWE-532"),
                    phase="enum", module=self.name,
                ))

        # Extract server paths
        for pattern, label in PATH_PATTERNS:
            matches = re.findall(pattern, search_text)
            if matches:
                result.add_data(f"debug_log_{label.replace(' ', '_').lower()}", matches[0])

        result.add_data("debug_log_secrets_count", len(secrets_found))
        return result
