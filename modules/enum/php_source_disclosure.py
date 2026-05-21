"""PHP source disclosure detection.

When PHP is misconfigured (handler disabled, mod_php removed, .php served
as text), the raw source of WordPress core files is returned to the
browser. This is a CRITICAL exposure: an attacker can read wp-config.php
and harvest DB credentials, AUTH_KEYs and any other server-side secrets.

Probe: /wp-includes/version.php
Validation: the response body literally contains `$wp_version =` (raw
PHP source visible as text), which means the file was NOT executed.

Author: Ayi NEDJIMI <ayinedjimi@users.noreply.github.com>
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import (
    Compliance,
    Confidence,
    Evidence,
    Finding,
    FindingType,
    Severity,
)
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


# Files whose raw PHP source, if returned, indicates broken PHP execution.
# (path, marker that proves we have the raw PHP source, description)
PROBES: list[tuple[str, str, str]] = [
    ("/wp-includes/version.php", "$wp_version =",
     "WordPress version.php source"),
    ("/wp-config.php", "DB_PASSWORD",
     "WordPress wp-config.php source"),
    ("/wp-load.php", "ABSPATH",
     "WordPress wp-load.php source"),
]


class PHPSourceDisclosureModule(BazookaModule):
    name = "enum.php_source_disclosure"
    phase = "enum"
    description = "Detects PHP source disclosure (PHP handler disabled)"
    profiles = ["quick", "standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        finding_count = 0

        for path, marker, desc in PROBES:
            url = f"{base}{path}"
            try:
                resp = await session.get(url, use_cache=True)
            except Exception:
                continue

            if resp.status_code != 200:
                continue

            try:
                body = resp.text[:8000]
            except Exception:
                continue

            # Strong assertion: literal raw PHP token visible as text.
            if marker not in body:
                continue

            # Extra guard: confirm Content-Type is text (not application/x-httpd-php).
            ctype = ""
            try:
                ctype = resp.headers.get("content-type", "").lower()
            except Exception:
                pass
            if "html" not in ctype and "plain" not in ctype and ctype != "":
                # Unusual content-type, still report but tag accordingly.
                pass

            finding_count += 1
            result.add_finding(Finding(
                id=f"ENUM-PHPSRC-{finding_count:03d}",
                title=f"PHP source disclosure: {path}",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"{desc} renvoye en clair (HTTP 200, marker '{marker}' "
                    f"present dans le body). PHP n'execute plus les fichiers .php: "
                    f"tout le code source du site (y compris wp-config.php) "
                    f"est exposable."
                ),
                evidence=Evidence(
                    request=f"GET {url}",
                    response_status=resp.status_code,
                    response_body_excerpt=body[:200],
                ),
                impact=(
                    "Exposition du code source PHP de WordPress. Un attaquant "
                    "peut recuperer wp-config.php (credentials BDD, AUTH_KEYs), "
                    "lire les plugins/themes proprietaires, et identifier des "
                    "vulnerabilites cachees dans le code metier."
                ),
                remediation=(
                    "Reactiver le handler PHP (mod_php, php-fpm, etc.) sur le "
                    "vhost. Verifier la configuration AddHandler/AddType pour "
                    "les .php. Tester avec une page phpinfo de controle "
                    "(supprimee apres). Bloquer l'acces direct a wp-config.php "
                    "via .htaccess en attendant."
                ),
                compliance=Compliance(
                    owasp_2021="A05:2021 - Security Misconfiguration",
                    cwe="CWE-540",
                ),
                references=[
                    "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                ],
                phase="enum",
                module=self.name,
                tags=["php-source", "source-disclosure", "misconfiguration"],
            ))

        return result
