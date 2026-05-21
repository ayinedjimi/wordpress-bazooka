"""phpinfo() exposure detection module.

Scans common paths where developers accidentally leave phpinfo() pages,
which leak server configuration, PHP settings, loaded modules, and environment variables.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

PHPINFO_PATHS = [
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/i.php",
    "/php_info.php",
    "/php-info.php",
    "/pi.php",
    "/p.php",
    "/phpversion.php",
    "/debug.php",
    "/php.php",
    "/pinfo.php",
    "/_phpinfo.php",
    "/wp-content/phpinfo.php",
    "/wp-content/uploads/phpinfo.php",
    "/wp-includes/phpinfo.php",
    "/temp/phpinfo.php",
    "/tmp/phpinfo.php",
]


class PhpInfoExposureModule(BazookaModule):
    name = "vuln.php_info_exposure"
    phase = "vuln"
    description = "phpinfo() page exposure detection"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        finding_count = 0

        for path in PHPINFO_PATHS:
            url = f"{base}{path}"
            try:
                resp = await session.get(url, use_cache=True)
            except Exception:
                continue

            if resp.status_code != 200:
                continue

            body = ""
            try:
                body = resp.text[:10000]
            except Exception:
                continue

            # Real phpinfo() signature: must contain BOTH markers
            if "PHP Version" not in body or "Configuration File" not in body:
                continue

            finding_count += 1

            # Try to extract useful data from the phpinfo page
            leaked_info: list[str] = []
            body_lower = body.lower()
            if "document_root" in body_lower:
                leaked_info.append("document_root")
            if "server_admin" in body_lower:
                leaked_info.append("server_admin")
            if "mysql" in body_lower or "mysqli" in body_lower:
                leaked_info.append("MySQL module")
            if "openssl" in body_lower:
                leaked_info.append("OpenSSL version")
            if "disable_functions" in body_lower:
                leaked_info.append("disable_functions list")
            if "smtp" in body_lower:
                leaked_info.append("SMTP config")
            if "environment" in body_lower:
                leaked_info.append("environment variables")

            leaked_str = ", ".join(leaked_info) if leaked_info else "full PHP configuration"

            result.add_finding(Finding(
                id=f"VULN-PHPINFO-{finding_count:03d}",
                title=f"phpinfo() expose sur {path}",
                severity=Severity.HIGH,
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"Une page phpinfo() est accessible a {url}. "
                    f"Elle expose: {leaked_str}. "
                    "phpinfo() revele les chemins serveur, la version PHP, les modules charges, "
                    "les variables d'environnement et la configuration complete du serveur."
                ),
                evidence=Evidence(
                    request=f"GET {url}",
                    response_status=resp.status_code,
                    response_body_excerpt=body[:200],
                ),
                impact=(
                    "Fuite d'informations critiques: chemins du serveur, version PHP, "
                    "extensions chargees, variables d'environnement (potentiellement des secrets), "
                    "configuration SMTP, chemins de log. Facilite le ciblage d'exploits specifiques."
                ),
                remediation=(
                    "Supprimer immediatement le fichier phpinfo(). "
                    "Si necessaire pour debug, le proteger par IP ou authentification. "
                    "Desactiver phpinfo() dans php.ini via disable_functions."
                ),
                compliance=Compliance(
                    owasp_2021="A05:2021 - Security Misconfiguration",
                    cwe="CWE-200",
                ),
                references=[
                    "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                    "https://www.php.net/manual/en/function.phpinfo.php",
                ],
                phase="vuln",
                module=self.name,
                tags=["phpinfo", "information-disclosure", "php"],
            ))

        return result
