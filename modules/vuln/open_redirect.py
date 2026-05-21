"""Open redirect scanner — tests unvalidated redirect parameters."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

logger = logging.getLogger(__name__)

REDIRECT_PARAMS = [
    "redirect_to", "next", "url", "redirect",
    "return", "goto", "dest", "redir",
]

ENDPOINTS = ["/wp-login.php", "/wp-admin/", "/"]

PAYLOAD = "https://evil.bazooka.test/"


class OpenRedirectModule(BazookaModule):
    name = "vuln.open_redirect"
    phase = "vuln"
    description = "Open redirect parameter scanner"
    profiles = ["standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url.rstrip("/")
        found = False
        requests_made = 0
        max_requests = 15

        for endpoint in ENDPOINTS:
            if found or requests_made >= max_requests:
                break
            for param in REDIRECT_PARAMS:
                if requests_made >= max_requests:
                    break
                url = f"{base}{endpoint}?{param}={PAYLOAD}"
                requests_made += 1
                try:
                    resp = await session.get(
                        url, use_cache=False, follow_redirects=False
                    )
                except httpx.TimeoutException:
                    logger.debug("Timeout on %s", url)
                    continue
                except httpx.ConnectError:
                    logger.debug("Connect error on %s", url)
                    continue

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if location.startswith(PAYLOAD):
                        found = True
                        result.add_finding(Finding(
                            id="VULN-OPENRED-001",
                            title=f"Open Redirect via parametre '{param}' sur {endpoint}",
                            severity=Severity.HIGH,
                            cvss_score=6.1,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                            confidence=Confidence.CONFIRMED,
                            finding_type=FindingType.MISCONFIGURATION,
                            description=(
                                f"Le parametre '{param}' sur {endpoint} accepte une URL externe "
                                f"sans validation. La requete a renvoye un {resp.status_code} "
                                f"avec Location pointant vers {location}."
                            ),
                            evidence=Evidence(
                                request=f"GET {url}",
                                response_status=resp.status_code,
                                response_headers={"Location": location},
                                response_body_excerpt=f"Location: {location}",
                            ),
                            impact=(
                                "Phishing: un attaquant peut envoyer un lien legitime vers le site "
                                "qui redirige vers une page malveillante (vol de credentials, malware)."
                            ),
                            remediation=(
                                "Utiliser wp_safe_redirect() au lieu de wp_redirect(). "
                                "Valider que l'URL cible appartient au domaine via wp_validate_redirect()."
                            ),
                            compliance=Compliance(
                                owasp_2021="A01:2021 - Broken Access Control",
                                cwe="CWE-601",
                            ),
                            references=[
                                "https://cwe.mitre.org/data/definitions/601.html",
                                "https://developer.wordpress.org/reference/functions/wp_safe_redirect/",
                            ],
                            phase="vuln",
                            module=self.name,
                            tags=["open-redirect", "phishing"],
                        ))
                        break

        if not found:
            result.add_finding(Finding(
                id="VULN-OPENRED-CLEAR",
                title="Pas d'open redirect detecte",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"{requests_made} combinaisons (parametre, endpoint) testees avec "
                    f"le payload {PAYLOAD}. Aucune redirection externe non validee detectee."
                ),
                phase="vuln",
                module=self.name,
            ))

        return result
