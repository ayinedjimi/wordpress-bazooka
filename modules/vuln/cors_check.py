"""CORS misconfiguration detection module."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class CORSCheckModule(BazookaModule):
    name = "vuln.cors_check"
    phase = "vuln"
    description = "CORS misconfiguration detection"
    profiles = ["quick", "standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        test_origins = [
            "https://evil.com",
            "https://attacker.io",
            "http://localhost",
            "null",
        ]

        for origin in test_origins:
            headers = {"Origin": origin}
            resp = await session.get(f"{base}/wp-json/wp/v2/posts", headers=headers, use_cache=False)

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            acam = resp.headers.get("Access-Control-Allow-Methods", "")

            if acao and (acao == origin or acao == "*"):
                is_credentialed = acac == "true"
                severity = Severity.CRITICAL if is_credentialed else Severity.HIGH
                cvss = 9.1 if is_credentialed else 7.4

                result.add_finding(Finding(
                    id=f"VULN-CORS-001",
                    title=f"CORS wildcard {'avec credentials' if is_credentialed else 'sans credentials'} sur {ctx.target.domain}",
                    severity=severity,
                    cvss_score=cvss,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" if is_credentialed
                               else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    confidence=Confidence.CONFIRMED,
                    finding_type=FindingType.MISCONFIGURATION,
                    description=(
                        f"Le serveur reflete l'origine '{origin}' dans Access-Control-Allow-Origin. "
                        + ("Avec Allow-Credentials: true, un site malveillant peut lire/modifier les donnees "
                           "au nom d'un utilisateur connecte via l'API REST WordPress."
                           if is_credentialed else
                           "Sans credentials, l'impact est limite aux donnees publiques.")
                    ),
                    evidence=Evidence(
                        request=f"GET {base}/wp-json/wp/v2/posts\nOrigin: {origin}",
                        response_status=resp.status_code,
                        response_headers={
                            "Access-Control-Allow-Origin": acao,
                            "Access-Control-Allow-Credentials": acac,
                            "Access-Control-Allow-Methods": acam,
                        },
                    ),
                    impact=(
                        "Equivalent a un CSRF universel : creation d'admin, exfiltration de donnees, "
                        "modification du contenu via l'API REST." if is_credentialed
                        else "Lecture de donnees publiques depuis n'importe quel site."
                    ),
                    remediation=(
                        "Ne jamais refleter l'en-tete Origin. Configurer des origines specifiques. "
                        "Retirer Access-Control-Allow-Credentials si non necessaire."
                    ),
                    compliance=Compliance(
                        owasp_2021="A01:2021 - Broken Access Control",
                        cwe="CWE-346",
                        mitre_attack="T1189 - Drive-by Compromise",
                    ),
                    references=[
                        "https://portswigger.net/web-security/cors",
                        "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                    ],
                    phase="vuln",
                    module=self.name,
                    tags=["cors", "api", "csrf"],
                ))
                # One finding is enough — we confirmed the pattern
                break

        return result
