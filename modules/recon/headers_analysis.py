"""HTTP security headers analysis module."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

HEADER_CHECKS = [
    {
        "header": "Strict-Transport-Security",
        "id": "RECON-HDR-001",
        "severity": Severity.HIGH,
        "cvss": 6.1,
        "desc": "HSTS absent — le site est vulnerable aux attaques de downgrade SSL.",
        "remed": "Ajouter le header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "owasp": "A05:2021",
        "cwe": "CWE-319",
    },
    {
        "header": "Content-Security-Policy",
        "id": "RECON-HDR-002",
        "severity": Severity.MEDIUM,
        "cvss": 5.4,
        "desc": "CSP absent — pas de protection contre les injections de contenu (XSS, data injection).",
        "remed": "Ajouter un Content-Security-Policy restrictif adapte au site.",
        "owasp": "A05:2021",
        "cwe": "CWE-693",
    },
    {
        "header": "X-Frame-Options",
        "id": "RECON-HDR-003",
        "severity": Severity.MEDIUM,
        "cvss": 4.3,
        "desc": "X-Frame-Options absent — le site peut etre embarque dans une iframe (clickjacking).",
        "remed": "Ajouter: X-Frame-Options: DENY ou SAMEORIGIN",
        "owasp": "A05:2021",
        "cwe": "CWE-1021",
    },
    {
        "header": "X-Content-Type-Options",
        "id": "RECON-HDR-004",
        "severity": Severity.LOW,
        "cvss": 3.1,
        "desc": "X-Content-Type-Options absent — le navigateur peut interpreter les MIME types incorrectement.",
        "remed": "Ajouter: X-Content-Type-Options: nosniff",
        "owasp": "A05:2021",
        "cwe": "CWE-693",
    },
    {
        "header": "Referrer-Policy",
        "id": "RECON-HDR-005",
        "severity": Severity.LOW,
        "cvss": 2.4,
        "desc": "Referrer-Policy absent — les URLs completes peuvent etre envoyees aux sites tiers.",
        "remed": "Ajouter: Referrer-Policy: strict-origin-when-cross-origin",
        "owasp": "A05:2021",
        "cwe": "CWE-200",
    },
    {
        "header": "Permissions-Policy",
        "id": "RECON-HDR-006",
        "severity": Severity.LOW,
        "cvss": 2.4,
        "desc": "Permissions-Policy absent — pas de controle sur les APIs navigateur (camera, micro, geolocation).",
        "remed": "Ajouter: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "owasp": "A05:2021",
        "cwe": "CWE-693",
    },
]


class HeadersAnalysisModule(BazookaModule):
    name = "recon.headers_analysis"
    phase = "recon"
    description = "HTTP security headers check"
    profiles = ["quick", "standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()

        response = await session.get(ctx.target.url)
        headers = dict(response.headers)
        result.add_data("response_headers", headers)

        # Check for information leaks
        server = headers.get("Server", "")
        if server:
            result.add_data("server_header", server)
        x_powered = headers.get("X-Powered-By", "")
        if x_powered:
            result.add_data("x_powered_by", x_powered)
            result.add_finding(Finding(
                id="RECON-HDR-010",
                title=f"X-Powered-By expose: {x_powered}",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=f"Le header X-Powered-By revele la technologie: {x_powered}.",
                evidence=Evidence(
                    request=f"GET {ctx.target.url}",
                    response_status=response.status_code,
                    response_headers={"X-Powered-By": x_powered},
                ),
                impact="Aide un attaquant a cibler des vulnerabilites specifiques a cette version.",
                remediation="Supprimer le header X-Powered-By dans la configuration du serveur.",
                compliance=Compliance(owasp_2021="A05:2021", cwe="CWE-200"),
                phase="recon",
                module=self.name,
            ))

        # Check each security header
        for check in HEADER_CHECKS:
            header_name = check["header"]
            if header_name not in headers:
                result.add_finding(Finding(
                    id=check["id"],
                    title=f"{header_name} absent",
                    severity=check["severity"],
                    cvss_score=check["cvss"],
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    confidence=Confidence.CONFIRMED,
                    finding_type=FindingType.MISCONFIGURATION,
                    description=check["desc"],
                    evidence=Evidence(
                        request=f"GET {ctx.target.url}",
                        response_status=response.status_code,
                        response_headers={k: v for k, v in headers.items() if k.lower().startswith(("x-", "strict", "content-s", "referrer", "permissions"))},
                    ),
                    impact="Absence de protection cote navigateur.",
                    remediation=check["remed"],
                    compliance=Compliance(owasp_2021=check["owasp"], cwe=check["cwe"]),
                    phase="recon",
                    module=self.name,
                ))

        return result
