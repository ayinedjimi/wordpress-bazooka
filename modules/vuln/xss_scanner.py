"""XSS scanner — reflected XSS in search, parameters."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

XSS_PAYLOADS = [
    ('<script>alert("BZ")</script>', "script tag"),
    ('<img src=x onerror=alert(1)>', "img onerror"),
    ('<svg onload=alert(1)>', "svg onload"),
    ('" onfocus="alert(1)" autofocus="', "event handler injection"),
    ("javascript:alert(1)", "javascript URI"),
    ("<details open ontoggle=alert(1)>", "details ontoggle"),
]


class XSSScannerModule(BazookaModule):
    name = "vuln.xss_scanner"
    phase = "vuln"
    description = "Reflected XSS scanner"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        xss_found = False

        for payload, payload_name in XSS_PAYLOADS:
            try:
                resp = await session.get(f"{base}/?s={payload}", use_cache=False)
                body = resp.text

                # Check if payload is reflected unencoded
                if payload in body:
                    # Verify it's not inside a quoted attribute where it can't execute
                    # Simple heuristic: if the raw payload appears in body, it's likely reflected
                    xss_found = True
                    result.add_finding(Finding(
                        id="VULN-XSS-001",
                        title=f"XSS reflechie dans le parametre de recherche (?s=)",
                        severity=Severity.HIGH,
                        cvss_score=6.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        confidence=Confidence.CONFIRMED,
                        finding_type=FindingType.CVE,
                        description=f"Le payload XSS '{payload_name}' est reflete sans encodage dans la page de resultats de recherche.",
                        evidence=Evidence(
                            request=f"GET {base}/?s={payload}",
                            response_status=resp.status_code,
                            response_body_excerpt=body[max(0, body.index(payload)-50):body.index(payload)+len(payload)+50],
                        ),
                        impact="Vol de session (cookie), redirection malveillante, defacement.",
                        remediation="Encoder les sorties avec esc_html() / esc_attr(). Activer CSP.",
                        compliance=Compliance(
                            owasp_2021="A03:2021 - Injection",
                            cwe="CWE-79",
                            mitre_attack="T1189 - Drive-by Compromise",
                        ),
                        phase="vuln", module=self.name,
                    ))
                    break

            except Exception:
                continue

        if not xss_found:
            result.add_finding(Finding(
                id="VULN-XSS-000",
                title="Aucune XSS reflechie detectee sur /?s=",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=f"{len(XSS_PAYLOADS)} payloads XSS testes. Aucune reflexion non-encodee detectee.",
                phase="vuln", module=self.name,
            ))

        return result

    def should_run(self, ctx) -> bool:
        return ctx.profile != "bugbounty"
