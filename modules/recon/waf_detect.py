"""WAF detection module — identifies web application firewalls."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Finding, Severity, Confidence, FindingType, Evidence
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

WAF_SIGNATURES = {
    "Cloudflare": {"headers": ["cf-ray", "cf-cache-status"], "body": []},
    "SecuPress": {"headers": [], "body": ["secupress"]},
    "Wordfence": {"headers": [], "body": ["wordfence", "wfwaf-"]},
    "Sucuri": {"headers": ["x-sucuri-id", "x-sucuri-cache"], "body": ["sucuri"]},
    "ModSecurity": {"headers": [], "body": ["mod_security", "modsecurity"]},
    "AWS WAF": {"headers": ["x-amzn-requestid"], "body": []},
    "Akamai": {"headers": ["x-akamai-transformed"], "body": ["akamai"]},
    "Imperva": {"headers": ["x-iinfo"], "body": ["incapsula"]},
    "OVH WAF": {"headers": [], "body": ["ovh"]},
    "BunkerWeb": {"headers": [], "body": ["bunkerweb", "nothing to see here"]},
    "Really Simple SSL": {"headers": [], "body": ["really-simple-ssl"]},
}


class WAFDetectModule(BazookaModule):
    name = "recon.waf_detect"
    phase = "recon"
    description = "Web Application Firewall detection"
    profiles = ["quick", "standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()

        # Reuse the WAF detection already done by session.detect_waf() at bootstrap
        # No need to re-detect — just report the finding
        detected_wafs: list[str] = []
        if session.waf_detected:
            detected_wafs = [session.waf_detected]

        if detected_wafs:
            ctx.target.waf_detected = ", ".join(detected_wafs)
            result.add_data("waf_detected", detected_wafs)
            result.add_finding(Finding(
                id="RECON-WAF-001",
                title=f"WAF detecte: {', '.join(detected_wafs)}",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=f"Un ou plusieurs WAF ont ete detectes: {', '.join(detected_wafs)}. "
                            "Cela peut limiter certains tests mais peut etre contourne via l'IP d'origin.",
                evidence=Evidence(
                    request=f"GET {ctx.target.url}",
                    response_status=0,
                ),
                phase="recon",
                module=self.name,
            ))
        else:
            result.add_data("waf_detected", [])
            result.add_finding(Finding(
                id="RECON-WAF-002",
                title="Aucun WAF detecte",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                confidence=Confidence.LIKELY,
                finding_type=FindingType.MISCONFIGURATION,
                description="Aucun WAF n'a ete detecte. Le site est potentiellement expose sans filtrage.",
                impact="Les attaques (SQLi, XSS, brute-force) ne sont pas filtrees.",
                remediation="Installer un WAF (Cloudflare, SecuPress Pro, Wordfence, etc.).",
                phase="recon",
                module=self.name,
            ))

        return result
