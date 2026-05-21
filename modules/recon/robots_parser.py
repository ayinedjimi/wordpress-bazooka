"""Robots.txt and sitemap parser."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class RobotsParserModule(BazookaModule):
    name = "recon.robots_parser"
    phase = "recon"
    description = "Robots.txt and sitemap discovery"
    profiles = ["quick", "standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url

        resp = await session.get(f"{base}/robots.txt")
        if resp.status_code != 200:
            return result

        body = resp.text
        result.add_data("robots_txt", body)

        # Extract disallowed paths (interesting for pentesters)
        disallowed = re.findall(r'Disallow:\s*(/[^\s]+)', body)
        sitemaps = re.findall(r'Sitemap:\s*(\S+)', body, re.IGNORECASE)

        result.add_data("robots_disallowed", disallowed)
        result.add_data("robots_sitemaps", sitemaps)

        # Check for interesting paths in robots.txt
        interesting = [p for p in disallowed if any(kw in p.lower() for kw in [
            "admin", "backup", "config", "database", "private", "secret",
            "staging", "dev", "test", "old", "temp", "secupress",
        ])]

        if interesting:
            result.add_finding(Finding(
                id="RECON-ROBOT-001",
                title=f"Robots.txt revele {len(interesting)} chemin(s) sensible(s)",
                severity=Severity.LOW,
                cvss_score=2.4,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=f"Chemins interessants dans robots.txt: {', '.join(interesting[:10])}.",
                evidence=Evidence(
                    request=f"GET {base}/robots.txt",
                    response_status=200,
                    response_body_excerpt="\n".join(f"Disallow: {p}" for p in interesting[:10]),
                ),
                impact="Revele des chemins caches ou sensibles a l'attaquant.",
                remediation="Ne pas lister de chemins sensibles dans robots.txt. Proteger les repertoires par authentification.",
                phase="recon", module=self.name,
            ))

        return result
