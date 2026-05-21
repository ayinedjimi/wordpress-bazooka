"""Certificate Transparency log enumeration via crt.sh API."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class CTLogsModule(BazookaModule):
    name = "recon.ct_logs"
    phase = "recon"
    description = "Certificate Transparency subdomain enumeration via crt.sh"
    profiles = ["standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        domain = ctx.target.domain
        subdomains: set[str] = set()

        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            resp = await session.get(url, use_cache=True, cache_ttl=600)

            if resp.status_code != 200:
                result.status = "partial"
                result.add_data("ct_subdomains", [])
                return result

            entries = resp.json()
            for entry in entries:
                name_value = entry.get("name_value", "")
                # name_value can contain multiple domains separated by newlines
                for name in name_value.strip().split("\n"):
                    name = name.strip().lower()
                    # Remove wildcard prefix
                    if name.startswith("*."):
                        name = name[2:]
                    # Validate: must end with domain and be a valid hostname
                    if name.endswith(f".{domain}") or name == domain:
                        if re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$', name):
                            subdomains.add(name)

        except Exception as exc:
            result.status = "partial"
            result.add_data("ct_subdomains", [])
            result.add_finding(Finding(
                id="RECON-CT-ERR",
                title=f"CT log query failed: {type(exc).__name__}",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=f"Could not query crt.sh for {domain}: {exc}",
                phase="recon",
                module=self.name,
            ))
            return result

        sorted_subdomains = sorted(subdomains)
        result.add_data("ct_subdomains", sorted_subdomains)
        ctx.data["ct_subdomains"] = sorted_subdomains

        result.add_finding(Finding(
            id="RECON-CT-001",
            title=f"CT logs: {len(sorted_subdomains)} sous-domaines decouverts pour {domain}",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            finding_type=FindingType.INFORMATION_DISCLOSURE,
            description=(
                f"L'interrogation des logs Certificate Transparency (crt.sh) a revele "
                f"{len(sorted_subdomains)} sous-domaines uniques pour {domain}. "
                f"Ces sous-domaines peuvent reveler des services internes, des environnements "
                f"de staging, ou des applications non securisees."
            ),
            evidence=Evidence(
                request=f"GET https://crt.sh/?q=%25.{domain}&output=json",
                response_status=200,
                response_body_excerpt=", ".join(sorted_subdomains[:20]) + (
                    "..." if len(sorted_subdomains) > 20 else ""
                ),
            ),
            impact="Exposition de la surface d'attaque: sous-domaines potentiellement non securises.",
            remediation="Auditer tous les sous-domaines decouverts, desactiver ceux inutilises.",
            compliance=Compliance(owasp_2021="A05:2021", cwe="CWE-200"),
            phase="recon",
            module=self.name,
            tags=["ct", "subdomains", "osint"],
        ))

        return result
