"""Virtual Host enumeration — discover sites hosted on the same IP via Host header."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class VHostEnumModule(BazookaModule):
    name = "infra.vhost_enum"
    phase = "infra"
    description = "Virtual Host enumeration via Host header"
    profiles = ["aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        target_ip = ctx.target.ip or ctx.target.origin_ip
        if not target_ip:
            return result

        # Collect all known domains from recon
        known_domains: list[str] = []
        ct_subs = ctx.data.get("ct_subdomains", [])
        if isinstance(ct_subs, list):
            known_domains.extend(ct_subs)
        subdomains = ctx.data.get("subdomains", [])
        if isinstance(subdomains, list):
            known_domains.extend([s.get("subdomain", "") if isinstance(s, dict) else str(s) for s in subdomains])
        known_domains.append(ctx.target.domain)

        known_domains = list(set(d for d in known_domains if d))
        if not known_domains:
            return result

        # Get baseline response (default vhost)
        base_url = f"http://{target_ip}"
        try:
            baseline = await session.get(base_url, headers={"Host": "bazooka-default-vhost.invalid"})
            baseline_size = len(baseline.content)
            baseline_status = baseline.status_code
        except Exception:
            return result

        # Test each domain as Host header
        discovered: list[dict] = []
        for domain in known_domains[:50]:  # Limit to 50
            try:
                resp = await session.get(
                    base_url,
                    headers={"Host": domain},
                    use_cache=False,
                )
                size = len(resp.content)
                # If response differs significantly from baseline, this vhost exists
                if resp.status_code != baseline_status or abs(size - baseline_size) > 200:
                    discovered.append({
                        "domain": domain,
                        "status": resp.status_code,
                        "size": size,
                    })
            except Exception:
                continue

        result.add_data("vhosts_discovered", discovered)

        if discovered:
            domains_list = ", ".join(d["domain"] for d in discovered[:10])
            result.add_finding(Finding(
                id="INFRA-VHOST-001",
                title=f"{len(discovered)} virtual host(s) decouverts sur {target_ip}",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                confidence=Confidence.LIKELY,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=f"Virtual hosts actifs sur {target_ip}: {domains_list}.",
                evidence=Evidence(
                    request=f"GET http://{target_ip}/ avec Host: {{domain}}",
                    response_body_excerpt=str(discovered[:5]),
                ),
                impact="Decouverte de sites/services supplementaires sur la meme IP, potentiel mouvement lateral.",
                remediation="Segmenter les sites sur des IPs/serveurs differents. Utiliser SNI strict.",
                phase="infra", module=self.name,
            ))

        return result
