"""CDN origin IP discovery — bypass WAF/CDN by finding the real server IP."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import dns.resolver

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

ORIGIN_PREFIXES = [
    "origin", "direct", "server", "backend", "real",
    "origin-www", "direct-connect", "ip", "host",
    "srv", "node", "web", "www-origin", "raw",
]


async def _resolve_a(hostname: str) -> list[str]:
    """Resolve hostname to A records."""
    loop = asyncio.get_event_loop()
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = await loop.run_in_executor(None, resolver.resolve, hostname, "A")
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


class OriginFinderModule(BazookaModule):
    name = "recon.origin_finder"
    phase = "recon"
    description = "CDN/WAF origin IP discovery to find the real server behind proxy"
    profiles = ["standard", "aggressive"]
    dependencies = ["recon.waf_detect", "recon.dns_enum"]

    def should_run(self, ctx: "ScanContext") -> bool:
        """Only run if a CDN or WAF has been detected."""
        return bool(
            ctx.target.cdn_detected
            or ctx.target.waf_detected
            or ctx.data.get("waf_profile")
        )

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        domain = ctx.target.domain
        main_ip = ctx.target.ip

        # Resolve the main domain IP if not already known
        if not main_ip:
            main_ips = await _resolve_a(domain)
            if main_ips:
                main_ip = main_ips[0]
                ctx.target.ip = main_ip

        if not main_ip:
            result.status = "partial"
            result.add_data("origin_ip", None)
            return result

        # Try common origin subdomains
        origin_candidates: list[dict] = []
        sem = asyncio.Semaphore(10)

        async def check_origin(prefix: str) -> None:
            async with sem:
                hostname = f"{prefix}.{domain}"
                ips = await _resolve_a(hostname)
                for ip in ips:
                    if ip != main_ip:
                        origin_candidates.append({
                            "hostname": hostname,
                            "ip": ip,
                            "verified": False,
                        })

        tasks = [check_origin(prefix) for prefix in ORIGIN_PREFIXES]
        await asyncio.gather(*tasks)

        # Also check common historical DNS records that might differ
        # Check MX records for same-server hosting
        try:
            dns_records = ctx.data.get("dns_records", {})
            mx_records = dns_records.get("MX", [])
            for mx in mx_records:
                # MX format: "10 mail.example.com." — extract hostname
                parts = mx.strip().split()
                if len(parts) >= 2:
                    mx_host = parts[-1].rstrip(".")
                    if mx_host.endswith(f".{domain}") or mx_host == domain:
                        mx_ips = await _resolve_a(mx_host)
                        for ip in mx_ips:
                            if ip != main_ip:
                                origin_candidates.append({
                                    "hostname": mx_host,
                                    "ip": ip,
                                    "verified": False,
                                    "source": "mx_record",
                                })
        except Exception:
            pass

        # Deduplicate by IP
        seen_ips: set[str] = set()
        unique_candidates: list[dict] = []
        for candidate in origin_candidates:
            if candidate["ip"] not in seen_ips:
                seen_ips.add(candidate["ip"])
                unique_candidates.append(candidate)

        # Step 2: Verify candidates by making HTTP request with Host header
        verified_origins: list[dict] = []

        async def verify_origin(candidate: dict) -> None:
            ip = candidate["ip"]
            for scheme in ("https", "http"):
                try:
                    url = f"{scheme}://{ip}"
                    resp = await session.get(
                        url,
                        headers={"Host": domain},
                        use_cache=False,
                    )
                    # Check if the response looks like the real site
                    body_lower = resp.text[:3000].lower() if resp.status_code < 500 else ""
                    is_valid = (
                        resp.status_code in (200, 301, 302, 403)
                        and (
                            domain.lower() in body_lower
                            or "wordpress" in body_lower
                            or "wp-content" in body_lower
                            or resp.status_code in (301, 302)
                        )
                    )
                    if is_valid:
                        candidate["verified"] = True
                        candidate["scheme"] = scheme
                        candidate["status_code"] = resp.status_code
                        candidate["server"] = resp.headers.get("Server", "")
                        verified_origins.append(candidate)
                        return
                except Exception:
                    continue

        verify_tasks = [verify_origin(c) for c in unique_candidates]
        if verify_tasks:
            await asyncio.gather(*verify_tasks)

        # Store results
        if verified_origins:
            best = verified_origins[0]
            ctx.data["origin_ip"] = best["ip"]
            ctx.target.origin_ip = best["ip"]
            result.add_data("origin_ip", best["ip"])
            result.add_data("origin_candidates", verified_origins)

            evidence_lines = []
            for orig in verified_origins:
                evidence_lines.append(
                    f"  {orig['hostname']} -> {orig['ip']} "
                    f"(HTTP {orig.get('status_code', '?')}, server: {orig.get('server', '?')})"
                )

            waf_name = ctx.target.waf_detected or "CDN/WAF"

            result.add_finding(Finding(
                id="RECON-ORIGIN-001",
                title=f"IP d'origine decouverte: {best['ip']} (bypass {waf_name} possible)",
                severity=Severity.HIGH,
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                confidence=Confidence.CONFIRMED if best["verified"] else Confidence.LIKELY,
                finding_type=FindingType.MISCONFIGURATION,
                description=(
                    f"L'IP d'origine du serveur ({best['ip']}) a ete decouverte derriere {waf_name}. "
                    f"Le serveur repond directement aux requetes HTTP avec le header Host: {domain}. "
                    f"Un attaquant peut bypasser le WAF/CDN en envoyant les requetes directement "
                    f"a cette IP, annulant toutes les protections (rate limiting, filtrage, etc.)."
                ),
                evidence=Evidence(
                    request=f"GET {best.get('scheme', 'http')}://{best['ip']}/ (Host: {domain})",
                    response_status=best.get("status_code", 0),
                    response_body_excerpt="\n".join(evidence_lines),
                ),
                impact=(
                    "Bypass complet du WAF: toutes les attaques (SQLi, XSS, brute-force) "
                    "peuvent etre envoyees directement au serveur sans filtrage."
                ),
                remediation=(
                    "1. Configurer le firewall du serveur pour n'accepter que les IPs du CDN/WAF.\n"
                    "2. Supprimer les sous-domaines pointant vers l'IP d'origine.\n"
                    "3. Utiliser un tunnel (Cloudflare Tunnel, Argo) au lieu d'un DNS direct."
                ),
                compliance=Compliance(
                    owasp_2021="A05:2021",
                    cwe="CWE-16",
                    mitre_attack="T1590.002",
                ),
                phase="recon",
                module=self.name,
                tags=["origin-ip", "waf-bypass", "cdn", "critical-finding"],
            ))

        elif unique_candidates:
            # Found IPs that differ but couldn't verify they serve the site
            result.add_data("origin_ip", None)
            result.add_data("origin_candidates_unverified", unique_candidates)

            candidate_lines = [
                f"  {c['hostname']} -> {c['ip']}" for c in unique_candidates[:10]
            ]

            result.add_finding(Finding(
                id="RECON-ORIGIN-002",
                title=f"IPs alternatives detectees (non verifiees) pour {domain}",
                severity=Severity.LOW,
                cvss_score=3.1,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                confidence=Confidence.POSSIBLE,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"{len(unique_candidates)} IP(s) differente(s) de l'IP principale ({main_ip}) "
                    f"ont ete trouvees mais n'ont pas pu etre confirmees comme IP d'origine."
                ),
                evidence=Evidence(
                    request=f"DNS resolve for origin.{domain}, direct.{domain}, etc.",
                    response_body_excerpt="\n".join(candidate_lines),
                ),
                phase="recon",
                module=self.name,
                tags=["origin-ip", "investigation"],
            ))

        else:
            result.add_data("origin_ip", None)
            result.add_finding(Finding(
                id="RECON-ORIGIN-003",
                title=f"Aucune IP d'origine trouvee pour {domain}",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"Les sous-domaines d'origine courants (origin.{domain}, direct.{domain}, etc.) "
                    f"ne resolvent pas vers une IP differente de {main_ip}. "
                    f"Le serveur est correctement configure derriere le WAF/CDN."
                ),
                phase="recon",
                module=self.name,
            ))

        return result
