"""Subdomain enumeration — combines CT logs with DNS brute-force and HTTP probing."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import dns.resolver

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

COMMON_PREFIXES = [
    "dev", "staging", "admin", "mail", "vpn", "ftp", "test", "api", "cdn",
    "beta", "demo", "shop", "blog", "forum", "support", "help", "docs",
    "status", "monitor", "grafana", "jenkins", "gitlab", "jira", "confluence",
    "wiki", "intranet", "portal", "sso", "auth", "login", "app", "m",
    "mobile", "old", "new", "backup", "db", "mysql", "phpmyadmin", "cpanel",
    "webmail",
]


async def _resolve_hostname(hostname: str) -> list[str]:
    """Resolve a hostname to its A records, returning IPs or empty list."""
    loop = asyncio.get_event_loop()
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        answers = await loop.run_in_executor(None, resolver.resolve, hostname, "A")
        return [str(rdata) for rdata in answers]
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.resolver.Timeout,
        dns.exception.DNSException,
    ):
        return []
    except Exception:
        return []


async def _probe_http(session: "BazookaSession", subdomain: str) -> dict | None:
    """Try HTTP/HTTPS request to subdomain. Return info dict or None if unreachable."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            resp = await session.get(url, use_cache=False, cache_ttl=60)
            return {
                "subdomain": subdomain,
                "url": url,
                "status_code": resp.status_code,
                "title": _extract_title(resp.text[:2000]) if resp.status_code < 500 else "",
                "server": resp.headers.get("Server", ""),
            }
        except Exception:
            continue
    return None


def _extract_title(html: str) -> str:
    """Extract page title from HTML."""
    import re
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()[:100]
    return ""


class SubdomainEnumModule(BazookaModule):
    name = "recon.subdomain_enum"
    phase = "recon"
    description = "Subdomain discovery via CT logs + DNS brute-force + HTTP probe"
    profiles = ["standard", "aggressive"]
    dependencies = ["recon.ct_logs"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        domain = ctx.target.domain
        discovered: dict[str, dict] = {}

        # Step 1: Collect subdomains from CT logs (already gathered by ct_logs module)
        ct_subdomains = ctx.data.get("ct_subdomains", [])
        for sub in ct_subdomains:
            discovered[sub] = {"source": "ct_logs", "ips": [], "http": None}

        # Step 2: DNS brute-force with common prefixes
        bruteforce_candidates = [f"{prefix}.{domain}" for prefix in COMMON_PREFIXES]

        # Resolve all candidates concurrently with a semaphore to avoid overload
        sem = asyncio.Semaphore(20)

        async def resolve_candidate(hostname: str, source: str) -> None:
            async with sem:
                ips = await _resolve_hostname(hostname)
                if ips:
                    if hostname not in discovered:
                        discovered[hostname] = {"source": source, "ips": ips, "http": None}
                    else:
                        discovered[hostname]["ips"] = ips
                        if source == "bruteforce" and discovered[hostname]["source"] == "ct_logs":
                            discovered[hostname]["source"] = "ct_logs+bruteforce"

        # Resolve CT subdomains and brute-force candidates
        resolve_tasks = []
        for sub in ct_subdomains:
            resolve_tasks.append(resolve_candidate(sub, "ct_logs"))
        for candidate in bruteforce_candidates:
            if candidate not in discovered:
                resolve_tasks.append(resolve_candidate(candidate, "bruteforce"))

        if resolve_tasks:
            await asyncio.gather(*resolve_tasks)

        # Filter to only resolved subdomains
        resolved_subs = {
            host: info for host, info in discovered.items() if info["ips"]
        }

        # Step 3: HTTP probe alive subdomains
        probe_sem = asyncio.Semaphore(10)

        async def probe_sub(hostname: str) -> None:
            async with probe_sem:
                http_info = await _probe_http(session, hostname)
                if http_info:
                    resolved_subs[hostname]["http"] = http_info

        probe_tasks = [probe_sub(host) for host in resolved_subs]
        if probe_tasks:
            await asyncio.gather(*probe_tasks)

        # Build final subdomain list
        subdomain_list = []
        for host, info in sorted(resolved_subs.items()):
            entry = {
                "subdomain": host,
                "ips": info["ips"],
                "source": info["source"],
                "alive": info["http"] is not None,
            }
            if info["http"]:
                entry["http_status"] = info["http"]["status_code"]
                entry["http_url"] = info["http"]["url"]
                entry["title"] = info["http"]["title"]
                entry["server"] = info["http"]["server"]
            subdomain_list.append(entry)

        result.add_data("subdomains", subdomain_list)
        ctx.data["subdomains"] = subdomain_list

        alive_count = sum(1 for s in subdomain_list if s.get("alive"))
        total_count = len(subdomain_list)

        # Build evidence excerpt
        evidence_lines = []
        for entry in subdomain_list[:30]:
            status = f"HTTP {entry.get('http_status', 'N/A')}" if entry.get("alive") else "no HTTP"
            evidence_lines.append(
                f"  {entry['subdomain']} -> {', '.join(entry['ips'])} ({status})"
            )
        if total_count > 30:
            evidence_lines.append(f"  ... and {total_count - 30} more")

        result.add_finding(Finding(
            id="RECON-SUB-001",
            title=f"Sous-domaines: {total_count} resolus, {alive_count} actifs pour {domain}",
            severity=Severity.LOW,
            cvss_score=3.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            confidence=Confidence.CONFIRMED,
            finding_type=FindingType.INFORMATION_DISCLOSURE,
            description=(
                f"L'enumeration des sous-domaines a identifie {total_count} sous-domaines resolus "
                f"dont {alive_count} repondent en HTTP pour {domain}. "
                f"Sources: CT logs ({len(ct_subdomains)} entrees) + brute-force DNS "
                f"({len(COMMON_PREFIXES)} prefixes testes)."
            ),
            evidence=Evidence(
                request=f"DNS resolve + HTTP probe for {domain} subdomains",
                response_body_excerpt="\n".join(evidence_lines),
            ),
            impact=(
                "Des sous-domaines non securises (staging, admin, monitoring) peuvent "
                "exposer des fonctionnalites sensibles ou des versions non patchees."
            ),
            remediation=(
                "Auditer chaque sous-domaine actif. Supprimer les entrees DNS inutilisees. "
                "Restreindre l'acces aux sous-domaines internes via VPN ou IP whitelisting."
            ),
            compliance=Compliance(owasp_2021="A05:2021", cwe="CWE-200"),
            phase="recon",
            module=self.name,
            tags=["subdomains", "dns", "bruteforce", "enumeration"],
        ))

        return result
