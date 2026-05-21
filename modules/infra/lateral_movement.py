"""Lateral movement analysis — identify pivot opportunities from discovered data."""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

# Patterns in debug.log or discovered data that suggest shared infrastructure
_INFRA_PATTERNS: list[str] = [
    "ispconfig",
    "cpanel",
    "plesk",
    "directadmin",
    "webmin",
    "virtualmin",
    "froxlor",
    "hestiacp",
    "cwp",  # CentOS Web Panel
]


class LateralMovementModule(BazookaModule):
    name = "infra.lateral_movement"
    phase = "infra"
    description = "Lateral movement analysis — identify pivot opportunities"
    profiles = ["aggressive"]
    dependencies = []

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()

        lateral_map: dict[str, list[dict[str, object]]] = {
            "shared_identities": [],
            "shared_infrastructure": [],
            "shared_hosting": [],
            "network_pivots": [],
        }

        pivot_opportunities: list[str] = []

        # ----------------------------------------------------------------
        # Analysis 1: Same email/username across multiple services
        # ----------------------------------------------------------------
        usernames: set[str] = set()
        emails: set[str] = set()
        user_sources: dict[str, list[str]] = defaultdict(list)

        # Collect from enumerated WordPress users
        for user in ctx.target.users:
            if user.username:
                usernames.add(user.username)
                user_sources[user.username].append(f"wordpress:{user.discovery_method}")
            if user.email:
                emails.add(user.email)
                user_sources[user.email].append(f"wordpress:email")

        # Collect from scan data (debug.log, credentials, etc.)
        debug_db_user = ctx.data.get("debug_log_DB_USER")
        if debug_db_user:
            usernames.add(debug_db_user)
            user_sources[debug_db_user].append("debug_log:DB_USER")

        # Collect from credential findings
        cred = ctx.data.get("credential_found", {})
        if isinstance(cred, dict) and cred.get("username"):
            cred_user = cred["username"]
            usernames.add(cred_user)
            user_sources[cred_user].append(f"credential:{cred.get('source', 'unknown')}")

        # Check for PMA credentials
        pma_found = ctx.data.get("pma_bruteforce_found", [])
        if isinstance(pma_found, list):
            for pma_cred in pma_found:
                if isinstance(pma_cred, dict) and pma_cred.get("username"):
                    pma_user = pma_cred["username"]
                    usernames.add(pma_user)
                    user_sources[pma_user].append("phpmyadmin:bruteforce")

        # Collect from git data
        git_files = ctx.data.get("git_files", {})
        if isinstance(git_files, dict):
            config = git_files.get(".git/config", "")
            if config:
                # Extract usernames from git remote URLs
                import re
                for match in re.finditer(r'(?:github|gitlab|bitbucket)\.com[:/](\w+)/', config):
                    git_user = match.group(1)
                    usernames.add(git_user)
                    user_sources[git_user].append("git:remote_url")

        # Find identities appearing in multiple contexts
        for identity, sources in user_sources.items():
            if len(sources) > 1:
                lateral_map["shared_identities"].append({
                    "identity": identity,
                    "sources": sources,
                    "type": "email" if "@" in identity else "username",
                })
                pivot_opportunities.append(
                    f"Identite '{identity}' presente dans {len(sources)} services: {', '.join(sources)}"
                )

        # ----------------------------------------------------------------
        # Analysis 2: Same IP hosting multiple services
        # ----------------------------------------------------------------
        target_ip = ctx.target.ip
        origin_ip = ctx.target.origin_ip
        network_hosts = ctx.data.get("network_hosts", [])

        if target_ip:
            services_on_ip: list[str] = ["wordpress"]

            # Check SSRF port scan results
            open_ports = ctx.data.get("ssrf_open_ports", [])
            if isinstance(open_ports, list):
                for port_info in open_ports:
                    if isinstance(port_info, dict):
                        service_name = port_info.get("service", f"port-{port_info.get('port', '?')}")
                        services_on_ip.append(service_name)

            # Check if phpMyAdmin is on same host
            if ctx.data.get("phpmyadmin_detected"):
                services_on_ip.append("phpMyAdmin")

            if len(services_on_ip) > 1:
                lateral_map["shared_hosting"].append({
                    "ip": target_ip,
                    "services": services_on_ip,
                })
                pivot_opportunities.append(
                    f"IP {target_ip} heberge {len(services_on_ip)} services: {', '.join(services_on_ip)}"
                )

            # Origin IP different from public IP (behind CDN)
            if origin_ip and origin_ip != target_ip:
                lateral_map["shared_hosting"].append({
                    "ip": origin_ip,
                    "note": "Origin IP behind CDN/proxy",
                    "public_ip": target_ip,
                })
                pivot_opportunities.append(
                    f"IP d'origine {origin_ip} decouverte derriere le CDN (IP publique: {target_ip})"
                )

        # ----------------------------------------------------------------
        # Analysis 3: Network hosts discovered via SSRF
        # ----------------------------------------------------------------
        if isinstance(network_hosts, list) and network_hosts:
            for host in network_hosts:
                if isinstance(host, dict):
                    host_ip = host.get("ip", "unknown")
                    lateral_map["network_pivots"].append({
                        "ip": host_ip,
                        "discovery_method": "ssrf_pingback",
                        "response_time": host.get("response_time"),
                    })

            pivot_opportunities.append(
                f"{len(network_hosts)} hotes internes decouverts via SSRF"
            )

        # ----------------------------------------------------------------
        # Analysis 4: Shared infrastructure patterns (ISPConfig, cPanel, etc.)
        # ----------------------------------------------------------------
        debug_log_content = ctx.data.get("debug_log_content", "")
        infra_detected: list[str] = []

        # Check debug.log content
        if debug_log_content:
            content_lower = debug_log_content.lower() if isinstance(debug_log_content, str) else ""
            for pattern in _INFRA_PATTERNS:
                if pattern in content_lower:
                    infra_detected.append(pattern)

        # Check from all scan data for infrastructure indicators
        for key, value in ctx.data.items():
            if isinstance(value, str):
                value_lower = value.lower()
                for pattern in _INFRA_PATTERNS:
                    if pattern in value_lower and pattern not in infra_detected:
                        infra_detected.append(pattern)

        # Check HTTP headers for infrastructure hints
        # (We can check what was stored from previous module runs)
        waf_profile = ctx.data.get("waf_profile", {})
        if isinstance(waf_profile, dict) and waf_profile.get("name"):
            lateral_map["shared_infrastructure"].append({
                "type": "waf",
                "name": waf_profile["name"],
                "note": "WAF detected — may indicate shared hosting or CDN",
            })

        if infra_detected:
            for infra in infra_detected:
                lateral_map["shared_infrastructure"].append({
                    "type": "control_panel",
                    "name": infra,
                    "note": f"Control panel '{infra}' detected — likely shared hosting with multiple sites",
                })
            pivot_opportunities.append(
                f"Panneau de controle detecte: {', '.join(infra_detected)} — hebergement partage probable"
            )

        # Check for vhosts discovered
        vhosts = ctx.data.get("vhosts", [])
        if isinstance(vhosts, list) and vhosts:
            lateral_map["shared_hosting"].append({
                "type": "virtual_hosts",
                "hosts": vhosts[:20],  # Limit to 20
                "count": len(vhosts),
            })
            pivot_opportunities.append(
                f"{len(vhosts)} virtual hosts decouverts sur la meme IP"
            )

        # Check for SSL cert domains
        ssl_domains = ctx.data.get("ssl_cert_domains", [])
        if isinstance(ssl_domains, list) and len(ssl_domains) > 1:
            lateral_map["shared_infrastructure"].append({
                "type": "ssl_certificate",
                "domains": ssl_domains,
                "note": "Multiple domains on same SSL certificate",
            })
            pivot_opportunities.append(
                f"Certificat SSL couvre {len(ssl_domains)} domaines: {', '.join(ssl_domains[:5])}"
            )

        # ----------------------------------------------------------------
        # Store the lateral map
        # ----------------------------------------------------------------
        result.add_data("lateral_map", lateral_map)
        result.add_data("pivot_opportunities", pivot_opportunities)

        # Generate finding
        if pivot_opportunities:
            detail_text = "\n".join(f"  - {p}" for p in pivot_opportunities)

            # Count the total number of relationships
            total_relationships = sum(len(v) for v in lateral_map.values())

            result.add_finding(Finding(
                id="INFRA-LATERAL-001",
                title=f"Analyse laterale: {len(pivot_opportunities)} opportunites de pivot identifiees",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
                confidence=Confidence.LIKELY,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"L'analyse des donnees collectees revele {len(pivot_opportunities)} "
                    f"opportunites de mouvement lateral, avec {total_relationships} relations "
                    f"entre les elements decouverts:\n{detail_text}\n\n"
                    f"Ces informations peuvent etre utilisees pour elargir la surface d'attaque "
                    f"vers d'autres services, sites ou comptes lies."
                ),
                evidence=Evidence(
                    request="Data correlation analysis",
                    response_body_excerpt=detail_text[:1000],
                ),
                impact=(
                    "Mouvement lateral possible vers d'autres services heberges sur la meme "
                    "infrastructure. Reutilisation de credentials sur d'autres plateformes. "
                    "Acces a des services internes non exposes directement."
                ),
                remediation=(
                    "1. Segmenter les services sur des serveurs/containers differents. "
                    "2. Utiliser des credentials uniques par service. "
                    "3. Restreindre les communications inter-services (zero trust). "
                    "4. Supprimer les panneaux de controle accessibles depuis Internet."
                ),
                compliance=Compliance(
                    owasp_2021="A05:2021 - Security Misconfiguration",
                    cwe="CWE-668",
                    mitre_attack="T1021 - Remote Services",
                ),
                references=[
                    "https://attack.mitre.org/tactics/TA0008/",
                    "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                ],
                phase="infra",
                module=self.name,
                tags=["lateral-movement", "pivot", "infrastructure", "correlation"],
            ))
        else:
            result.add_finding(Finding(
                id="INFRA-LATERAL-NONE",
                title="Analyse laterale: aucune opportunite de pivot identifiee",
                severity=Severity.INFO,
                cvss_score=0.0,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    "L'analyse de correlation des donnees collectees n'a pas revele "
                    "d'opportunites de mouvement lateral significatives."
                ),
                phase="infra",
                module=self.name,
                tags=["lateral-movement", "infrastructure"],
            ))

        return result
