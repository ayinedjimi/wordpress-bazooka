"""Service fingerprinting — identify web applications on hosts discovered by network_scan."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import httpx

from core.models import Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

# Service signatures: (path, label, detection patterns in response body)
_SERVICE_SIGNATURES: list[dict] = [
    {
        "path": "/wp-json/",
        "label": "WordPress",
        "patterns": ["wp-json", "rest_route", "wp/v2", "name", "namespaces"],
    },
    {
        "path": "/status.php",
        "label": "Nextcloud",
        "patterns": ["nextcloud", "installed", "productname", "version"],
    },
    {
        "path": "/phpmyadmin/",
        "label": "phpMyAdmin",
        "patterns": ["phpmyadmin", "pma_", "pmahomme", "phpMyAdmin"],
    },
    {
        "path": "/api/config",
        "label": "Vaultwarden",
        "patterns": ["vaultwarden", "bitwarden", "vault", "signups_allowed"],
    },
    {
        "path": "/api/health",
        "label": "Grafana",
        "patterns": ["grafana", "ok", "commit", "database"],
    },
]


class ServiceDetectModule(BazookaModule):
    name = "infra.service_detect"
    phase = "infra"
    description = "Service fingerprinting on discovered network hosts"
    profiles = ["aggressive"]
    intrusive = False
    dependencies = ["infra.network_scan"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()

        network_hosts = ctx.data.get("network_hosts", [])
        if not network_hosts:
            result.status = "skipped"
            return result

        discovered_services: list[dict] = []
        sem = asyncio.Semaphore(10)

        # Single AsyncClient shared across the whole probe sweep:
        # - reuses TCP connections (keep-alive)
        # - one place that owns SSL verification policy
        # - massively cheaper than 1 client per (host,port,sig) combination
        # We still bypass BazookaSession deliberately: these are internal/adjacent
        # IPs that aren't subject to WAF detection / target-aware throttling.
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(5.0, connect=3.0),
            verify=True,  # was False — silently accepted MITM certs
            follow_redirects=True,
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=20),
            headers={"User-Agent": "Mozilla/5.0"},
        ) as shared_client:

            async def _probe_service(ip: str, port: int, sig: dict) -> dict | None:
                """Send an HTTP GET and check for service fingerprint."""
                scheme = "https" if port in (443, 8443) else "http"
                url = f"{scheme}://{ip}:{port}{sig['path']}"

                async with sem:
                    try:
                        resp = await shared_client.get(url)
                        if resp.status_code < 500:
                            body_lower = resp.text[:3000].lower()
                            matched = [p for p in sig["patterns"] if p.lower() in body_lower]
                            if len(matched) >= 2:
                                return {
                                    "ip": ip,
                                    "port": port,
                                    "service": sig["label"],
                                    "path": sig["path"],
                                    "status": resp.status_code,
                                    "matched_patterns": matched,
                                    "excerpt": resp.text[:200],
                                }
                    except (httpx.RequestError, httpx.TimeoutException):
                        pass
                    except Exception:
                        pass
                return None

            # Build all probe tasks
            tasks = []
            for host in network_hosts:
                ip = host["ip"]
                for port_info in host.get("ports", []):
                    port = port_info["port"]
                    for sig in _SERVICE_SIGNATURES:
                        tasks.append(_probe_service(ip, port, sig))

            if not tasks:
                result.status = "skipped"
                return result

            probe_results = await asyncio.gather(*tasks)

        for svc in probe_results:
            if svc is not None:
                discovered_services.append(svc)

        result.add_data("discovered_services", discovered_services)

        # Emit one finding per discovered service
        for svc in discovered_services:
            svc_label = svc["service"]
            svc_ip = svc["ip"]
            svc_port = svc["port"]

            severity = Severity.MEDIUM
            if svc_label in ("phpMyAdmin", "Vaultwarden"):
                severity = Severity.HIGH

            result.add_finding(Finding(
                id=f"INFRA-SVC-{svc_label.upper()}-{svc_ip.replace('.', '_')}",
                title=f"{svc_label} detecte sur {svc_ip}:{svc_port}",
                severity=severity,
                cvss_score=5.0 if severity == Severity.MEDIUM else 7.0,
                confidence=Confidence.CONFIRMED if len(svc["matched_patterns"]) >= 3 else Confidence.LIKELY,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"Service {svc_label} detecte sur {svc_ip}:{svc_port}{svc['path']} "
                    f"(patterns: {', '.join(svc['matched_patterns'])}). "
                    f"Status HTTP: {svc['status']}."
                ),
                evidence=Evidence(
                    request=f"GET http{'s' if svc_port in (443, 8443) else ''}://{svc_ip}:{svc_port}{svc['path']}",
                    response_status=svc["status"],
                    response_body_excerpt=svc.get("excerpt", "")[:300],
                ),
                impact=(
                    f"Le service {svc_label} est expose sur le reseau. "
                    "Cela peut representer une surface d'attaque supplementaire."
                ),
                remediation=(
                    f"Verifier que {svc_label} est volontairement expose. "
                    "Restreindre l'acces par firewall ou VPN si non necessaire."
                ),
                phase="infra",
                module=self.name,
                tags=["service-detection", svc_label.lower(), "infrastructure"],
            ))

        # Summary finding
        if not discovered_services:
            result.add_finding(Finding(
                id="INFRA-SVC-NONE",
                title="Fingerprinting services: aucun service web identifie",
                severity=Severity.INFO,
                cvss_score=0.0,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"Aucun service web connu detecte sur les {len(network_hosts)} hotes "
                    f"decouverts par le scan reseau."
                ),
                phase="infra",
                module=self.name,
                tags=["service-detection", "infrastructure"],
            ))

        return result
