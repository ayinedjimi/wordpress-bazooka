"""Sensitive port exposure detection module.

Checks if database, cache, and management ports are publicly accessible
on the target IP using raw TCP connections (no nmap dependency).
"""

from __future__ import annotations

import asyncio
import socket
from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

# (port, service_name, category)
# category determines severity: "database" → CRITICAL, "cache" → HIGH, "other" → MEDIUM
SENSITIVE_PORTS = [
    (3306, "MySQL", "database"),
    (5432, "PostgreSQL", "database"),
    (6379, "Redis", "cache"),
    (11211, "Memcached", "cache"),
    (27017, "MongoDB", "database"),
    (9200, "Elasticsearch", "other"),
    (5601, "Kibana", "other"),
    (8080, "Alt HTTP", "other"),
    (8443, "Alt HTTPS", "other"),
    (2222, "Alt SSH", "other"),
]

CATEGORY_SEVERITY = {
    "database": Severity.CRITICAL,
    "cache": Severity.HIGH,
    "other": Severity.MEDIUM,
}

CATEGORY_CVSS = {
    "database": 9.8,
    "cache": 7.5,
    "other": 5.3,
}

CONNECT_TIMEOUT = 2.0
BANNER_TIMEOUT = 2.0


async def _check_port(host: str, port: int) -> tuple[bool, str]:
    """Attempt TCP connect and banner grab on a single port.

    Returns (is_open, banner_text).
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=CONNECT_TIMEOUT,
        )
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError, ConnectionResetError):
        return False, ""

    # Port is open — try to read a banner
    banner = ""
    try:
        data = await asyncio.wait_for(reader.read(200), timeout=BANNER_TIMEOUT)
        if data:
            # Decode defensively; banners may contain binary bytes
            banner = data.decode("utf-8", errors="replace").strip()
    except (asyncio.TimeoutError, OSError):
        pass

    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

    return True, banner


class OpenPortsExposureModule(BazookaModule):
    name = "vuln.open_ports_exposure"
    phase = "vuln"
    description = "Sensitive port exposure detection"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()

        # Determine the IP to scan — prefer origin IP (bypasses CDN), fall back to resolved IP
        target_host = ctx.target.origin_ip or ctx.target.ip
        if not target_host:
            # Resolve domain to IP as a last resort
            try:
                loop = asyncio.get_event_loop()
                target_host = await loop.run_in_executor(
                    None, socket.gethostbyname, ctx.target.domain,
                )
            except socket.gaierror:
                result.status = "failed"
                return result

        # Scan all ports concurrently
        tasks = [_check_port(target_host, port) for port, _, _ in SENSITIVE_PORTS]
        results_raw = await asyncio.gather(*tasks)

        open_ports: list[dict] = []
        finding_count = 0

        for (port, service, category), (is_open, banner) in zip(SENSITIVE_PORTS, results_raw):
            if not is_open:
                continue

            finding_count += 1
            severity = CATEGORY_SEVERITY[category]
            cvss = CATEGORY_CVSS[category]

            port_info = {
                "port": port,
                "service": service,
                "category": category,
                "banner": banner[:200] if banner else "",
            }
            open_ports.append(port_info)

            banner_note = f" Banner: {banner[:100]}" if banner else ""

            result.add_finding(Finding(
                id=f"VULN-PORT-{finding_count:03d}",
                title=f"Port {port} ({service}) ouvert sur {target_host}",
                severity=severity,
                cvss_score=cvss,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if category == "database"
                           else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION,
                description=(
                    f"Le port {port} ({service}) est accessible publiquement sur {target_host}. "
                    f"Ce service ne devrait pas etre expose a Internet.{banner_note}"
                ),
                evidence=Evidence(
                    request=f"TCP connect {target_host}:{port}",
                    response_status=0,
                    response_body_excerpt=banner[:200] if banner else None,
                ),
                impact=(
                    "Acces direct a la base de donnees — extraction totale des donnees, "
                    "creation de comptes admin, execution de commandes."
                    if category == "database"
                    else "Acces direct au cache — lecture/ecriture de donnees en cache, "
                         "possibilite d'empoisonnement de session."
                    if category == "cache"
                    else "Service d'administration expose — possibilite d'acces non autorise."
                ),
                remediation=(
                    "Restreindre l'acces au port via un firewall (iptables/ufw/security group). "
                    "Lier le service a 127.0.0.1 ou a un reseau prive. "
                    "Utiliser un tunnel SSH ou VPN pour l'administration distante."
                ),
                compliance=Compliance(
                    owasp_2021="A05:2021 - Security Misconfiguration",
                    cwe="CWE-200",
                    mitre_attack="T1046 - Network Service Discovery",
                ),
                references=[
                    "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                    "https://www.shodan.io/",
                ],
                phase="vuln",
                module=self.name,
                tags=["port-scan", "exposure", service.lower()],
            ))

        result.data["open_ports"] = open_ports
        return result
