"""Network range TCP scan — scan the /24 subnet for common web ports."""

from __future__ import annotations

import asyncio
import socket
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

_PORTS = [80, 443, 8080, 8443]
_CONNECT_TIMEOUT = 2.0
_MAX_CONCURRENT = 50  # semaphore limit to avoid fd exhaustion


async def _tcp_connect(ip: str, port: int, timeout: float = _CONNECT_TIMEOUT) -> bool:
    """Attempt a TCP connection and return True if the port is open."""
    loop = asyncio.get_event_loop()
    try:
        # Use loop.run_in_executor for blocking socket connect
        def _connect() -> bool:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                sock.connect((ip, port))
                return True
            except (socket.timeout, ConnectionRefusedError, OSError):
                return False
            finally:
                sock.close()

        return await loop.run_in_executor(None, _connect)
    except Exception:
        return False


async def _grab_banner(ip: str, port: int, timeout: float = _CONNECT_TIMEOUT) -> str:
    """Grab the first 500 bytes from an HTTP service."""
    loop = asyncio.get_event_loop()

    def _fetch() -> str:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            # Send a minimal HTTP request
            request_line = f"GET / HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
            sock.sendall(request_line.encode())
            data = sock.recv(500)
            return data.decode("utf-8", errors="replace")
        except Exception:
            return ""
        finally:
            sock.close()

    try:
        return await loop.run_in_executor(None, _fetch)
    except Exception:
        return ""


def _ip_to_int(ip: str) -> int:
    parts = ip.split(".")
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])


def _int_to_ip(n: int) -> str:
    return f"{(n >> 24) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"


def _generate_range(base_ip: str) -> list[str]:
    """Generate all IPs in the /24 of *base_ip*."""
    parts = base_ip.split(".")
    if len(parts) != 4:
        return []
    prefix = f"{parts[0]}.{parts[1]}.{parts[2]}"
    return [f"{prefix}.{i}" for i in range(1, 255)]


class NetworkScanModule(BazookaModule):
    name = "infra.network_scan"
    phase = "infra"
    description = "TCP port scan on the /24 network range"
    profiles = ["aggressive"]
    intrusive = False

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()

        # Determine target IP
        target_ip = ctx.target.origin_ip or ctx.target.ip
        if not target_ip:
            result.status = "skipped"
            return result

        ip_range = _generate_range(target_ip)
        if not ip_range:
            result.status = "skipped"
            return result

        network_hosts: list[dict] = []
        sem = asyncio.Semaphore(_MAX_CONCURRENT)

        async def _scan_host(ip: str) -> dict | None:
            open_ports: list[dict] = []
            for port in _PORTS:
                async with sem:
                    is_open = await _tcp_connect(ip, port)
                if is_open:
                    async with sem:
                        banner = await _grab_banner(ip, port)
                    open_ports.append({
                        "port": port,
                        "banner": banner[:500] if banner else "",
                    })
            if open_ports:
                return {"ip": ip, "ports": open_ports}
            return None

        # Scan all IPs concurrently (bounded by semaphore)
        tasks = [_scan_host(ip) for ip in ip_range]
        results = await asyncio.gather(*tasks)

        for host_result in results:
            if host_result is not None:
                network_hosts.append(host_result)

        result.add_data("network_hosts", network_hosts)

        host_count = len(network_hosts)
        total_ports = sum(len(h["ports"]) for h in network_hosts)

        # Build summary of discovered hosts
        summary_lines: list[str] = []
        for h in network_hosts[:20]:  # limit summary
            ports_str = ", ".join(f"{p['port']}" for p in h["ports"])
            summary_lines.append(f"  {h['ip']}: {ports_str}")
        summary = "\n".join(summary_lines)

        result.add_finding(Finding(
            id="INFRA-NET-001",
            title=f"Scan reseau /24: {host_count} hotes, {total_ports} ports ouverts",
            severity=Severity.INFO,
            cvss_score=0.0,
            confidence=Confidence.CONFIRMED,
            finding_type=FindingType.INFORMATION_DISCLOSURE,
            description=(
                f"Scan TCP du sous-reseau {target_ip}/24 sur les ports {_PORTS}. "
                f"{host_count} hotes avec des ports web ouverts detectes.\n{summary}"
            ),
            evidence=Evidence(
                request=f"TCP connect scan on {target_ip}/24 ports {_PORTS}",
                response_body_excerpt=summary[:500],
            ),
            phase="infra",
            module=self.name,
            tags=["network", "portscan", "infrastructure"],
        ))

        return result
