"""Technology stack detection — Server, PHP, MySQL version from headers and error pages."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class TechnologyStackModule(BazookaModule):
    name = "recon.technology_stack"
    phase = "recon"
    description = "Server and technology stack detection"
    profiles = ["quick", "standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        stack: dict[str, str] = {}

        resp = await session.get(base, use_cache=True)
        # Use resp.headers directly (httpx Headers is case-insensitive).
        # dict(resp.headers) would lowercase keys and break header.get("X-Powered-By").
        headers = resp.headers

        # Server
        server = headers.get("Server", "")
        if server:
            stack["server"] = server
            # Extract version
            match = re.search(r'(Apache|nginx|LiteSpeed|IIS)[/ ]*([\d.]+)?', server, re.IGNORECASE)
            if match:
                stack["server_software"] = match.group(1)
                if match.group(2):
                    stack["server_version"] = match.group(2)

        # PHP version
        php = headers.get("X-Powered-By", "")
        if php:
            match = re.search(r'PHP[/ ]*([\d.]+)', php, re.IGNORECASE)
            if match:
                stack["php_version"] = match.group(1)

        # Hosting hints
        via = headers.get("Via", "")
        if via:
            stack["via"] = via

        x_cache = headers.get("X-Cache", "")
        if x_cache:
            stack["cache"] = x_cache

        # Try to detect from error page (best-effort; some servers timeout here)
        try:
            resp_err = await session.get(f"{base}/bazooka_trigger_error.php", use_cache=False)
            if resp_err.status_code in (404, 500):
                body = resp_err.text[:2000]
                match = re.search(r'Apache/([\d.]+)', body)
                if match and "server_version" not in stack:
                    stack["server_version"] = match.group(1)
                    stack["server_software"] = "Apache"
                match = re.search(r'PHP ([\d.]+)', body)
                if match and "php_version" not in stack:
                    stack["php_version"] = match.group(1)
        except Exception:
            pass

        result.add_data("technology_stack", stack)

        if stack:
            parts = []
            if "server_software" in stack:
                v = stack.get("server_version", "")
                parts.append(f"{stack['server_software']}{' ' + v if v else ''}")
            if "php_version" in stack:
                parts.append(f"PHP {stack['php_version']}")
            if "cache" in stack:
                parts.append(f"Cache: {stack['cache']}")

            if parts:
                result.add_finding(Finding(
                    id="RECON-TECH-001",
                    title=f"Stack technologique: {', '.join(parts)}",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    finding_type=FindingType.INFORMATION_DISCLOSURE,
                    description=f"Technologies detectees: {', '.join(parts)}.",
                    evidence=Evidence(
                        request=f"GET {base}",
                        response_status=resp.status_code,
                        response_headers={k: headers.get(k, "") for k in ("Server", "X-Powered-By", "Via", "X-Cache") if headers.get(k)},
                    ),
                    phase="recon", module=self.name,
                ))

        return result
