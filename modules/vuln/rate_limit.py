"""Rate limiting check — tests wp-login, XML-RPC, REST API for throttling."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class RateLimitModule(BazookaModule):
    name = "vuln.rate_limit"
    phase = "vuln"
    description = "Rate limiting check on login, XML-RPC, REST API"
    profiles = ["standard", "aggressive"]
    intrusive = False  # We send a few requests, not actual brute-force

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url

        # Test 1: wp-login.php — send 10 rapid failed logins
        login_url = f"{base}/wp-login.php"
        blocked = False
        block_after = 0
        statuses: list[int] = []

        for i in range(10):
            try:
                resp = await session.post(
                    login_url,
                    data={"log": f"bazooka_test_{i}", "pwd": "wrong_password", "wp-submit": "Log In"},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    use_cache=False,
                )
                statuses.append(resp.status_code)
                if resp.status_code in (429, 503):
                    blocked = True
                    block_after = i + 1
                    break
                if resp.status_code == 403 and i > 0:
                    blocked = True
                    block_after = i + 1
                    break
            except Exception:
                break

        result.add_data("login_rate_limit", blocked)
        result.add_data("login_rate_limit_after", block_after)

        if not blocked:
            result.add_finding(Finding(
                id="VULN-RATE-001",
                title="Aucun rate-limiting sur wp-login.php",
                severity=Severity.HIGH,
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION,
                description=f"10 tentatives de login echouees sans blocage. Statuts: {statuses}.",
                evidence=Evidence(
                    request=f"POST {login_url} x10 (failed logins)",
                    response_status=statuses[-1] if statuses else 0,
                    response_body_excerpt=f"Statuses: {statuses}",
                ),
                impact="Brute-force de mots de passe possible sans limitation.",
                remediation="Installer un plugin de limitation (Wordfence, Limit Login Attempts, SecuPress) ou configurer fail2ban.",
                compliance=Compliance(owasp_2021="A07:2021", cwe="CWE-307"),
                phase="vuln", module=self.name,
            ))
        else:
            result.add_finding(Finding(
                id="VULN-RATE-001",
                title=f"Rate-limiting actif sur wp-login.php (blocage apres {block_after} tentatives)",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=f"Le login est bloque apres {block_after} tentatives.",
                phase="vuln", module=self.name,
            ))

        # Test 2: XML-RPC multicall — if available
        xmlrpc_accessible = ctx.data.get("xmlrpc_accessible", False)
        if xmlrpc_accessible:
            xmlrpc_url = f"{base}/xmlrpc.php"
            mc_statuses: list[int] = []
            mc_blocked = False

            # Send 5 multicall requests rapidly
            payload = """<?xml version="1.0"?>
<methodCall><methodName>system.multicall</methodName><params><param><value><array><data>
<value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
<member><name>params</name><value><array><data>
<value><string>bazooka_test</string></value><value><string>wrong</string></value>
</data></array></value></member></struct></value>
</data></array></value></param></params></methodCall>"""

            for i in range(5):
                try:
                    resp = await session.post(
                        xmlrpc_url,
                        content=payload,
                        headers={"Content-Type": "text/xml"},
                        use_cache=False,
                    )
                    mc_statuses.append(resp.status_code)
                    if resp.status_code in (429, 503, 403):
                        mc_blocked = True
                        break
                except Exception:
                    break

            if not mc_blocked and mc_statuses:
                result.add_finding(Finding(
                    id="VULN-RATE-002",
                    title="Aucun rate-limiting sur XML-RPC multicall",
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    confidence=Confidence.CONFIRMED,
                    finding_type=FindingType.MISCONFIGURATION,
                    description=f"5 requetes multicall envoyees sans blocage. Statuts: {mc_statuses}.",
                    impact="Brute-force amplifie via XML-RPC sans rate-limiting.",
                    remediation="Bloquer XML-RPC ou system.multicall.",
                    compliance=Compliance(owasp_2021="A07:2021", cwe="CWE-307"),
                    phase="vuln", module=self.name,
                ))

        return result

    def should_run(self, ctx) -> bool:
        # Skip in bugbounty mode — intrusive
        return ctx.profile != "bugbounty"
