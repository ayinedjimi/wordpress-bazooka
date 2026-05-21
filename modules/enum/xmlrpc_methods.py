"""XML-RPC analysis — method enumeration, multicall detection."""

from __future__ import annotations

from typing import TYPE_CHECKING
import re

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

XMLRPC_LIST_METHODS = """<?xml version="1.0"?>
<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>"""

XMLRPC_MULTICALL_TEST = """<?xml version="1.0"?>
<methodCall><methodName>system.multicall</methodName><params><param><value><array><data>
<value><struct><member><name>methodName</name><value><string>system.listMethods</string></value></member>
<member><name>params</name><value><array><data></data></array></value></member></struct></value>
</data></array></value></param></params></methodCall>"""

DANGEROUS_METHODS = [
    "system.multicall",
    "wp.getUsersBlogs",
    "wp.uploadFile",
    "pingback.ping",
    "wp.getOptions",
    "wp.setOptions",
    "wp.newPost",
    "wp.editPost",
    "wp.deletePost",
]


class XMLRPCMethodsModule(BazookaModule):
    name = "enum.xmlrpc_methods"
    phase = "enum"
    description = "XML-RPC method enumeration and multicall detection"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        xmlrpc_url = f"{base}/xmlrpc.php"

        # 1. Check if XML-RPC is accessible
        resp = await session.post(
            xmlrpc_url,
            content=XMLRPC_LIST_METHODS,
            headers={"Content-Type": "text/xml"},
        )

        if resp.status_code not in (200, 405):
            result.add_data("xmlrpc_accessible", False)
            return result

        methods: list[str] = []
        if resp.status_code == 200 and "<methodResponse>" in resp.text:
            methods = re.findall(r"<string>([^<]+)</string>", resp.text)
            result.add_data("xmlrpc_accessible", True)
            result.add_data("xmlrpc_methods", methods)
            result.add_data("xmlrpc_method_count", len(methods))

            dangerous_found = [m for m in methods if m in DANGEROUS_METHODS]

            severity = Severity.HIGH if dangerous_found else Severity.MEDIUM
            result.add_finding(Finding(
                id="ENUM-RPC-001",
                title=f"XML-RPC actif: {len(methods)} methodes exposees",
                severity=severity,
                cvss_score=7.5 if dangerous_found else 5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION,
                description=(
                    f"XML-RPC est actif avec {len(methods)} methodes. "
                    f"Methodes dangereuses: {', '.join(dangerous_found) if dangerous_found else 'aucune detectee'}."
                ),
                evidence=Evidence(
                    request=f"POST {xmlrpc_url}\n{XMLRPC_LIST_METHODS[:100]}...",
                    response_status=resp.status_code,
                    response_body_excerpt=f"{len(methods)} methods found",
                ),
                impact="XML-RPC permet le brute-force amplifie (system.multicall), le SSRF (pingback.ping), et l'upload de fichiers.",
                remediation="Desactiver XML-RPC si non utilise, ou restreindre les methodes avec un plugin de securite.",
                compliance=Compliance(owasp_2021="A05:2021", cwe="CWE-16"),
                phase="enum", module=self.name,
            ))

        # 2. Test system.multicall amplification
        if "system.multicall" in methods:
            resp_mc = await session.post(
                xmlrpc_url,
                content=XMLRPC_MULTICALL_TEST,
                headers={"Content-Type": "text/xml"},
            )
            if resp_mc.status_code == 200 and "<methodResponse>" in resp_mc.text:
                result.add_finding(Finding(
                    id="ENUM-RPC-002",
                    title="system.multicall actif — brute-force amplifie possible",
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    confidence=Confidence.CONFIRMED,
                    finding_type=FindingType.MISCONFIGURATION,
                    description="system.multicall permet d'envoyer des centaines de tentatives de login en une seule requete HTTP.",
                    impact="Brute-force 100x plus rapide, contourne le rate-limiting par requete.",
                    remediation="Bloquer system.multicall via plugin ou .htaccess.",
                    compliance=Compliance(owasp_2021="A07:2021", cwe="CWE-307"),
                    phase="enum", module=self.name,
                ))

        # 3. Test pingback SSRF
        if "pingback.ping" in methods:
            result.add_data("pingback_available", True)
            result.add_finding(Finding(
                id="ENUM-RPC-003",
                title="pingback.ping actif — vecteur SSRF potentiel",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.DESIGN_FLAW,
                description="pingback.ping est disponible et peut etre utilise pour du SSRF (port scan interne, acces reseau).",
                impact="Scan de ports interne, acces aux services non exposes sur Internet.",
                remediation="Desactiver pingback.ping ou XML-RPC entierement.",
                compliance=Compliance(owasp_2021="A10:2021", cwe="CWE-918"),
                phase="enum", module=self.name,
            ))

        return result
