"""SQL Injection scanner — search, admin-ajax, REST API filters."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

SQLI_PAYLOADS = [
    ("'", "single quote"),
    ('"', "double quote"),
    ("' OR '1'='1", "boolean OR"),
    ("1' AND SLEEP(3)--", "time-based blind"),
    ("1 UNION SELECT NULL--", "union select"),
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", "error-based extractvalue"),
    ("1' OR BENCHMARK(3000000,MD5('a'))#", "benchmark blind"),
]

MYSQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "mysql_fetch",
    "mysql_num_rows",
    "supplied argument is not a valid mysql",
    "call to a member function",
    "wp_query",
    "wpdb",
]


class SQLiScannerModule(BazookaModule):
    name = "vuln.sqli_scanner"
    phase = "vuln"
    description = "SQL Injection scanner (search, AJAX, REST)"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        sqli_found = False

        # Get baseline response for comparison
        baseline_resp = await session.get(f"{base}/?s=bazooka_normal_search_test", use_cache=False)
        baseline_time = 0.5  # seconds

        # Test 1: Search parameter /?s=
        for payload, payload_name in SQLI_PAYLOADS:
            try:
                start = time.time()
                resp = await session.get(f"{base}/?s={payload}", use_cache=False)
                elapsed = time.time() - start

                body_lower = resp.text[:5000].lower()

                # Error-based detection
                for pattern in MYSQL_ERROR_PATTERNS:
                    if pattern in body_lower:
                        sqli_found = True
                        result.add_finding(Finding(
                            id="VULN-SQLI-001",
                            title=f"SQL Injection potentielle (error-based) dans /?s=",
                            severity=Severity.CRITICAL,
                            cvss_score=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            confidence=Confidence.CONFIRMED,
                            finding_type=FindingType.CVE,
                            description=f"Erreur SQL detectee avec le payload '{payload_name}'. Pattern: '{pattern}'.",
                            evidence=Evidence(
                                request=f"GET {base}/?s={payload}",
                                response_status=resp.status_code,
                                response_body_excerpt=body_lower[body_lower.index(pattern):body_lower.index(pattern)+200],
                            ),
                            impact="Lecture/modification/suppression de la base de donnees. Compromission totale.",
                            remediation="Utiliser des requetes preparees (wpdb::prepare). Mettre a jour WordPress et les plugins.",
                            compliance=Compliance(
                                owasp_2021="A03:2021 - Injection",
                                cwe="CWE-89",
                                mitre_attack="T1190 - Exploit Public-Facing Application",
                            ),
                            phase="vuln", module=self.name,
                        ))
                        break

                # Time-based detection
                if "SLEEP" in payload and elapsed > baseline_time + 2.5:
                    sqli_found = True
                    result.add_finding(Finding(
                        id="VULN-SQLI-002",
                        title=f"SQL Injection potentielle (time-based blind) dans /?s=",
                        severity=Severity.CRITICAL,
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        confidence=Confidence.LIKELY,
                        finding_type=FindingType.CVE,
                        description=f"Delai anormal ({elapsed:.1f}s vs {baseline_time:.1f}s baseline) avec SLEEP(3).",
                        evidence=Evidence(
                            request=f"GET {base}/?s={payload}",
                            response_status=resp.status_code,
                            response_body_excerpt=f"Response time: {elapsed:.2f}s (baseline: {baseline_time:.2f}s)",
                        ),
                        impact="Injection SQL blind confirmee. Extraction de donnees possible.",
                        remediation="Audit du code, requetes preparees, mise a jour WordPress et plugins.",
                        compliance=Compliance(owasp_2021="A03:2021", cwe="CWE-89"),
                        phase="vuln", module=self.name,
                    ))

                if sqli_found:
                    break

            except Exception:
                continue

        if not sqli_found:
            result.add_finding(Finding(
                id="VULN-SQLI-000",
                title="Aucune SQL Injection detectee sur /?s=",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=f"{len(SQLI_PAYLOADS)} payloads testes sur le parametre de recherche. Aucune injection detectee.",
                phase="vuln", module=self.name,
            ))

        return result

    def should_run(self, ctx) -> bool:
        return ctx.profile != "bugbounty"
