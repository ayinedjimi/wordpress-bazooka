"""Active testing of known plugin CVEs."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


# Map of plugin slug → list of active CVE tests
# Each test: (cve_id, description, method, path, check_fn_name, severity, cvss, cwe)
PLUGIN_CVE_TESTS: dict[str, list[dict]] = {
    "contact-form-7": [
        {
            "id": "CVE-2020-35489",
            "title": "Contact Form 7 unrestricted file upload",
            "method": "GET",
            "path": "/wp-json/contact-form-7/v1/contact-forms",
            "check": "status_200_json",
            "severity": Severity.MEDIUM,
            "cvss": 5.3,
            "cwe": "CWE-434",
            "desc": (
                "REST API for Contact Form 7 form structures is accessible. "
                "Exposed form configurations reveal file upload fields and "
                "accepted extensions, aiding targeted upload attacks."
            ),
        },
    ],
    "elementor": [
        {
            "id": "CVE-2022-29455",
            "title": "Elementor DOM-based XSS via REST API",
            "method": "GET",
            "path": "/wp-json/elementor/v1/system-info",
            "check": "status_200_json",
            "severity": Severity.HIGH,
            "cvss": 6.1,
            "cwe": "CWE-79",
            "desc": (
                "Elementor REST API v1 system-info endpoint is accessible without "
                "authentication, leaking server and plugin configuration. Versions "
                "before 3.5.6 are vulnerable to DOM-based XSS."
            ),
        },
        {
            "id": "ELEMENTOR-API-ENUM",
            "title": "Elementor REST API endpoint enumeration",
            "method": "GET",
            "path": "/wp-json/elementor/v1/",
            "check": "status_200",
            "severity": Severity.MEDIUM,
            "cvss": 5.3,
            "cwe": "CWE-200",
            "desc": (
                "The Elementor REST API root is accessible and may expose internal "
                "route listings, template data, and configuration."
            ),
        },
    ],
    "updraftplus": [
        {
            "id": "CVE-2022-0633",
            "title": "UpdraftPlus backup download without proper authorization",
            "method": "GET",
            "path": "/wp-admin/admin-ajax.php?action=updraft_download_backup&type=db&timestamp=0&nonce=0",
            "check": "not_403_not_401",
            "severity": Severity.CRITICAL,
            "cvss": 8.5,
            "cwe": "CWE-639",
            "desc": (
                "UpdraftPlus versions before 1.22.3 (free) / 2.22.3 (premium) "
                "allow any authenticated user to download backups via "
                "admin-ajax.php?action=updraft_download_backup by manipulating "
                "the nonce and timestamp parameters (CVE-2022-0633)."
            ),
        },
    ],
    "wp-file-manager": [
        {
            "id": "CVE-2020-25213",
            "title": "WP File Manager unauthenticated RCE via connector.minimal.php",
            "method": "GET",
            "path": "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php",
            "check": "connector_alive",
            "severity": Severity.CRITICAL,
            "cvss": 9.8,
            "cwe": "CWE-434",
            "desc": (
                "WP File Manager versions 6.0-6.8 expose elFinder's "
                "connector.minimal.php without authentication, allowing "
                "unauthenticated arbitrary file upload and remote code execution."
            ),
        },
    ],
    "litespeed-cache": [
        {
            "id": "LSCACHE-PRIVESC",
            "title": "LiteSpeed Cache unauthenticated AJAX endpoint",
            "method": "GET",
            "path": "/wp-admin/admin-ajax.php?action=litespeed_update",
            "check": "not_403_not_401",
            "severity": Severity.HIGH,
            "cvss": 7.5,
            "cwe": "CWE-269",
            "desc": (
                "LiteSpeed Cache AJAX action is accessible, potentially allowing "
                "unauthenticated cache purging or configuration changes. Multiple "
                "privilege escalation vectors have been reported in various versions."
            ),
        },
        {
            "id": "CVE-2024-28000",
            "title": "LiteSpeed Cache role simulation privilege escalation",
            "method": "GET",
            "path": "/wp-admin/admin-ajax.php?action=litespeed_preload",
            "check": "not_403_not_401",
            "severity": Severity.CRITICAL,
            "cvss": 9.8,
            "cwe": "CWE-269",
            "desc": (
                "LiteSpeed Cache versions before 6.4 contain a privilege escalation "
                "via the role simulation feature. The preload AJAX endpoint can be "
                "used to probe for this vulnerability."
            ),
        },
    ],
    "really-simple-ssl": [
        {
            "id": "CVE-2023-49583",
            "title": "Really Simple SSL 2FA bypass",
            "method": "POST",
            "path": "/wp-json/reallysimplessl/v1/two_fa/skip_onboarding",
            "check": "not_403_not_401",
            "severity": Severity.CRITICAL,
            "cvss": 9.8,
            "cwe": "CWE-287",
            "desc": (
                "Really Simple SSL Pro versions 9.0.0-9.1.1 allow 2FA bypass via "
                "the REST API skip_onboarding endpoint, enabling authentication "
                "bypass for any user including administrators."
            ),
        },
    ],
    "jetpack": [
        {
            "id": "JETPACK-INFO-DISC",
            "title": "Jetpack REST API information disclosure",
            "method": "GET",
            "path": "/wp-json/jetpack/v4/module/all",
            "check": "status_200_json",
            "severity": Severity.MEDIUM,
            "cvss": 5.3,
            "cwe": "CWE-200",
            "desc": (
                "Jetpack REST API exposes module configuration data without "
                "authentication, revealing which security features are active or "
                "disabled."
            ),
        },
        {
            "id": "JETPACK-CONN-INFO",
            "title": "Jetpack connection info exposure",
            "method": "GET",
            "path": "/wp-json/jetpack/v4/connection/data",
            "check": "status_200_json",
            "severity": Severity.MEDIUM,
            "cvss": 5.3,
            "cwe": "CWE-200",
            "desc": (
                "Jetpack connection data endpoint is accessible, potentially "
                "revealing the connected WordPress.com account and site ID."
            ),
        },
    ],
}


class PluginVulnsActiveModule(BazookaModule):
    name = "vuln.plugin_vulns_active"
    phase = "vuln"
    description = "Active testing of known plugin CVEs"
    profiles = ["aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url

        detected_slugs = {p.slug for p in ctx.target.plugins}

        tested_count = 0
        for slug, tests in PLUGIN_CVE_TESTS.items():
            if slug not in detected_slugs:
                continue

            for test in tests:
                url = f"{base}{test['path']}"
                method = test["method"]

                try:
                    if method == "GET":
                        resp = await session.get(url, use_cache=False)
                    else:
                        resp = await session.post(url)
                except Exception:
                    continue

                tested_count += 1
                vulnerable = False
                confidence = Confidence.LIKELY

                check = test["check"]

                if check == "status_200_json":
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            if data:  # Non-empty JSON response
                                vulnerable = True
                                confidence = Confidence.CONFIRMED
                        except Exception:
                            pass

                elif check == "status_200":
                    if resp.status_code == 200:
                        vulnerable = True
                        confidence = Confidence.CONFIRMED

                elif check == "not_403_not_401":
                    if resp.status_code not in (401, 403, 404, 405):
                        vulnerable = True
                        # 200 is confirmed, anything else is likely
                        if resp.status_code == 200:
                            confidence = Confidence.CONFIRMED
                        else:
                            confidence = Confidence.LIKELY

                elif check == "connector_alive":
                    if resp.status_code == 200:
                        body = resp.text[:1000].lower()
                        # elFinder connector returns JSON with specific keys
                        if "elfinder" in body or '"error"' in body or '"cwd"' in body:
                            vulnerable = True
                            confidence = Confidence.CONFIRMED
                        elif resp.status_code == 200 and len(resp.content) > 0:
                            # Connector is alive but might be patched
                            vulnerable = True
                            confidence = Confidence.POSSIBLE

                if vulnerable:
                    severity = test["severity"]
                    # Downgrade from CRITICAL to MEDIUM if only POSSIBLE confidence
                    if confidence == Confidence.POSSIBLE and severity == Severity.CRITICAL:
                        effective_severity = Severity.MEDIUM
                        effective_cvss = min(test["cvss"], 5.3)
                    elif confidence == Confidence.POSSIBLE:
                        effective_severity = Severity.MEDIUM
                        effective_cvss = min(test["cvss"], 5.3)
                    else:
                        effective_severity = severity
                        effective_cvss = test["cvss"]

                    body_excerpt = resp.text[:300] if resp.text else ""
                    result.add_finding(Finding(
                        id=f"VULN-PLUGIN-{test['id']}",
                        title=f"{test['title']} ({slug}) on {ctx.target.domain}",
                        severity=effective_severity,
                        cvss_score=effective_cvss,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        confidence=confidence,
                        finding_type=FindingType.CVE if test["id"].startswith("CVE") else FindingType.MISCONFIGURATION,
                        description=test["desc"],
                        evidence=Evidence(
                            request=f"{method} {url}",
                            response_status=resp.status_code,
                            response_headers={
                                k: v for k, v in list(resp.headers.items())[:10]
                            },
                            response_body_excerpt=body_excerpt,
                        ),
                        impact=(
                            f"Exploitation of this vulnerability in '{slug}' could lead to "
                            f"unauthorized access, data theft, or remote code execution "
                            f"depending on the specific CVE."
                        ),
                        remediation=(
                            f"Update '{slug}' to the latest version immediately. If the "
                            f"plugin is no longer maintained, consider replacing it with "
                            f"a secure alternative."
                        ),
                        compliance=Compliance(
                            owasp_2021="A06:2021 - Vulnerable and Outdated Components",
                            cwe=test["cwe"],
                            mitre_attack="T1190 - Exploit Public-Facing Application",
                        ),
                        references=[
                            f"https://nvd.nist.gov/vuln/detail/{test['id']}"
                            if test["id"].startswith("CVE") else
                            f"https://wpscan.com/plugin/{slug}",
                        ],
                        phase="vuln",
                        module=self.name,
                        tags=["plugin-cve", slug, "active-test"],
                    ))

        result.add_data("plugin_vulns_active_tested", tested_count)
        return result
