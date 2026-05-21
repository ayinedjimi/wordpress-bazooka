"""Deep REST API exposure audit."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class RestAPIExposureModule(BazookaModule):
    name = "vuln.rest_api_exposure"
    phase = "vuln"
    description = "Deep REST API exposure audit"
    profiles = ["standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url

        # ── Test 1: Users with edit context (full data with emails) ──────────
        try:
            resp = await session.get(
                f"{base}/wp-json/wp/v2/users?context=edit",
                use_cache=False,
            )
            if resp.status_code == 200:
                body = resp.text[:2000]
                try:
                    data = resp.json()
                except Exception:
                    data = []
                # Confirm it actually contains email fields (edit context)
                has_emails = False
                if isinstance(data, list) and data:
                    has_emails = any("email" in u for u in data if isinstance(u, dict))
                if has_emails:
                    user_count = len(data) if isinstance(data, list) else 0
                    result.add_finding(Finding(
                        id="VULN-REST-001",
                        title=f"REST API exposes full user data with emails on {ctx.target.domain}",
                        severity=Severity.CRITICAL,
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        confidence=Confidence.CONFIRMED,
                        finding_type=FindingType.INFORMATION_DISCLOSURE,
                        description=(
                            f"The REST API endpoint /wp-json/wp/v2/users?context=edit returns "
                            f"full user objects including email addresses without authentication. "
                            f"{user_count} user(s) exposed."
                        ),
                        evidence=Evidence(
                            request=f"GET {base}/wp-json/wp/v2/users?context=edit",
                            response_status=resp.status_code,
                            response_headers=dict(resp.headers.items()),
                            response_body_excerpt=body[:500],
                        ),
                        impact=(
                            "Full user data exposure including emails enables targeted phishing, "
                            "credential stuffing, and social engineering against site administrators."
                        ),
                        remediation=(
                            "Restrict the REST API users endpoint to authenticated requests only. "
                            "Use a plugin like Disable REST API or add a filter to "
                            "rest_authentication_errors to block unauthenticated access."
                        ),
                        compliance=Compliance(
                            owasp_2021="A01:2021 - Broken Access Control",
                            cwe="CWE-200",
                            mitre_attack="T1589.002 - Gather Victim Identity: Email Addresses",
                        ),
                        references=[
                            "https://developer.wordpress.org/rest-api/reference/users/",
                            "https://www.wordfence.com/blog/2016/12/wordfence-blocks-username-harvesting/",
                        ],
                        phase="vuln",
                        module=self.name,
                        tags=["rest-api", "user-enumeration", "email-disclosure"],
                    ))
        except Exception:
            pass

        # ── Test 2: Settings endpoint exposed ────────────────────────────────
        try:
            resp = await session.get(
                f"{base}/wp-json/wp/v2/settings",
                use_cache=False,
            )
            if resp.status_code == 200:
                body = resp.text[:2000]
                try:
                    data = resp.json()
                except Exception:
                    data = {}
                # Settings endpoint should never return 200 without auth
                if isinstance(data, dict) and data:
                    result.add_finding(Finding(
                        id="VULN-REST-002",
                        title=f"REST API settings endpoint exposed on {ctx.target.domain}",
                        severity=Severity.CRITICAL,
                        cvss_score=8.6,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        confidence=Confidence.CONFIRMED,
                        finding_type=FindingType.MISCONFIGURATION,
                        description=(
                            f"The REST API endpoint /wp-json/wp/v2/settings returns site "
                            f"configuration data without authentication. Exposed keys: "
                            f"{', '.join(list(data.keys())[:10])}"
                        ),
                        evidence=Evidence(
                            request=f"GET {base}/wp-json/wp/v2/settings",
                            response_status=resp.status_code,
                            response_headers=dict(resp.headers.items()),
                            response_body_excerpt=body[:500],
                        ),
                        impact=(
                            "Site settings exposure may reveal internal configuration, "
                            "admin email, timezone, and other sensitive data. If writable, "
                            "an attacker could modify site settings."
                        ),
                        remediation=(
                            "Ensure the settings endpoint requires administrator authentication. "
                            "Check for broken authentication plugins or misconfigured REST API "
                            "permissions."
                        ),
                        compliance=Compliance(
                            owasp_2021="A01:2021 - Broken Access Control",
                            cwe="CWE-200",
                        ),
                        references=[
                            "https://developer.wordpress.org/rest-api/reference/settings/",
                        ],
                        phase="vuln",
                        module=self.name,
                        tags=["rest-api", "settings", "configuration-exposure"],
                    ))
        except Exception:
            pass

        # ── Test 3: Themes endpoint with inactive themes ─────────────────────
        try:
            resp = await session.get(
                f"{base}/wp-json/wp/v2/themes",
                use_cache=False,
            )
            if resp.status_code == 200:
                body = resp.text[:2000]
                try:
                    data = resp.json()
                except Exception:
                    data = []
                if isinstance(data, list) and data:
                    inactive_themes = [
                        t for t in data
                        if isinstance(t, dict) and t.get("status") != "active"
                    ]
                    if inactive_themes:
                        theme_names = [
                            t.get("name", t.get("stylesheet", "unknown"))
                            for t in inactive_themes[:5]
                        ]
                        result.add_finding(Finding(
                            id="VULN-REST-003",
                            title=f"REST API exposes inactive themes on {ctx.target.domain}",
                            severity=Severity.MEDIUM,
                            cvss_score=5.3,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            confidence=Confidence.CONFIRMED,
                            finding_type=FindingType.INFORMATION_DISCLOSURE,
                            description=(
                                f"The REST API themes endpoint reveals {len(inactive_themes)} "
                                f"inactive theme(s): {', '.join(str(n) for n in theme_names)}. "
                                f"Inactive themes are often unpatched and can contain exploitable "
                                f"vulnerabilities."
                            ),
                            evidence=Evidence(
                                request=f"GET {base}/wp-json/wp/v2/themes",
                                response_status=resp.status_code,
                                response_headers=dict(resp.headers.items()),
                                response_body_excerpt=body[:500],
                            ),
                            impact=(
                                "Inactive theme disclosure helps attackers identify unpatched "
                                "themes to target with known CVEs."
                            ),
                            remediation=(
                                "Delete inactive themes from the server. Restrict the themes "
                                "endpoint to authenticated administrators."
                            ),
                            compliance=Compliance(
                                owasp_2021="A05:2021 - Security Misconfiguration",
                                cwe="CWE-200",
                            ),
                            references=[
                                "https://developer.wordpress.org/rest-api/reference/themes/",
                            ],
                            phase="vuln",
                            module=self.name,
                            tags=["rest-api", "themes", "info-disclosure"],
                        ))
        except Exception:
            pass

        # ── Test 4: Plugins endpoint exposed ─────────────────────────────────
        try:
            resp = await session.get(
                f"{base}/wp-json/wp/v2/plugins",
                use_cache=False,
            )
            if resp.status_code == 200:
                body = resp.text[:2000]
                try:
                    data = resp.json()
                except Exception:
                    data = []
                if isinstance(data, list) and data:
                    plugin_info = []
                    for p in data[:10]:
                        if isinstance(p, dict):
                            plugin_info.append(
                                f"{p.get('name', p.get('plugin', 'unknown'))} "
                                f"v{p.get('version', '?')}"
                            )
                    result.add_finding(Finding(
                        id="VULN-REST-004",
                        title=f"REST API exposes plugin list with versions on {ctx.target.domain}",
                        severity=Severity.HIGH,
                        cvss_score=6.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        confidence=Confidence.CONFIRMED,
                        finding_type=FindingType.INFORMATION_DISCLOSURE,
                        description=(
                            f"The REST API plugins endpoint returns {len(data)} plugin(s) with "
                            f"version info without authentication: {'; '.join(plugin_info)}"
                        ),
                        evidence=Evidence(
                            request=f"GET {base}/wp-json/wp/v2/plugins",
                            response_status=resp.status_code,
                            response_headers=dict(resp.headers.items()),
                            response_body_excerpt=body[:500],
                        ),
                        impact=(
                            "Full plugin inventory with version numbers enables precise CVE "
                            "matching and targeted exploitation."
                        ),
                        remediation=(
                            "Restrict the plugins endpoint to authenticated administrators. "
                            "This endpoint should require manage_options capability by default."
                        ),
                        compliance=Compliance(
                            owasp_2021="A01:2021 - Broken Access Control",
                            cwe="CWE-200",
                            mitre_attack="T1592.002 - Gather Victim Host Information: Software",
                        ),
                        references=[
                            "https://developer.wordpress.org/rest-api/reference/plugins/",
                        ],
                        phase="vuln",
                        module=self.name,
                        tags=["rest-api", "plugins", "version-disclosure"],
                    ))
        except Exception:
            pass

        # ── Test 5: User creation without auth ───────────────────────────────
        try:
            resp = await session.post(
                f"{base}/wp-json/wp/v2/users",
                json={
                    "username": "bz_test_nocreate_probe",
                    "email": "bz_nocreate@example.invalid",
                    "password": "BzTestProbe!2024_nocreate",
                },
                headers={"Content-Type": "application/json"},
            )
            # 401/403 = properly protected. Anything else is suspicious.
            if resp.status_code not in (401, 403):
                body = resp.text[:2000]
                severity = Severity.CRITICAL
                conf = Confidence.CONFIRMED
                # 201 = user actually created (worst case)
                # 400 = might be validation error but endpoint is reachable
                if resp.status_code == 201:
                    desc = (
                        "The REST API allows unauthenticated user creation. A POST to "
                        "/wp-json/wp/v2/users with arbitrary data returned HTTP 201. "
                        "This is a full authentication bypass."
                    )
                elif resp.status_code == 400:
                    # Could be validation error — endpoint is reachable but may not
                    # actually allow creation. Downgrade confidence.
                    severity = Severity.HIGH
                    conf = Confidence.LIKELY
                    desc = (
                        "The REST API user creation endpoint does not return 401/403. "
                        f"Response code: {resp.status_code}. The endpoint may accept "
                        "unauthenticated requests with valid data."
                    )
                else:
                    desc = (
                        f"The REST API user creation endpoint returned unexpected status "
                        f"{resp.status_code} instead of 401/403. The endpoint may be "
                        f"misconfigured or partially accessible."
                    )
                    conf = Confidence.POSSIBLE

                result.add_finding(Finding(
                    id="VULN-REST-005",
                    title=f"REST API user creation without authentication on {ctx.target.domain}",
                    severity=severity,
                    cvss_score=9.8 if resp.status_code == 201 else 7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    confidence=conf,
                    finding_type=FindingType.MISCONFIGURATION,
                    description=desc,
                    evidence=Evidence(
                        request=(
                            f"POST {base}/wp-json/wp/v2/users\n"
                            f"Content-Type: application/json\n"
                            f'{{"username":"bz_test_nocreate_probe","email":"bz_nocreate@example.invalid"}}'
                        ),
                        response_status=resp.status_code,
                        response_headers=dict(resp.headers.items()),
                        response_body_excerpt=body[:500],
                    ),
                    impact=(
                        "Unauthenticated user creation allows attackers to register accounts, "
                        "potentially with elevated privileges, leading to full site compromise."
                    ),
                    remediation=(
                        "Ensure the users endpoint requires authentication with "
                        "create_users capability. Check for vulnerable plugins that register "
                        "custom REST routes overriding default permissions."
                    ),
                    compliance=Compliance(
                        owasp_2021="A01:2021 - Broken Access Control",
                        cwe="CWE-287",
                        mitre_attack="T1136.003 - Create Account: Cloud Account",
                    ),
                    references=[
                        "https://developer.wordpress.org/rest-api/reference/users/#create-a-user",
                    ],
                    phase="vuln",
                    module=self.name,
                    tags=["rest-api", "user-creation", "auth-bypass", "critical"],
                ))
        except Exception:
            pass

        # ── Test 6: Search leaking private content ───────────────────────────
        try:
            resp = await session.get(
                f"{base}/wp-json/wp/v2/search?search=password&type=post",
                use_cache=False,
            )
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except Exception:
                    data = []
                # Check if any results have status 'private' or 'draft'
                private_results = []
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            status = item.get("status", "")
                            if status in ("private", "draft", "pending"):
                                private_results.append(item)
                if private_results:
                    result.add_finding(Finding(
                        id="VULN-REST-006",
                        title=f"REST API search leaks private/draft content on {ctx.target.domain}",
                        severity=Severity.MEDIUM,
                        cvss_score=5.3,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        confidence=Confidence.CONFIRMED,
                        finding_type=FindingType.INFORMATION_DISCLOSURE,
                        description=(
                            f"The REST API search endpoint returns {len(private_results)} "
                            f"private/draft post(s) when searching for 'password'. "
                            f"Non-public content is accessible without authentication."
                        ),
                        evidence=Evidence(
                            request=f"GET {base}/wp-json/wp/v2/search?search=password&type=post",
                            response_status=resp.status_code,
                            response_headers=dict(resp.headers.items()),
                            response_body_excerpt=json.dumps(private_results[:3], indent=2)[:500],
                        ),
                        impact=(
                            "Private and draft posts may contain sensitive information, "
                            "internal notes, or pre-publication content not intended for "
                            "public access."
                        ),
                        remediation=(
                            "Audit REST API search permissions. Ensure the search endpoint "
                            "filters results based on post status and user capabilities."
                        ),
                        compliance=Compliance(
                            owasp_2021="A01:2021 - Broken Access Control",
                            cwe="CWE-200",
                        ),
                        references=[
                            "https://developer.wordpress.org/rest-api/reference/search-results/",
                        ],
                        phase="vuln",
                        module=self.name,
                        tags=["rest-api", "search", "private-content-leak"],
                    ))
        except Exception:
            pass

        return result
