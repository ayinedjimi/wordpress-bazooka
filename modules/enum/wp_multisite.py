"""WordPress Multisite detection — signup, REST API indicators, HTML patterns."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class WPMultisiteModule(BazookaModule):
    name = "enum.wp_multisite"
    phase = "enum"
    description = "WordPress Multisite detection"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        is_multisite = False
        open_signup = False
        indicators: list[str] = []

        # Test 1: wp-signup.php
        signup_url = f"{base}/wp-signup.php"
        resp = await session.get(signup_url)
        if resp.status_code == 200:
            body = resp.text
            # Check for actual signup form elements (not just a redirect page)
            signup_markers = [
                "id=\"setupform\"",
                "id=\"signup-content\"",
                "name=\"stage\"",
                "signup_for",
                "blogname",
                "Create a New Site",
                "Get your own",
            ]
            form_found = any(marker in body for marker in signup_markers)
            if form_found:
                is_multisite = True
                open_signup = True
                indicators.append("wp-signup.php with registration form")
        elif resp.status_code == 302:
            # Redirect to wp-login.php often indicates multisite without open signup
            location = resp.headers.get("Location", "")
            if "wp-login.php" in location:
                is_multisite = True
                indicators.append("wp-signup.php redirects to wp-login.php (multisite, closed signup)")

        # Test 2: REST API multisite indicators
        api_url = f"{base}/wp-json/"
        resp = await session.get(api_url, use_cache=True)
        if resp.status_code == 200:
            try:
                data = resp.json()
                namespaces = data.get("namespaces", [])
                routes = list(data.get("routes", {}).keys())

                # wp/v2/sites endpoint or multisite-specific namespaces
                multisite_routes = [r for r in routes if "/sites" in r or "/network" in r]
                if multisite_routes:
                    is_multisite = True
                    indicators.append(f"REST API multisite routes: {', '.join(multisite_routes[:5])}")

                # Check for wp-site-health or network-admin references
                for ns in namespaces:
                    if "network" in ns.lower():
                        is_multisite = True
                        indicators.append(f"Multisite namespace: {ns}")
            except Exception:
                pass

        # Test 3: HTML patterns — look for /sites/ or /blog/ subsite patterns
        resp = await session.get(base, use_cache=True)
        if resp.status_code == 200:
            body = resp.text
            # Links to /sites/{name}/ or /blog/{name}/
            sites_pattern = re.findall(r'href=["\'][^"\']*?/sites/([a-zA-Z0-9_-]+)/', body)
            blog_pattern = re.findall(r'href=["\'][^"\']*?/blog/([a-zA-Z0-9_-]+)/', body)

            if sites_pattern:
                is_multisite = True
                unique_sites = list(set(sites_pattern))[:10]
                indicators.append(f"Subsite paths found: /sites/ ({', '.join(unique_sites)})")

            if blog_pattern:
                is_multisite = True
                unique_blogs = list(set(blog_pattern))[:10]
                indicators.append(f"Blog paths found: /blog/ ({', '.join(unique_blogs)})")

            # Check for network-admin links in source
            if "/wp-admin/network/" in body:
                is_multisite = True
                indicators.append("Network admin link found in HTML source")

        result.add_data("is_multisite", is_multisite)
        result.add_data("open_signup", open_signup)
        result.add_data("indicators", indicators)

        if is_multisite and open_signup:
            result.add_finding(Finding(
                id="ENUM-MULTI-001",
                title="WordPress Multisite avec inscription ouverte detecte",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION,
                description=(
                    f"WordPress Multisite detecte avec inscription ouverte. "
                    f"Indicateurs: {'; '.join(indicators)}."
                ),
                evidence=Evidence(
                    request=f"GET {signup_url}",
                    response_status=200,
                ),
                impact=(
                    "Un attaquant peut creer un sous-site et potentiellement "
                    "uploader des fichiers, installer des themes ou pivoter vers d'autres sites."
                ),
                remediation=(
                    "Desactiver l'inscription ouverte dans Network Admin > Settings "
                    "ou definir 'Registration is Disabled' si non necessaire."
                ),
                compliance=Compliance(owasp_2021="A05:2021", cwe="CWE-284"),
                phase="enum",
                module=self.name,
            ))
        elif is_multisite:
            result.add_finding(Finding(
                id="ENUM-MULTI-002",
                title="WordPress Multisite detecte (inscription fermee)",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=f"WordPress Multisite detecte. Indicateurs: {'; '.join(indicators)}.",
                evidence=Evidence(request=f"GET {signup_url}"),
                phase="enum",
                module=self.name,
            ))

        return result
