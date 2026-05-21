"""WordPress version detection module — multiple methods."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class WPVersionModule(BazookaModule):
    name = "enum.wp_version"
    phase = "enum"
    description = "WordPress version detection"
    profiles = ["quick", "standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        versions_found: list[tuple[str, str]] = []  # (version, method)

        base = ctx.target.url

        # Method 1: Meta generator tag
        resp = await session.get(base, use_cache=True)
        if resp.status_code == 200:
            match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([\d.]+)', resp.text)
            if match:
                versions_found.append((match.group(1), "meta_generator"))

        # Method 2: readme.html
        resp = await session.get(f"{base}/readme.html")
        if resp.status_code == 200 and "wordpress" in resp.text.lower():
            match = re.search(r'Version\s+([\d.]+)', resp.text)
            if match:
                versions_found.append((match.group(1), "readme.html"))

        # Method 3: RSS feed
        resp = await session.get(f"{base}/feed/")
        if resp.status_code == 200:
            match = re.search(r'generator>https?://wordpress\.org/\?v=([\d.]+)', resp.text)
            if match:
                versions_found.append((match.group(1), "rss_feed"))

        # Method 4: wp-links-opml.php
        resp = await session.get(f"{base}/wp-links-opml.php")
        if resp.status_code == 200:
            match = re.search(r'generator="WordPress/([\d.]+)', resp.text)
            if match:
                versions_found.append((match.group(1), "wp-links-opml"))

        # Method 5: REST API
        resp = await session.get(f"{base}/wp-json/")
        if resp.status_code == 200:
            try:
                data = resp.json()
                if "namespaces" in data:
                    result.add_data("rest_api_available", True)
                    result.add_data("rest_api_namespaces", data.get("namespaces", []))
            except Exception:
                pass

        # Method 6: CSS/JS version strings
        main_resp = await session.get(base, use_cache=True)
        if main_resp.status_code == 200:
            ver_matches = re.findall(r'\?ver=([\d.]+)', main_resp.text)
            if ver_matches:
                from collections import Counter
                most_common = Counter(ver_matches).most_common(1)
                if most_common:
                    versions_found.append((most_common[0][0], "css_js_ver"))

        # Determine best version
        if versions_found:
            version = versions_found[0][0]
            methods = [m for _, m in versions_found]

            # Prefer the MD5-fingerprinted version if present and divergent;
            # that detection is hash-based and far more reliable than meta tags.
            fp_ver = getattr(ctx.target, "wp_version_fingerprinted", None)
            if fp_ver and fp_ver != version:
                import logging
                logging.getLogger(__name__).warning(
                    "wp_version mismatch: regex=%s fingerprint=%s — using fingerprint",
                    version, fp_ver,
                )
                version = fp_ver
                methods = ["md5_fingerprint"] + methods
            elif fp_ver:
                methods = ["md5_fingerprint"] + methods

            ctx.target.wp_version = version
            result.add_data("wp_version", version)
            result.add_data("wp_version_methods", methods)

            result.add_finding(Finding(
                id="ENUM-VER-001",
                title=f"WordPress {version} detecte",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=f"WordPress version {version} detecte via: {', '.join(methods)}.",
                evidence=Evidence(request=f"Multiple methods on {base}", response_body_excerpt=f"Version: {version}"),
                impact="La version expose permet de cibler des CVEs specifiques.",
                remediation="Masquer la version WordPress (remove_action('wp_head', 'wp_generator')).",
                phase="enum",
                module=self.name,
            ))
        else:
            result.add_data("wp_version", None)

        return result
