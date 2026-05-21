"""WordPress plugin enumeration — passive HTML, REST namespaces, readme.txt, wordlist."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from core.models import Evidence, Finding, Severity, Confidence, FindingType, WPPlugin, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


PLUGIN_PATH_RE = re.compile(r'/wp-content/(?:mu-)?plugins/([a-zA-Z0-9_\-\.]+)/', re.IGNORECASE)
VER_QUERY_RE = re.compile(r'/wp-content/(?:mu-)?plugins/([a-zA-Z0-9_\-\.]+)/[^"\'\s>]*\?[^"\'\s>]*?ver=([0-9][0-9A-Za-z\.\-_]*)', re.IGNORECASE)
STABLE_TAG_RE = re.compile(r'Stable tag:\s*"?([0-9][0-9A-Za-z\.\-]*)"?', re.IGNORECASE)
VERSION_RE = re.compile(r'^\s*Version:?\s*[:=]?\s*"?([0-9][0-9A-Za-z\.\-]+)"?', re.IGNORECASE | re.MULTILINE)
# Looser fallback: "Version X.Y[.Z]" anywhere (for release_notes/changelog)
VERSION_LOOSE_RE = re.compile(r'\bVersion\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:\.[0-9]+)?)', re.IGNORECASE)
# Common WP plugin meta files where versions appear
PLUGIN_META_FILES = ("readme.txt", "release_notes.txt", "changelog.txt", "CHANGELOG.md")
NAME_RE = re.compile(r'===\s*(.+?)\s*===')

WORDLIST_PATH = Path(__file__).parent.parent.parent / "data" / "wp_plugins_wordlist.txt"
PRIORITY_PATH = Path(__file__).parent.parent.parent / "data" / "wp_plugins_priority.txt"


def _extract_versions_from_html(html: str) -> dict[str, str]:
    versions: dict[str, str] = {}
    for m in VER_QUERY_RE.finditer(html):
        slug = m.group(1)
        ver = m.group(2)
        if slug not in versions:
            versions[slug] = ver
    return versions


def _extract_slugs_from_html(html: str) -> set[str]:
    return set(PLUGIN_PATH_RE.findall(html))


class WPPluginsModule(BazookaModule):
    name = "enum.wp_plugins"
    phase = "enum"
    description = "WordPress plugin enumeration"
    profiles = ["quick", "standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        wp_content = ctx.target.wp_content_path
        plugins: dict[str, WPPlugin] = {}

        # === Method 1: passive HTML scrape on multiple pages ===
        passive_pages = [base, f"{base}/", f"{base}/wp-login.php",
                         f"{base}/?p=1", f"{base}/feed/"]
        seen_urls = set()
        wp_core_ver = (ctx.target.wp_version or "").strip()
        for url in passive_pages:
            if url in seen_urls:
                continue
            seen_urls.add(url)
            try:
                resp = await session.get(url, use_cache=True)
            except Exception:
                continue
            if resp.status_code >= 400:
                continue
            html = resp.text or ""
            for slug in _extract_slugs_from_html(html):
                if slug not in plugins:
                    plugins[slug] = WPPlugin(slug=slug, discovery_method="html_passive")
            for slug, ver in _extract_versions_from_html(html).items():
                if slug not in plugins or plugins[slug].version:
                    continue
                # Reject WP-core-version-equal ?ver= values: they're a WP fallback
                # when the plugin registered its asset without an explicit version.
                if wp_core_ver and ver == wp_core_ver:
                    continue
                plugins[slug].version = ver

        # === Method 2: REST API namespaces ===
        namespaces = ctx.data.get("rest_api_namespaces", [])
        namespace_map = {
            "contact-form-7": "contact-form-7",
            "jetpack": "jetpack",
            "yoast": "wordpress-seo",
            "wc": "woocommerce",
            "wpml": "sitepress-multilingual-cms",
            "elementor": "elementor",
            "acf": "advanced-custom-fields",
            "redirection": "redirection",
            "wp-mail-smtp": "wp-mail-smtp",
            "rank-math": "seo-by-rank-math",
        }
        if isinstance(namespaces, list):
            for ns in namespaces:
                ns_base = ns.split("/")[0] if "/" in ns else ns
                if ns_base in namespace_map:
                    slug = namespace_map[ns_base]
                    if slug not in plugins:
                        plugins[slug] = WPPlugin(slug=slug, discovery_method="rest_namespace")

        # === Method 3: probe plugin meta files (overrides Method 1's ?ver= as more authoritative) ===
        for slug, plugin in list(plugins.items()):
            authoritative_ver: Optional[str] = None
            for meta_file in PLUGIN_META_FILES:
                if authoritative_ver and plugin.name:
                    break
                meta_url = f"{base}{wp_content}plugins/{slug}/{meta_file}"
                try:
                    resp = await session.get(meta_url)
                except Exception:
                    continue
                if resp.status_code != 200 or len(resp.text) < 30:
                    continue
                txt = resp.text
                if not authoritative_ver:
                    for rx in (STABLE_TAG_RE, VERSION_RE, VERSION_LOOSE_RE):
                        m = rx.search(txt)
                        if not m:
                            continue
                        cand = m.group(1)
                        if cand.lower() in ("trunk", "main", "master"):
                            continue
                        authoritative_ver = cand
                        break
                if not plugin.name:
                    m = NAME_RE.search(txt)
                    if m:
                        plugin.name = m.group(1)
            if authoritative_ver:
                # Authoritative meta-file version trumps the ?ver= leaked from passive HTML.
                plugin.version = authoritative_ver

        # === Method 4: aggressive wordlist brute (only in aggressive profile) ===
        if ctx.profile == "aggressive" and WORDLIST_PATH.exists():
            await self._wordlist_brute(base, wp_content, plugins, session)

        plugin_list = list(plugins.values())
        ctx.target.plugins = plugin_list

        plugins_detected = [
            {"slug": p.slug, "version": p.version, "name": p.name,
             "source": p.discovery_method}
            for p in plugin_list
        ]
        ctx.set_data("plugins_detected", plugins_detected)
        result.add_data("plugins", [p.model_dump() for p in plugin_list])
        result.add_data("plugins_detected", plugins_detected)

        # Emit per-plugin INFO findings (with version)
        for idx, p in enumerate(plugin_list, 1):
            ver_str = p.version or "version inconnue"
            result.add_finding(Finding(
                id=f"ENUM-PLG-{idx:03d}",
                title=f"Plugin detecte: {p.slug} {ver_str}",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED if p.version else Confidence.LIKELY,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=f"Plugin {p.name or p.slug} (slug={p.slug}, version={p.version or 'inconnue'}, source={p.discovery_method}).",
                evidence=Evidence(request=f"Detection {p.discovery_method} sur {base}"),
                impact="Les versions de plugins peuvent correspondre a des CVEs connues.",
                remediation="Maintenir tous les plugins a jour. Supprimer les plugins inutilises.",
                compliance=Compliance(owasp_2021="A06:2021", cwe="CWE-1104"),
                phase="enum",
                module=self.name,
                tags=["plugin", p.slug],
            ))

        if plugin_list:
            result.add_finding(Finding(
                id="ENUM-PLG-000",
                title=f"{len(plugin_list)} plugin(s) WordPress detecte(s)",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=f"Plugins: {', '.join(p.slug for p in plugin_list[:20])}{'...' if len(plugin_list) > 20 else ''}",
                evidence=Evidence(request=f"HTML parse + REST namespaces + wordlist on {base}"),
                impact="Les versions de plugins peuvent correspondre a des CVEs connues.",
                remediation="Maintenir tous les plugins a jour. Supprimer les plugins inutilises.",
                compliance=Compliance(owasp_2021="A06:2021", cwe="CWE-1104"),
                phase="enum",
                module=self.name,
            ))

        return result

    async def _wordlist_brute(self, base: str, wp_content: str,
                              plugins: dict, session) -> None:
        # Load priority list FIRST (curated: admin/management/security/popular plugins)
        # — these are the ones we want even on a small budget.
        priority_lines: list[str] = []
        if PRIORITY_PATH.exists():
            try:
                with open(PRIORITY_PATH, "r", encoding="utf-8", errors="ignore") as f:
                    priority_lines = [ln.strip() for ln in f]
            except Exception:
                pass
        try:
            with open(WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
                wordlist_lines = [ln.strip() for ln in f]
        except Exception:
            wordlist_lines = []
        lines = priority_lines + wordlist_lines
        slugs: list[str] = []
        for ln in lines:
            if not ln or ln.startswith("#"):
                continue
            m = re.search(r'wp-content/plugins/([^/\s]+)/?', ln)
            if m:
                slug = m.group(1)
            else:
                slug = ln.strip("/")
            if not slug or "/" in slug:
                continue
            # filter ascii alnum + dash/dot/underscore
            if not re.match(r'^[a-zA-Z0-9_\-\.]+$', slug):
                continue
            slugs.append(slug)
        # Keep first 500 unique
        seen = set()
        target_slugs: list[str] = []
        for s in slugs:
            if s in seen or s in plugins:
                continue
            seen.add(s)
            target_slugs.append(s)
            if len(target_slugs) >= 500:
                break

        sem = asyncio.Semaphore(20)

        async def probe(slug: str) -> Optional[tuple[str, Optional[str], int]]:
            url = f"{base}{wp_content}plugins/{slug}/readme.txt"
            async with sem:
                try:
                    resp = await session.head(url, use_cache=False, follow_redirects=False)
                except Exception:
                    return None
            status = resp.status_code
            # Redirects (301/302) mean WP rewrote to a themed 404 — not a real plugin
            if status not in (200, 403):
                return None
            try:
                if session.is_waf_generic_page(status, len(resp.content)):
                    return None
            except Exception:
                pass
            version: Optional[str] = None
            if status == 200:
                try:
                    g = await session.get(url, use_cache=True, follow_redirects=False)
                except Exception:
                    return None
                # Confirm it's actually a WP plugin readme, not a generic HTML
                if g.status_code != 200:
                    return None
                txt = g.text or ""
                is_real_readme = (
                    "=== " in txt[:200]  # WP readme.txt section heading
                    or STABLE_TAG_RE.search(txt) is not None
                    or "Contributors:" in txt[:500]
                )
                if not is_real_readme:
                    return None
                m = STABLE_TAG_RE.search(txt) or VERSION_RE.search(txt)
                if m:
                    version = m.group(1)
            return slug, version, status

        results = await asyncio.gather(*(probe(s) for s in target_slugs),
                                       return_exceptions=True)
        for r in results:
            if not r or isinstance(r, Exception):
                continue
            slug, version, status = r
            if slug not in plugins:
                plugins[slug] = WPPlugin(
                    slug=slug,
                    version=version,
                    discovery_method=f"wordlist_brute_{status}",
                )
