"""WordPress theme detection — style.css parsing, version extraction."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, WPTheme
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class WPThemesModule(BazookaModule):
    name = "enum.wp_themes"
    phase = "enum"
    description = "WordPress theme detection"
    profiles = ["quick", "standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        wp_content = ctx.target.wp_content_path
        themes: dict[str, WPTheme] = {}

        # Method 1: Parse HTML for theme references
        resp = await session.get(base, use_cache=True)
        if resp.status_code == 200:
            matches = re.findall(rf'{re.escape(wp_content)}themes/([a-zA-Z0-9_-]+)/', resp.text)
            for slug in set(matches):
                themes[slug] = WPTheme(slug=slug, discovery_method="html_passive")

        # Method 2: Fetch style.css for each detected theme
        for slug, theme in list(themes.items()):
            style_url = f"{base}{wp_content}themes/{slug}/style.css"
            resp = await session.get(style_url)
            if resp.status_code == 200 and len(resp.text) > 100:
                css = resp.text[:3000]
                name_match = re.search(r'Theme Name:\s*(.+)', css)
                ver_match = re.search(r'Version:\s*([\d.]+)', css)
                author_match = re.search(r'Author:\s*(.+)', css)
                parent_match = re.search(r'Template:\s*(\S+)', css)

                if name_match:
                    theme.name = name_match.group(1).strip()
                if ver_match:
                    theme.version = ver_match.group(1).strip()
                if author_match:
                    theme.author = author_match.group(1).strip()
                if parent_match:
                    parent_slug = parent_match.group(1).strip()
                    theme.parent = parent_slug
                    if parent_slug not in themes:
                        themes[parent_slug] = WPTheme(slug=parent_slug, discovery_method="child_template")

        # Fetch parent theme style.css too
        for slug, theme in list(themes.items()):
            if theme.version is None:
                style_url = f"{base}{wp_content}themes/{slug}/style.css"
                resp = await session.get(style_url)
                if resp.status_code == 200 and len(resp.text) > 100:
                    css = resp.text[:3000]
                    ver_match = re.search(r'Version:\s*([\d.]+)', css)
                    name_match = re.search(r'Theme Name:\s*(.+)', css)
                    if ver_match:
                        theme.version = ver_match.group(1).strip()
                    if name_match:
                        theme.name = name_match.group(1).strip()

        theme_list = list(themes.values())
        ctx.target.themes = theme_list
        result.add_data("themes", [t.model_dump() for t in theme_list])

        if theme_list:
            desc_parts = []
            for t in theme_list:
                v = f" v{t.version}" if t.version else ""
                p = f" (child of {t.parent})" if t.parent else ""
                desc_parts.append(f"{t.name or t.slug}{v}{p}")
            result.add_finding(Finding(
                id="ENUM-THM-001",
                title=f"Theme(s) detecte(s): {', '.join(t.name or t.slug for t in theme_list)}",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=f"Themes: {'; '.join(desc_parts)}.",
                evidence=Evidence(request=f"style.css parse"),
                phase="enum", module=self.name,
            ))

        return result
