"""Detect plugins via shortcodes found in page/post content."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, WPPlugin, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

# Map shortcode prefixes/names to plugin slugs
SHORTCODE_PLUGIN_MAP: dict[str, str] = {
    "contact-form-7": "contact-form-7",
    "contact-form": "contact-form-7",
    "wpforms": "wpforms-lite",
    "wpforms_survey": "wpforms-lite",
    "elementor": "elementor",
    "elementor-template": "elementor",
    "vc_row": "js_composer",
    "vc_column": "js_composer",
    "vc_section": "js_composer",
    "vc_column_text": "js_composer",
    "vc_single_image": "js_composer",
    "gallery": "wordpress-core-gallery",
    "gravityform": "gravityforms",
    "gravityforms": "gravityforms",
    "gform": "gravityforms",
    "ninja_form": "ninja-forms",
    "ninja_forms": "ninja-forms",
    "woocommerce": "woocommerce",
    "woocommerce_cart": "woocommerce",
    "woocommerce_checkout": "woocommerce",
    "woocommerce_my_account": "woocommerce",
    "woocommerce_order_tracking": "woocommerce",
    "products": "woocommerce",
    "product_page": "woocommerce",
    "add_to_cart": "woocommerce",
    "yoast": "wordpress-seo",
    "wpseo_breadcrumb": "wordpress-seo",
    "tablepress": "tablepress",
    "table": "tablepress",
    "mc4wp_form": "mailchimp-for-wp",
    "mailchimp": "mailchimp-for-wp",
    "et_pb_section": "divi-builder",
    "et_pb_row": "divi-builder",
    "et_pb_column": "divi-builder",
    "et_pb_text": "divi-builder",
    "fusion_builder_container": "fusion-builder",
    "fusion_builder_row": "fusion-builder",
    "fusion_builder_column": "fusion-builder",
    "rev_slider": "revslider",
    "layerslider": "layerslider",
    "wpcf7": "contact-form-7",
    "tribe_events": "the-events-calendar",
    "events-calendar-pro": "events-calendar-pro",
    "wp_google_maps": "wp-google-maps",
    "supsystic-tables": "data-tables-generator-by-supsystic",
    "formidable": "formidable",
    "frm-form": "formidable",
    "acf": "advanced-custom-fields",
    "give_form": "give",
    "wp-members": "wp-members",
    "s2member": "s2member",
    "restrict": "restrict-content",
    "mepr-membership": "memberpress",
    "learndash": "sfwd-lms",
    "ld_course_list": "sfwd-lms",
    "bbpress": "bbpress",
    "bbp-forum-index": "bbpress",
    "buddypress": "buddypress",
    "siteorigin_widget": "so-widgets-bundle",
    "su_button": "developer-flavor-developer",
    "su_tabs": "developer-flavor-developer",
}


class ShortcodeParserModule(BazookaModule):
    name = "enum.shortcode_parser"
    phase = "enum"
    description = "Detect plugins via shortcodes in page content"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        detected_shortcodes: dict[str, set[str]] = {}  # plugin_slug -> set of shortcodes
        all_shortcodes: list[str] = []

        # Collect content to search: pages and posts from REST API or ctx.data
        content_pieces: list[str] = []

        # Check if rest_api module has already fetched data
        posts_data = ctx.data.get("posts", [])
        pages_data = ctx.data.get("pages", [])

        # If no cached data, fetch from REST API directly
        if not posts_data and not pages_data:
            # Fetch posts
            resp = await session.get(f"{base}/wp-json/wp/v2/posts?per_page=50")
            if resp.status_code == 200:
                try:
                    posts_data = resp.json()
                except Exception:
                    posts_data = []

            # Fetch pages
            resp = await session.get(f"{base}/wp-json/wp/v2/pages?per_page=50")
            if resp.status_code == 200:
                try:
                    pages_data = resp.json()
                except Exception:
                    pages_data = []

        # Extract rendered content
        for item in (posts_data if isinstance(posts_data, list) else []):
            content = item.get("content", {})
            if isinstance(content, dict):
                rendered = content.get("rendered", "")
            else:
                rendered = str(content)
            if rendered:
                content_pieces.append(rendered)
            # Also check excerpt
            excerpt = item.get("excerpt", {})
            if isinstance(excerpt, dict):
                rendered_excerpt = excerpt.get("rendered", "")
            else:
                rendered_excerpt = str(excerpt)
            if rendered_excerpt:
                content_pieces.append(rendered_excerpt)

        for item in (pages_data if isinstance(pages_data, list) else []):
            content = item.get("content", {})
            if isinstance(content, dict):
                rendered = content.get("rendered", "")
            else:
                rendered = str(content)
            if rendered:
                content_pieces.append(rendered)

        # Also fetch the homepage HTML (may contain shortcode output)
        resp = await session.get(base, use_cache=True)
        if resp.status_code == 200:
            content_pieces.append(resp.text)

        # Search all content for shortcodes
        combined_content = "\n".join(content_pieces)

        # Extract all WordPress shortcodes: [shortcode_name ...] or [shortcode_name]
        shortcode_matches = re.findall(r'\[([a-zA-Z][a-zA-Z0-9_-]*)', combined_content)
        all_shortcodes = list(set(shortcode_matches))

        # Map shortcodes to plugins
        existing_plugin_slugs = {p.slug for p in ctx.target.plugins}
        new_plugins: list[WPPlugin] = []

        for shortcode in all_shortcodes:
            sc_lower = shortcode.lower()

            # Direct match
            plugin_slug = SHORTCODE_PLUGIN_MAP.get(sc_lower)

            # Prefix match if no direct match
            if not plugin_slug:
                for sc_key, slug in SHORTCODE_PLUGIN_MAP.items():
                    if sc_lower.startswith(sc_key) or sc_key.startswith(sc_lower):
                        plugin_slug = slug
                        break

            if plugin_slug and plugin_slug != "wordpress-core-gallery":
                if plugin_slug not in detected_shortcodes:
                    detected_shortcodes[plugin_slug] = set()
                detected_shortcodes[plugin_slug].add(shortcode)

                # Add to target plugins if not already known
                if plugin_slug not in existing_plugin_slugs:
                    new_plugin = WPPlugin(slug=plugin_slug, discovery_method="shortcode_analysis")
                    new_plugins.append(new_plugin)
                    existing_plugin_slugs.add(plugin_slug)

        # Update context
        if new_plugins:
            ctx.target.plugins.extend(new_plugins)

        result.add_data("shortcodes_found", all_shortcodes)
        result.add_data("plugin_shortcode_map", {
            slug: list(scs) for slug, scs in detected_shortcodes.items()
        })
        result.add_data("new_plugins_from_shortcodes", [p.slug for p in new_plugins])
        result.add_data("content_pieces_analyzed", len(content_pieces))

        if detected_shortcodes:
            plugin_list = ", ".join(
                f"{slug} (via [{', '.join(sorted(scs)[:3])}])"
                for slug, scs in detected_shortcodes.items()
            )
            result.add_finding(Finding(
                id="ENUM-SC-001",
                title=f"{len(detected_shortcodes)} plugin(s) detecte(s) via shortcodes",
                severity=Severity.INFO,
                confidence=Confidence.LIKELY,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"Analyse des shortcodes dans le contenu des pages/articles. "
                    f"Plugins identifies: {plugin_list}."
                ),
                evidence=Evidence(
                    request=f"REST API content analysis on {base}",
                    response_body_excerpt=f"Shortcodes trouves: {', '.join(all_shortcodes[:20])}",
                ),
                impact="Identification de plugins supplementaires pour l'enumeration de vulnerabilites.",
                remediation="Aucune action requise — information de reconnaissance.",
                compliance=Compliance(owasp_2021="A06:2021", cwe="CWE-200"),
                phase="enum",
                module=self.name,
            ))

        return result
