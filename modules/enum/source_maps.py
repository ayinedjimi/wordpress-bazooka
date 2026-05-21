"""JavaScript source map detection — find exposed .map files and sourceMappingURL."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class SourceMapsModule(BazookaModule):
    name = "enum.source_maps"
    phase = "enum"
    description = "JavaScript source map detection"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        source_maps_found: list[dict] = []

        # Fetch homepage to extract JS URLs
        resp = await session.get(base, use_cache=True)
        if resp.status_code != 200:
            return result

        body = resp.text

        # Extract all .js file URLs from the HTML
        js_urls: list[str] = []

        # Match src="...*.js" in script tags
        script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', body, re.IGNORECASE)
        for src in script_srcs:
            full_url = urljoin(base, src)
            # Only check same-domain JS files
            if ctx.target.domain in full_url or full_url.startswith(base):
                js_urls.append(full_url)

        # Also check for inline sourceMappingURL references in the HTML (rare but possible)
        inline_maps = re.findall(r'//[#@]\s*sourceMappingURL=(\S+)', body)
        for map_ref in inline_maps:
            map_url = urljoin(base, map_ref)
            source_maps_found.append({
                "js_url": base,
                "map_url": map_url,
                "detection": "inline_html_comment",
            })

        # Deduplicate JS URLs
        js_urls = list(set(js_urls))

        # Check each JS file for source maps
        for js_url in js_urls[:50]:  # Safety limit
            # Strip query string for the .map check
            clean_js_url = js_url.split("?")[0]

            # Method 1: Check if {url}.map exists
            map_url = f"{clean_js_url}.map"
            map_resp = await session.get(map_url)
            if map_resp.status_code == 200:
                # Validate it's a real source map (JSON with "sources" key)
                try:
                    map_data = map_resp.json()
                    if isinstance(map_data, dict) and "sources" in map_data:
                        sources = map_data.get("sources", [])
                        source_maps_found.append({
                            "js_url": js_url,
                            "map_url": map_url,
                            "detection": "external_map_file",
                            "sources_count": len(sources),
                            "sources_sample": sources[:10],
                        })
                        continue  # Skip Method 2 if found
                except Exception:
                    pass

            # Method 2: Fetch JS content and check for sourceMappingURL comment
            js_resp = await session.get(js_url, use_cache=True)
            if js_resp.status_code == 200:
                js_content = js_resp.text
                # Check last 500 chars for the sourceMappingURL comment (usually at the end)
                tail = js_content[-500:] if len(js_content) > 500 else js_content
                mapping_match = re.search(r'//[#@]\s*sourceMappingURL=(\S+)', tail)
                if mapping_match:
                    ref = mapping_match.group(1)
                    ref_url = urljoin(js_url, ref)

                    # Try to fetch the referenced map
                    ref_resp = await session.get(ref_url)
                    if ref_resp.status_code == 200:
                        try:
                            ref_data = ref_resp.json()
                            if isinstance(ref_data, dict) and "sources" in ref_data:
                                sources = ref_data.get("sources", [])
                                source_maps_found.append({
                                    "js_url": js_url,
                                    "map_url": ref_url,
                                    "detection": "sourceMappingURL_comment",
                                    "sources_count": len(sources),
                                    "sources_sample": sources[:10],
                                })
                        except Exception:
                            # Map URL responds but is not valid JSON
                            source_maps_found.append({
                                "js_url": js_url,
                                "map_url": ref_url,
                                "detection": "sourceMappingURL_comment_unverified",
                            })

        result.add_data("source_maps", source_maps_found)
        result.add_data("js_files_checked", len(js_urls))

        # Create a finding for each source map found
        for i, smap in enumerate(source_maps_found):
            sources_info = ""
            if "sources_count" in smap:
                sources_info = f" ({smap['sources_count']} fichiers source)"
            result.add_finding(Finding(
                id=f"ENUM-SRCMAP-{i + 1:03d}",
                title=f"Source map JavaScript expose: {smap['map_url'].split('/')[-1]}{sources_info}",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"Source map JavaScript accessible: {smap['map_url']}. "
                    f"Detection: {smap['detection']}. "
                    f"JS d'origine: {smap['js_url']}."
                ),
                evidence=Evidence(
                    request=f"GET {smap['map_url']}",
                    response_status=200,
                    response_body_excerpt=str(smap.get("sources_sample", ""))[:300],
                ),
                impact=(
                    "Les source maps exposent le code source original non-minifie, "
                    "incluant commentaires, noms de variables, et structure du projet."
                ),
                remediation=(
                    "Supprimer les fichiers .map du serveur de production. "
                    "Retirer les commentaires sourceMappingURL des fichiers JS compiles."
                ),
                compliance=Compliance(owasp_2021="A05:2021", cwe="CWE-540"),
                phase="enum",
                module=self.name,
            ))

        return result
