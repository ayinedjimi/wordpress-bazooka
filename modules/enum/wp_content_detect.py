"""Custom wp-content path detection and 404 calibration."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class WPContentDetectModule(BazookaModule):
    name = "enum.wp_content_detect"
    phase = "enum"
    description = "Detect custom wp-content path and calibrate 404 response"
    profiles = ["quick", "standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        detected_path = ctx.target.wp_content_path  # default: /wp-content/

        # Fetch homepage HTML
        resp = await session.get(base, use_cache=True)
        if resp.status_code == 200:
            body = resp.text

            # Look for custom wp-content paths in CSS/JS link references
            # Patterns: href=".../{custom}/themes/...", src=".../{custom}/plugins/..."
            custom_matches = re.findall(
                r'(?:href|src|content)=["\']'
                r'(?:https?://[^"\']*?)?'
                r'/([a-zA-Z0-9_-]+)/'
                r'(?:themes|plugins|uploads)/',
                body,
                re.IGNORECASE,
            )

            # Count occurrences of each candidate path
            candidates: dict[str, int] = {}
            for match in custom_matches:
                # Normalise to lowercase for counting
                slug = match.lower()
                # Skip obviously wrong candidates
                if slug in ("http", "https", "www", "//"):
                    continue
                candidates[slug] = candidates.get(slug, 0) + 1

            if candidates:
                # Pick the most frequent candidate
                best = max(candidates, key=lambda k: candidates[k])
                detected_path = f"/{best}/"

                # Update context if we found something different
                if detected_path != "/wp-content/":
                    ctx.target.wp_content_path = detected_path

            # Also verify with an explicit check for /wp-content/ if no custom found
            if not candidates or detected_path == "/wp-content/":
                # Confirm the default path by looking for it directly
                if "/wp-content/" in body:
                    detected_path = "/wp-content/"
                else:
                    # No standard wp-content found — try alternative approach
                    # Search for wp-includes references to confirm WP, then look
                    # for any content directory adjacent to it
                    alt_matches = re.findall(
                        r'(?:href|src)=["\']'
                        r'(?:https?://[^"\']*?)?'
                        r'/([a-zA-Z0-9_-]+)/'
                        r'(?:uploads/\d{4}/)',
                        body,
                        re.IGNORECASE,
                    )
                    if alt_matches:
                        best_alt = max(set(alt_matches), key=alt_matches.count)
                        detected_path = f"/{best_alt.lower()}/"
                        ctx.target.wp_content_path = detected_path

        result.add_data("wp_content_path", detected_path)

        # 404 calibration: request a guaranteed-nonexistent path
        calibration_url = f"{base}/bazooka-nonexistent-path-4f3a9b2c1d/"
        cal_resp = await session.get(calibration_url)
        calibration_404_size = len(cal_resp.content) if cal_resp.content else 0
        result.add_data("calibration_404_size", calibration_404_size)
        result.add_data("calibration_404_status", cal_resp.status_code)

        return result
