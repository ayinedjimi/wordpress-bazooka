"""Media attachment brute force — enumerates ?attachment_id=N.

WordPress exposes uploaded media via the canonical /?attachment_id=<int>
permalink. A 200 response indicates the attachment exists; the final URL
(after rewrite) reveals the original filename — useful to spot internal
documents, drafts, or leaked credentials in PDFs/exports.

Author: Ayi NEDJIMI <ayinedjimi@users.noreply.github.com>
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from core.models import (
    Compliance,
    Confidence,
    Evidence,
    Finding,
    FindingType,
    Severity,
)
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class MediaAttachmentBruteModule(BazookaModule):
    name = "enum.media_attachment_brute"
    phase = "enum"
    description = "Brute force media attachment IDs via ?attachment_id=N"
    profiles = ["aggressive", "bugbounty"]
    intrusive = True

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url.rstrip("/")

        scan_options = getattr(ctx, "scan_options", None) or {}
        max_id = 200
        if isinstance(scan_options, dict):
            try:
                max_id = int(scan_options.get("attachment_max", 200) or 200)
            except (TypeError, ValueError):
                max_id = 200
        max_id = max(1, min(max_id, 10000))

        sem = asyncio.Semaphore(10)
        # attachment_id -> final url (after redirects/rewrite)
        found: dict[int, str] = {}

        async def probe(attachment_id: int) -> None:
            url = f"{base}/?attachment_id={attachment_id}"
            async with sem:
                try:
                    resp = await session.get(url, follow_redirects=True)
                except Exception:
                    return
            if resp.status_code != 200:
                return
            final_url = str(getattr(resp, "url", "") or url)
            # A real attachment redirects to /?attachment_id=N's permalink
            # (e.g. /my-image/) — reject if it looks like the homepage.
            if final_url.rstrip("/") == base.rstrip("/"):
                return
            found[attachment_id] = final_url

        await asyncio.gather(
            *(probe(i) for i in range(1, max_id + 1)),
            return_exceptions=True,
        )

        # Distinct URLs only
        distinct_urls: list[str] = []
        seen: set[str] = set()
        for aid in sorted(found):
            u = found[aid]
            if u in seen:
                continue
            seen.add(u)
            distinct_urls.append(u)

        result.add_data(
            "attachments",
            [{"id": aid, "url": found[aid]} for aid in sorted(found)],
        )
        result.add_data("attachment_count", len(distinct_urls))

        # Try to push into ctx.target.media if it exists (forward-compat)
        media_list = getattr(ctx.target, "media", None)
        if isinstance(media_list, list):
            for u in distinct_urls:
                if u not in media_list:
                    media_list.append(u)

        if distinct_urls:
            preview = ", ".join(distinct_urls[:5])
            if len(distinct_urls) > 5:
                preview += f", ... (+{len(distinct_urls) - 5})"
            result.add_finding(Finding(
                id="ENUM-MEDIA-001",
                title=f"{len(distinct_urls)} attachement(s) media enumere(s) via attachment_id",
                severity=Severity.LOW,
                cvss_score=3.7,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"Brute force de ?attachment_id=1..{max_id} a revele "
                    f"{len(distinct_urls)} attachements distincts. Exemples: {preview}."
                ),
                evidence=Evidence(request=f"GET {base}/?attachment_id=N (N=1..{max_id})"),
                impact=(
                    "Enumeration de medias non lies depuis la navigation publique "
                    "(brouillons, exports, PDF internes, captures privees)."
                ),
                remediation=(
                    "Bloquer ?attachment_id=N pour les attachements orphelins ou "
                    "filtrer en amont via un plugin (Hide My WP / Restricted Site Access)."
                ),
                compliance=Compliance(owasp_2021="A01:2021", cwe="CWE-200"),
                phase="enum",
                module=self.name,
                tags=["media", "enum"],
            ))
        else:
            result.status = "partial"

        return result
