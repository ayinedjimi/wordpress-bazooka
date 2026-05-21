"""TimThumb detection — probes detected themes for the vulnerable thumbnail script.

TimThumb is the root cause of CVE-2011-4106 and many sibling RCE issues. When
present and reachable, it allows remote attackers to write arbitrary PHP files
into the cache directory via crafted image URLs from whitelisted domains.

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


TIMTHUMB_PATHS: list[str] = [
    "timthumb.php",
    "lib/timthumb.php",
    "inc/timthumb.php",
    "includes/timthumb.php",
    "scripts/timthumb.php",
    "tools/timthumb.php",
    "functions/timthumb.php",
]


class TimThumbDetectModule(BazookaModule):
    name = "enum.timthumb"
    phase = "enum"
    description = "TimThumb (CVE-2011-4106 family) detection in detected themes"
    profiles = ["standard", "aggressive", "bugbounty"]
    intrusive = False
    dependencies = ["enum.wp_themes"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url.rstrip("/")
        wp_content = ctx.target.wp_content_path or "/wp-content/"
        if not wp_content.endswith("/"):
            wp_content = wp_content + "/"

        themes = list(getattr(ctx.target, "themes", []) or [])
        if not themes:
            result.status = "skipped"
            return result

        sem = asyncio.Semaphore(8)
        hits: list[tuple[str, str, str]] = []  # (theme_slug, path, full_url)

        async def probe(theme_slug: str, sub_path: str) -> None:
            full_url = f"{base}{wp_content}themes/{theme_slug}/{sub_path}"
            async with sem:
                try:
                    resp = await session.get(full_url, follow_redirects=False)
                except Exception:
                    return
            if resp.status_code != 400:
                return
            body = (resp.text or "").lower()
            if "no image specified" in body:
                hits.append((theme_slug, sub_path, full_url))

        tasks = []
        for theme in themes:
            slug = getattr(theme, "slug", "") or ""
            if not slug:
                continue
            for sub_path in TIMTHUMB_PATHS:
                tasks.append(probe(slug, sub_path))

        if not tasks:
            result.status = "skipped"
            return result

        await asyncio.gather(*tasks, return_exceptions=True)

        result.add_data(
            "timthumb_hits",
            [{"theme": t, "path": p, "url": u} for (t, p, u) in hits],
        )

        for idx, (theme_slug, sub_path, full_url) in enumerate(hits, 1):
            result.add_finding(Finding(
                id=f"ENUM-TTHUMB-{idx:03d}",
                title=f"TimThumb detecte dans le theme {theme_slug} ({sub_path})",
                severity=Severity.HIGH,
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION,
                description=(
                    f"Le script TimThumb est present a {full_url}. TimThumb est "
                    "a l'origine de CVE-2011-4106 (RCE via WebShot/whitelist bypass) "
                    "et de nombreuses vulnerabilites apparentees. Toute version <= 2.8.13 "
                    "est consideree dangereuse, et meme les versions plus recentes ont un "
                    "historique de patchs incomplets."
                ),
                evidence=Evidence(
                    request=f"GET {full_url}",
                    response_status=400,
                    response_body_excerpt="no image specified",
                ),
                impact=(
                    "Execution de code distant possible via injection PHP dans le "
                    "repertoire cache, defacement, pivot vers le reste du serveur."
                ),
                remediation=(
                    "Supprimer TimThumb du theme et le remplacer par les fonctions "
                    "natives WordPress (add_image_size + wp_get_attachment_image). "
                    "Si la suppression est impossible, bloquer l'acces a timthumb.php "
                    "au niveau du serveur web (Nginx/Apache)."
                ),
                compliance=Compliance(owasp_2021="A06:2021", cwe="CWE-1104"),
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2011-4106",
                    "https://www.exploit-db.com/exploits/17602",
                ],
                phase="enum",
                module=self.name,
                tags=["timthumb", theme_slug],
            ))

        return result
