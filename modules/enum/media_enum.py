"""Media file enumeration via WordPress REST API."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

# Filenames that suggest sensitive content
SENSITIVE_PATTERNS = [
    r"(?i)password",
    r"(?i)confidentiel",
    r"(?i)confidential",
    r"(?i)secret",
    r"(?i)private",
    r"(?i)internal",
    r"(?i)backup",
    r"(?i)credentials",
    r"(?i)invoice",
    r"(?i)facture",
    r"(?i)salary",
    r"(?i)salaire",
    r"(?i)contract",
    r"(?i)contrat",
    r"(?i)bank",
    r"(?i)banque",
    r"(?i)passport",
    r"(?i)identity",
    r"(?i)ssn",
    r"(?i)social.?security",
    r"(?i)medical",
    r"(?i)health",
    r"(?i)financial",
    r"(?i)budget",
    r"(?i)strategic",
    r"(?i)roadmap",
]


class MediaEnumModule(BazookaModule):
    name = "enum.media_enum"
    phase = "enum"
    description = "Media file enumeration via REST API"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        api_url = f"{base}/wp-json/wp/v2/media"

        all_media: list[dict] = []
        page = 1
        max_pages = 10  # Safety limit
        total_media = 0

        while page <= max_pages:
            resp = await session.get(f"{api_url}?per_page=100&page={page}")
            if resp.status_code != 200:
                break

            try:
                media_page = resp.json()
            except Exception:
                break

            if not isinstance(media_page, list) or len(media_page) == 0:
                break

            all_media.extend(media_page)

            # Get total from headers
            total_header = resp.headers.get("X-WP-Total")
            if total_header:
                total_media = int(total_header)

            total_pages_header = resp.headers.get("X-WP-TotalPages")
            if total_pages_header and page >= int(total_pages_header):
                break

            page += 1

        if not total_media:
            total_media = len(all_media)

        # Categorise media
        pdfs: list[dict] = []
        sensitive_files: list[dict] = []
        media_summary: list[dict] = []

        for item in all_media:
            mime = item.get("mime_type", "")
            source_url = item.get("source_url", "")
            title = item.get("title", {})
            rendered_title = title.get("rendered", "") if isinstance(title, dict) else str(title)
            slug = item.get("slug", "")

            entry = {
                "id": item.get("id"),
                "title": rendered_title,
                "mime_type": mime,
                "source_url": source_url,
                "date": item.get("date", ""),
            }
            media_summary.append(entry)

            if mime == "application/pdf":
                pdfs.append(entry)

            # Check for sensitive filenames
            check_text = f"{rendered_title} {slug} {source_url}"
            for pattern in SENSITIVE_PATTERNS:
                if re.search(pattern, check_text):
                    sensitive_files.append(entry)
                    break

        result.add_data("media_total", total_media)
        result.add_data("media_fetched", len(all_media))
        result.add_data("media_list", media_summary)
        result.add_data("pdfs", pdfs)
        result.add_data("sensitive_files", sensitive_files)

        # Findings
        if pdfs:
            pdf_urls = [p["source_url"] for p in pdfs[:10]]
            result.add_finding(Finding(
                id="ENUM-MEDIA-001",
                title=f"{len(pdfs)} PDF(s) accessibles via REST API media",
                severity=Severity.HIGH,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"{len(pdfs)} fichier(s) PDF exposes via l'API REST media. "
                    f"URLs: {', '.join(pdf_urls)}."
                ),
                evidence=Evidence(
                    request=f"GET {api_url}?per_page=100",
                    response_status=200,
                    response_body_excerpt=f"Total media: {total_media}, PDFs: {len(pdfs)}",
                ),
                impact="Documents potentiellement confidentiels accessibles publiquement.",
                remediation="Restreindre l'acces aux medias via l'API REST. Verifier les fichiers exposes.",
                compliance=Compliance(owasp_2021="A01:2021", cwe="CWE-200"),
                phase="enum",
                module=self.name,
            ))

        if sensitive_files:
            sensitive_urls = [s["source_url"] for s in sensitive_files[:10]]
            result.add_finding(Finding(
                id="ENUM-MEDIA-002",
                title=f"{len(sensitive_files)} fichier(s) potentiellement sensible(s) detecte(s)",
                severity=Severity.HIGH,
                cvss_score=6.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                confidence=Confidence.LIKELY,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"Fichiers avec des noms suggerant un contenu sensible: "
                    f"{', '.join(sensitive_urls)}."
                ),
                evidence=Evidence(
                    request=f"GET {api_url}?per_page=100",
                    response_status=200,
                ),
                impact="Fuite potentielle de documents internes, financiers ou personnels.",
                remediation="Verifier et retirer les fichiers sensibles. Restreindre l'API media.",
                compliance=Compliance(owasp_2021="A01:2021", cwe="CWE-200"),
                phase="enum",
                module=self.name,
            ))

        if all_media and not pdfs and not sensitive_files:
            result.add_finding(Finding(
                id="ENUM-MEDIA-003",
                title=f"{total_media} fichier(s) media accessibles via REST API",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=f"{total_media} fichiers media enumeres via l'API REST.",
                evidence=Evidence(
                    request=f"GET {api_url}?per_page=100",
                    response_status=200,
                ),
                phase="enum",
                module=self.name,
            ))

        return result
