"""REST API deep enumeration — routes, posts, pages, media, comments, settings."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class RestAPIModule(BazookaModule):
    name = "enum.rest_api"
    phase = "enum"
    description = "WordPress REST API deep enumeration"
    profiles = ["standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        api_base = f"{base}/wp-json"

        # 1. Root discovery
        resp = await session.get(f"{api_base}/")
        if resp.status_code != 200:
            result.status = "partial"
            return result

        try:
            root = resp.json()
        except Exception:
            return result

        namespaces = root.get("namespaces", [])
        routes = list(root.get("routes", {}).keys())
        result.add_data("rest_api_root", {"namespaces": namespaces, "route_count": len(routes)})
        result.add_data("rest_api_namespaces", namespaces)

        result.add_finding(Finding(
            id="ENUM-API-001",
            title=f"REST API expose: {len(routes)} routes, {len(namespaces)} namespaces",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            finding_type=FindingType.INFORMATION_DISCLOSURE,
            description=f"L'API REST WordPress est accessible. {len(routes)} routes dans {len(namespaces)} namespaces: {', '.join(namespaces[:10])}.",
            evidence=Evidence(request=f"GET {api_base}/", response_status=200),
            phase="enum", module=self.name,
        ))

        # 2. Posts
        resp = await session.get(f"{api_base}/wp/v2/posts?per_page=100")
        if resp.status_code == 200:
            try:
                posts = resp.json()
                total = resp.headers.get("X-WP-Total", len(posts))
                result.add_data("posts_count", int(total))
                if int(total) > 0:
                    result.add_finding(Finding(
                        id="ENUM-API-002",
                        title=f"{total} article(s) accessibles via REST API",
                        severity=Severity.MEDIUM if int(total) > 10 else Severity.LOW,
                        cvss_score=3.1,
                        confidence=Confidence.CONFIRMED,
                        finding_type=FindingType.INFORMATION_DISCLOSURE,
                        description=f"{total} articles WordPress accessibles publiquement via /wp/v2/posts.",
                        phase="enum", module=self.name,
                    ))
            except Exception:
                pass

        # 3. Pages
        resp = await session.get(f"{api_base}/wp/v2/pages?per_page=100")
        if resp.status_code == 200:
            try:
                pages = resp.json()
                total = resp.headers.get("X-WP-Total", len(pages))
                result.add_data("pages_count", int(total))
            except Exception:
                pass

        # 4. Media — flag PDFs
        resp = await session.get(f"{api_base}/wp/v2/media?per_page=100")
        if resp.status_code == 200:
            try:
                media = resp.json()
                total = resp.headers.get("X-WP-Total", len(media))
                pdfs = [m for m in media if m.get("mime_type", "") == "application/pdf"]
                result.add_data("media_count", int(total))
                result.add_data("pdf_count", len(pdfs))
                if pdfs:
                    pdf_urls = [m.get("source_url", "") for m in pdfs[:5]]
                    result.add_finding(Finding(
                        id="ENUM-API-003",
                        title=f"{len(pdfs)} PDF(s) accessibles via REST API media",
                        severity=Severity.HIGH,
                        cvss_score=5.3,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        confidence=Confidence.CONFIRMED,
                        finding_type=FindingType.INFORMATION_DISCLOSURE,
                        description=f"{len(pdfs)} fichiers PDF exposes: {', '.join(pdf_urls)}.",
                        impact="Documents potentiellement confidentiels accessibles publiquement.",
                        remediation="Restreindre l'acces aux medias via l'API REST ou rendre les fichiers prives.",
                        compliance=Compliance(owasp_2021="A01:2021", cwe="CWE-200"),
                        phase="enum", module=self.name,
                    ))
            except Exception:
                pass

        # 5. Comments — check for email leaks
        resp = await session.get(f"{api_base}/wp/v2/comments?per_page=20")
        if resp.status_code == 200:
            try:
                comments = resp.json()
                emails_in_comments = [c.get("author_email") for c in comments if c.get("author_email")]
                if emails_in_comments:
                    result.add_finding(Finding(
                        id="ENUM-API-004",
                        title=f"Emails exposes dans les commentaires REST API",
                        severity=Severity.HIGH,
                        cvss_score=5.3,
                        confidence=Confidence.CONFIRMED,
                        finding_type=FindingType.INFORMATION_DISCLOSURE,
                        description=f"{len(emails_in_comments)} email(s) d'auteurs de commentaires exposes.",
                        compliance=Compliance(owasp_2021="A01:2021", cwe="CWE-200"),
                        phase="enum", module=self.name,
                    ))
            except Exception:
                pass

        # 6. Drafts / Private posts — should be 401
        for status_type in ["draft", "private"]:
            resp = await session.get(f"{api_base}/wp/v2/posts?status={status_type}")
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, list) and len(data) > 0:
                        result.add_finding(Finding(
                            id=f"ENUM-API-005-{status_type}",
                            title=f"Articles {status_type} accessibles SANS authentification!",
                            severity=Severity.CRITICAL,
                            cvss_score=7.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            confidence=Confidence.CONFIRMED,
                            finding_type=FindingType.MISCONFIGURATION,
                            description=f"{len(data)} article(s) {status_type} accessibles sans auth via REST API.",
                            impact="Fuite de contenu non publie, potentiellement sensible.",
                            remediation="Verifier les permissions REST API et les filtres d'authentification.",
                            compliance=Compliance(owasp_2021="A01:2021", cwe="CWE-862"),
                            phase="enum", module=self.name,
                        ))
                except Exception:
                    pass

        # 7. Settings — should be 401
        resp = await session.get(f"{api_base}/wp/v2/settings")
        if resp.status_code == 200:
            result.add_finding(Finding(
                id="ENUM-API-006",
                title="Settings WordPress accessibles sans authentification!",
                severity=Severity.CRITICAL,
                cvss_score=9.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION,
                description="Les parametres WordPress sont accessibles sans auth via /wp/v2/settings.",
                impact="Lecture et modification potentielle de la configuration du site.",
                remediation="Restreindre l'acces aux settings REST API.",
                compliance=Compliance(owasp_2021="A01:2021", cwe="CWE-862"),
                phase="enum", module=self.name,
            ))

        return result
