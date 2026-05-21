"""Google dorking — search for leaked sensitive files indexed by Google."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import quote

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

# Google dorks for WordPress-specific leaks
DORKS = [
    ('site:{domain} filetype:sql', "SQL dump indexe", Severity.CRITICAL),
    ('site:{domain} filetype:env', "Fichier .env indexe", Severity.CRITICAL),
    ('site:{domain} filetype:log', "Fichier log indexe", Severity.HIGH),
    ('site:{domain} filetype:bak', "Fichier backup indexe", Severity.HIGH),
    ('site:{domain} filetype:old', "Ancien fichier indexe", Severity.MEDIUM),
    ('site:{domain} filetype:conf', "Fichier de configuration indexe", Severity.HIGH),
    ('site:{domain} inurl:wp-config', "wp-config potentiellement indexe", Severity.CRITICAL),
    ('site:{domain} inurl:debug.log', "debug.log indexe par Google", Severity.HIGH),
    ('site:{domain} inurl:phpmyadmin', "phpMyAdmin indexe", Severity.CRITICAL),
    ('site:{domain} inurl:adminer', "Adminer indexe", Severity.CRITICAL),
    ('site:{domain} "Index of" "wp-content/uploads"', "Directory listing uploads indexe", Severity.HIGH),
    ('site:{domain} inurl:".git"', "Repository Git indexe", Severity.CRITICAL),
    ('site:{domain} "DB_PASSWORD"', "Credentials DB dans des pages indexees", Severity.CRITICAL),
    ('site:{domain} intitle:"index of" backup', "Repertoire backup indexe", Severity.HIGH),
    ('site:{domain} ext:xml inurl:sitemap', "Sitemaps XML", Severity.LOW),
]


class GoogleDorkingModule(BazookaModule):
    name = "recon.google_dorking"
    phase = "recon"
    description = "Google dorking for indexed sensitive files"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        domain = ctx.target.domain

        # We don't actually query Google (rate-limited, requires API key, TOS issues)
        # Instead, we generate the dork URLs and check if files are directly accessible
        # This is more reliable and doesn't violate Google TOS

        dork_urls: list[dict] = []
        direct_checks: list[tuple[str, str, Severity]] = [
            (f"{ctx.target.url}/wp-config.php.bak", "wp-config backup", Severity.CRITICAL),
            (f"{ctx.target.url}/dump.sql", "SQL dump", Severity.CRITICAL),
            (f"{ctx.target.url}/{domain}.sql", "SQL dump (domain name)", Severity.CRITICAL),
            (f"{ctx.target.url}/backup.sql", "SQL backup", Severity.CRITICAL),
            (f"{ctx.target.url}/database.sql", "Database dump", Severity.CRITICAL),
            (f"{ctx.target.url}/{domain}.zip", "Site archive", Severity.CRITICAL),
            (f"{ctx.target.url}/backup.zip", "Backup archive", Severity.HIGH),
            (f"{ctx.target.url}/site.tar.gz", "Site tarball", Severity.HIGH),
            (f"{ctx.target.url}/error_log", "Error log", Severity.MEDIUM),
            (f"{ctx.target.url}/access_log", "Access log", Severity.MEDIUM),
            (f"{ctx.target.url}/.DS_Store", "macOS DS_Store", Severity.LOW),
            (f"{ctx.target.url}/thumbs.db", "Windows thumbnails", Severity.LOW),
        ]

        finding_count = 0
        for url, desc, severity in direct_checks:
            try:
                resp = await session.get(url, use_cache=True)
                if resp.status_code == 200 and len(resp.content) > 200:
                    # Validate it's not a WordPress 404/redirect page
                    content_type = resp.headers.get("Content-Type", "")
                    body = resp.text[:500].lower()

                    is_real = False
                    if ".sql" in url and ("insert into" in body or "create table" in body):
                        is_real = True
                    elif ".zip" in url and content_type and "zip" in content_type:
                        is_real = True
                    elif ".tar" in url and content_type and ("tar" in content_type or "gzip" in content_type):
                        is_real = True
                    elif "error_log" in url and ("php" in body or "error" in body or "[" in body):
                        is_real = True
                    elif ".DS_Store" in url and len(resp.content) > 10 and resp.content[:4] == b'\x00\x00\x00\x01':
                        is_real = True

                    if is_real:
                        finding_count += 1
                        result.add_finding(Finding(
                            id=f"RECON-DORK-{finding_count:02d}",
                            title=f"{desc} accessible: {url.split('/')[-1]}",
                            severity=severity,
                            cvss_score=9.8 if severity == Severity.CRITICAL else 7.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            confidence=Confidence.CONFIRMED,
                            finding_type=FindingType.INFORMATION_DISCLOSURE,
                            description=f"{desc} trouve a {url} ({len(resp.content)} bytes, Content-Type: {content_type}).",
                            evidence=Evidence(request=f"GET {url}", response_status=200),
                            impact="Fuite de donnees potentiellement critique (credentials, base de donnees, code source).",
                            remediation="Supprimer le fichier immediatement. Bloquer l'acces via .htaccess. Verifier Google Cache.",
                            compliance=Compliance(owasp_2021="A05:2021", cwe="CWE-538"),
                            phase="recon", module=self.name,
                        ))
            except Exception:
                continue

        # Also provide Google dork URLs for manual investigation
        dork_list = [dork.format(domain=domain) for dork, _, _ in DORKS]
        result.add_data("google_dorks", dork_list)

        if not finding_count:
            result.add_finding(Finding(
                id="RECON-DORK-000",
                title=f"Aucun fichier sensible directement accessible ({len(direct_checks)} tests)",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=f"{len(direct_checks)} fichiers sensibles testes (SQL dumps, archives, logs). Aucun accessible.",
                phase="recon", module=self.name,
            ))

        return result
