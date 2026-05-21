"""File upload vulnerability scanner for WordPress."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class FileUploadModule(BazookaModule):
    name = "vuln.file_upload"
    phase = "vuln"
    description = "File upload vulnerability scanner"
    profiles = ["aggressive"]
    intrusive = True

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url

        # Test 1: wp-file-manager connector (CVE-2020-25213)
        await self._test_wp_file_manager(ctx, session, result, base)

        # Test 2: SVG upload risk assessment
        await self._test_svg_upload(ctx, session, result, base)

        # Test 3: Duplicator installer exposure
        await self._test_duplicator(ctx, session, result, base)

        return result

    async def _test_wp_file_manager(
        self, ctx: ScanContext, session: BazookaSession, result: ModuleResult, base: str
    ) -> None:
        """Check for CVE-2020-25213 — wp-file-manager connector accessible."""
        connector_paths = [
            "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php",
            "/wp-content/plugins/file-manager/lib/php/connector.minimal.php",
        ]

        for path in connector_paths:
            url = f"{base}{path}"
            try:
                resp = await session.get(url, use_cache=False)
                if resp.status_code == 200:
                    body = resp.text.lower()
                    # The connector typically returns JSON with file manager data or an error
                    # but a 200 means the endpoint is accessible (should be blocked)
                    if "errconnect" not in body and len(resp.content) > 0:
                        result.add_finding(Finding(
                            id="VULN-UPLOAD-001",
                            title=f"CVE-2020-25213: wp-file-manager connector accessible",
                            severity=Severity.CRITICAL,
                            cvss_score=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            confidence=Confidence.CONFIRMED,
                            finding_type=FindingType.CVE,
                            description=(
                                f"Le connecteur elFinder du plugin wp-file-manager est accessible a {path}. "
                                f"CVE-2020-25213 permet l'execution de code arbitraire via upload de fichier PHP "
                                f"sans authentification. Cette vulnerabilite est activement exploitee."
                            ),
                            evidence=Evidence(
                                request=f"GET {url}",
                                response_status=resp.status_code,
                                response_body_excerpt=resp.text[:300],
                            ),
                            impact=(
                                "Execution de code arbitraire sur le serveur. "
                                "Un attaquant peut uploader un webshell PHP et prendre le controle complet "
                                "du serveur web. Compromission totale du site et potentiellement du serveur."
                            ),
                            remediation=(
                                "Mettre a jour wp-file-manager vers la derniere version (>= 6.9). "
                                "Ou supprimer le plugin immediatement. "
                                "Verifier les fichiers recemment uploades dans /wp-content/plugins/wp-file-manager/lib/files/ "
                                "pour detecter des webshells existants."
                            ),
                            compliance=Compliance(
                                owasp_2021="A06:2021 - Vulnerable and Outdated Components",
                                cwe="CWE-434",
                                mitre_attack="T1190 - Exploit Public-Facing Application",
                            ),
                            references=[
                                "https://nvd.nist.gov/vuln/detail/CVE-2020-25213",
                                "https://www.wordfence.com/blog/2020/09/700000-wordpress-users-affected-by-zero-day-vulnerability-in-file-manager-plugin/",
                                "https://github.com/w4fz5uck5/wp-file-manager-0day",
                            ],
                            phase="vuln",
                            module=self.name,
                            tags=["cve", "rce", "file-upload", "wp-file-manager", "critical"],
                        ))
                        return
            except Exception:
                continue

    async def _test_svg_upload(
        self, ctx: ScanContext, session: BazookaSession, result: ModuleResult, base: str
    ) -> None:
        """Check if SVG files are allowed in media library (XSS risk)."""
        # Check existing media for SVG files
        svg_found = False
        svg_urls = []

        try:
            resp = await session.get(f"{base}/wp-json/wp/v2/media?per_page=100&mime_type=image/svg+xml", use_cache=False)
            if resp.status_code == 200:
                try:
                    media = resp.json()
                    if isinstance(media, list) and len(media) > 0:
                        svg_found = True
                        svg_urls = [m.get("source_url", "") for m in media[:5] if m.get("source_url")]
                except Exception:
                    pass
        except Exception:
            pass

        # Also check general media listing for SVGs
        if not svg_found:
            try:
                resp = await session.get(f"{base}/wp-json/wp/v2/media?per_page=100", use_cache=False)
                if resp.status_code == 200:
                    try:
                        media = resp.json()
                        if isinstance(media, list):
                            for m in media:
                                mime = m.get("mime_type", "")
                                if "svg" in mime.lower():
                                    svg_found = True
                                    src = m.get("source_url", "")
                                    if src:
                                        svg_urls.append(src)
                    except Exception:
                        pass
            except Exception:
                pass

        if svg_found:
            result.add_finding(Finding(
                id="VULN-UPLOAD-002",
                title=f"Upload SVG autorise — risque de Stored XSS",
                severity=Severity.HIGH,
                cvss_score=6.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION,
                description=(
                    f"Des fichiers SVG sont presents dans la mediatheque WordPress. "
                    f"Les SVG peuvent contenir du JavaScript et permettent des attaques XSS stockees (Stored XSS). "
                    f"SVGs trouves: {', '.join(svg_urls) if svg_urls else 'oui (URLs non exposees)'}."
                ),
                evidence=Evidence(
                    request=f"GET {base}/wp-json/wp/v2/media?mime_type=image/svg+xml",
                    response_status=200,
                    response_body_excerpt=f"SVG files found: {len(svg_urls)} files",
                ),
                impact=(
                    "Stored XSS via fichiers SVG malveillants. Un fichier SVG peut contenir "
                    "du JavaScript qui s'execute dans le navigateur des visiteurs. "
                    "Permet le vol de cookies admin, la redirection malveillante et le defacement."
                ),
                remediation=(
                    "Desactiver l'upload de fichiers SVG ou utiliser un plugin de sanitisation SVG "
                    "(Safe SVG, SVG Support avec sanitisation). "
                    "Ajouter dans wp-config.php: define('ALLOW_UNFILTERED_UPLOADS', false); "
                    "Servir les SVG avec Content-Type: image/svg+xml et Content-Disposition: attachment."
                ),
                compliance=Compliance(
                    owasp_2021="A03:2021 - Injection",
                    cwe="CWE-79",
                    mitre_attack="T1189 - Drive-by Compromise",
                ),
                references=[
                    "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                    "https://brutelogic.com.br/blog/svg-xss/",
                ],
                phase="vuln",
                module=self.name,
                tags=["svg", "xss", "file-upload", "media"],
            ))

    async def _test_duplicator(
        self, ctx: ScanContext, session: BazookaSession, result: ModuleResult, base: str
    ) -> None:
        """Check if Duplicator installer.php is accessible (wp-config exposure)."""
        # Only test if Duplicator is detected
        duplicator_detected = any(
            p.slug in ("duplicator", "duplicator-pro")
            for p in ctx.target.plugins
        ) if ctx.target.plugins else False

        # Also test by default — the file might exist even if plugin is not currently active
        installer_paths = [
            "/installer.php",
            "/dup-installer/main.installer.php",
        ]
        if duplicator_detected:
            installer_paths.insert(0, "/wp-content/plugins/duplicator/installer.php")

        for path in installer_paths:
            url = f"{base}{path}"
            try:
                resp = await session.get(url, use_cache=False)
                if resp.status_code == 200:
                    body = resp.text.lower()
                    # Duplicator installer contains specific strings
                    indicators = ["duplicator", "installer", "database", "wp-config", "archive"]
                    match_count = sum(1 for indicator in indicators if indicator in body)

                    if match_count >= 2:
                        result.add_finding(Finding(
                            id="VULN-UPLOAD-003",
                            title=f"Duplicator installer.php accessible — extraction de wp-config.php possible",
                            severity=Severity.CRITICAL,
                            cvss_score=9.1,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                            confidence=Confidence.CONFIRMED,
                            finding_type=FindingType.CVE,
                            description=(
                                f"Le fichier installer de Duplicator est accessible a {path}. "
                                f"Ce fichier peut permettre l'extraction de wp-config.php contenant "
                                f"les credentials de base de donnees, et potentiellement la reinstallation "
                                f"complete du site avec un compte admin controle par l'attaquant."
                            ),
                            evidence=Evidence(
                                request=f"GET {url}",
                                response_status=resp.status_code,
                                response_body_excerpt=resp.text[:300],
                            ),
                            impact=(
                                "Exposition de wp-config.php (credentials DB, clefs de salage). "
                                "Reinstallation potentielle du site avec prise de controle complete."
                            ),
                            remediation=(
                                "Supprimer immediatement le fichier installer.php et tous les fichiers "
                                "de backup Duplicator (*.zip, *.daf) du repertoire racine. "
                                "Bloquer l'acces via .htaccess."
                            ),
                            compliance=Compliance(
                                owasp_2021="A05:2021 - Security Misconfiguration",
                                cwe="CWE-200",
                                mitre_attack="T1005 - Data from Local System",
                            ),
                            references=[
                                "https://www.wordfence.com/blog/2020/02/active-attack-on-recently-patched-duplicator-plugin-vulnerability-affects-over-1-million-sites/",
                            ],
                            phase="vuln",
                            module=self.name,
                            tags=["duplicator", "installer", "wp-config", "critical"],
                        ))
                        return
            except Exception:
                continue
