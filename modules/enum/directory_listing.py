"""Deep directory listing check — detect Options +Indexes misconfiguration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

# Markers that indicate directory listing is enabled
LISTING_MARKERS = [
    "Index of",
    "Parent Directory",
    "<title>Index of",
    "Directory listing for",
    "[To Parent Directory]",  # IIS
    "Directory Listing For",  # Tomcat
]


class DirectoryListingModule(BazookaModule):
    name = "enum.directory_listing"
    phase = "enum"
    description = "Deep directory listing check for exposed directories"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        wp_content = ctx.target.wp_content_path
        listed_dirs: list[dict] = []

        # Directories to check
        directories = [
            f"{wp_content}uploads/",
            f"{wp_content}uploads/2024/",
            f"{wp_content}uploads/2025/",
            f"{wp_content}uploads/2026/",
            f"{wp_content}plugins/",
            f"{wp_content}themes/",
            f"{wp_content}upgrade/",
            f"{wp_content}cache/",
            f"{wp_content}backups/",
            f"{wp_content}wflogs/",
            "/wp-includes/",
            "/wp-includes/js/",
            "/wp-includes/css/",
            "/wp-admin/css/",
            "/wp-admin/js/",
        ]

        for dir_path in directories:
            url = f"{base}{dir_path}"
            resp = await session.get(url)

            if resp.status_code == 200:
                body = resp.text
                is_listing = any(marker in body for marker in LISTING_MARKERS)

                if is_listing:
                    # Count the number of entries visible
                    # Apache/Nginx typically use <a href=""> for each entry
                    import re
                    entries = re.findall(r'<a\s+href="([^"]+)"', body)
                    # Filter out parent directory and sort links
                    real_entries = [
                        e for e in entries
                        if e not in ("../", "?", "/") and not e.startswith("?")
                    ]

                    dir_info = {
                        "path": dir_path,
                        "url": url,
                        "entries_count": len(real_entries),
                        "entries_sample": real_entries[:20],
                    }
                    listed_dirs.append(dir_info)

                    # Determine severity based on directory type
                    if "uploads" in dir_path:
                        severity = Severity.HIGH
                        impact = (
                            "Le repertoire uploads expose tous les fichiers telecharges, "
                            "incluant potentiellement des documents sensibles, des backups, "
                            "et des fichiers prives."
                        )
                    elif "plugins" in dir_path:
                        severity = Severity.HIGH
                        impact = (
                            "Le repertoire plugins expose la liste complete des plugins "
                            "installes et leurs versions, facilitant la recherche de CVEs."
                        )
                    elif "themes" in dir_path:
                        severity = Severity.MEDIUM
                        impact = (
                            "Le repertoire themes expose les themes installes et leur structure."
                        )
                    elif "backups" in dir_path or "cache" in dir_path:
                        severity = Severity.HIGH
                        impact = (
                            f"Le repertoire {dir_path.strip('/')} peut contenir des fichiers "
                            f"de sauvegarde ou cache avec des donnees sensibles."
                        )
                    else:
                        severity = Severity.MEDIUM
                        impact = (
                            f"Le listing du repertoire {dir_path} expose la structure interne du site."
                        )

                    result.add_finding(Finding(
                        id=f"ENUM-DIRLIST-{len(listed_dirs):03d}",
                        title=f"Directory listing actif: {dir_path} ({len(real_entries)} fichiers)",
                        severity=severity,
                        cvss_score=5.3 if severity == Severity.HIGH else 3.7,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        confidence=Confidence.CONFIRMED,
                        finding_type=FindingType.MISCONFIGURATION,
                        description=(
                            f"Le directory listing (Options +Indexes) est actif sur {url}. "
                            f"{len(real_entries)} entree(s) visible(s)."
                        ),
                        evidence=Evidence(
                            request=f"GET {url}",
                            response_status=200,
                            response_body_excerpt=body[:300],
                        ),
                        impact=impact,
                        remediation=(
                            "Desactiver le directory listing:\n"
                            "- Apache: Options -Indexes dans .htaccess\n"
                            "- Nginx: autoindex off; dans la configuration\n"
                            "- Ajouter un fichier index.php vide dans chaque repertoire."
                        ),
                        compliance=Compliance(owasp_2021="A05:2021", cwe="CWE-548"),
                        phase="enum",
                        module=self.name,
                    ))

        result.add_data("directories_checked", len(directories))
        result.add_data("directories_listed", listed_dirs)
        result.add_data("listing_count", len(listed_dirs))

        return result
