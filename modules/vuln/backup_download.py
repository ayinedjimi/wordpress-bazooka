"""Backup file download detection module.

Tests for downloadable database dumps, archive backups, and backup directories
that are commonly left exposed on WordPress installations.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

# SQL dump signatures (at least one must be present)
SQL_SIGNATURES = [
    "INSERT INTO",
    "CREATE TABLE",
    "DROP TABLE",
    "mysqldump",
    "-- Dump",
    "-- MySQL",
    "-- PostgreSQL",
    "-- Server version",
    "BEGIN TRANSACTION",
]

# Content types indicating archive files
ARCHIVE_CONTENT_TYPES = [
    "application/zip",
    "application/x-zip-compressed",
    "application/gzip",
    "application/x-gzip",
    "application/x-tar",
    "application/x-compressed-tar",
    "application/octet-stream",
]

# Minimum size for archives to be considered real (10KB)
MIN_ARCHIVE_SIZE = 10240


def _build_backup_paths(domain: str) -> list[tuple[str, str]]:
    """Build the list of backup paths to test.

    Returns list of (path, type) where type is "sql", "archive", or "directory".
    """
    paths: list[tuple[str, str]] = []

    # SQL dump files
    sql_files = [
        "/backup.sql",
        "/dump.sql",
        "/database.sql",
        "/db.sql",
        "/wp_backup.sql",
        f"/{domain}.sql",
    ]
    for p in sql_files:
        paths.append((p, "sql"))

    # Archive files
    archive_files = [
        "/backup.zip",
        "/backup.tar.gz",
        "/site-backup.zip",
        "/wp-backup.zip",
        f"/{domain}.zip",
        f"/{domain}.tar.gz",
    ]
    for p in archive_files:
        paths.append((p, "archive"))

    # Backup directories (check for directory listing)
    directories = [
        "/wp-content/backups/",
        "/wp-content/backup/",
        "/backups/",
        "/backup/",
        "/wp-content/uploads/backups/",
        "/wp-content/ai1wm-backups/",
        "/wp-content/updraft/",
        "/wp-snapshots/",
        "/wp-content/db-backup/",
    ]
    for p in directories:
        paths.append((p, "directory"))

    return paths


class BackupDownloadModule(BazookaModule):
    name = "vuln.backup_download"
    phase = "vuln"
    description = "Downloadable backup file detection"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        domain = ctx.target.domain
        finding_count = 0

        backup_paths = _build_backup_paths(domain)

        for path, file_type in backup_paths:
            url = f"{base}{path}"
            try:
                resp = await session.get(url, use_cache=True)
            except Exception:
                continue

            if resp.status_code != 200:
                continue

            confirmed = False
            detail = ""

            if file_type == "sql":
                # Validate SQL dump content
                body = ""
                try:
                    body = resp.text[:10000]
                except Exception:
                    continue

                matched_sigs = [sig for sig in SQL_SIGNATURES if sig in body]
                if matched_sigs:
                    confirmed = True
                    detail = f"Signatures SQL detectees: {', '.join(matched_sigs[:3])}"

            elif file_type == "archive":
                # Validate by Content-Type header and minimum file size
                content_type = resp.headers.get("content-type", "").lower().split(";")[0].strip()
                content_length = len(resp.content)

                # Also check Content-Length header if available (more reliable for large files)
                cl_header = resp.headers.get("content-length", "")
                if cl_header.isdigit():
                    content_length = max(content_length, int(cl_header))

                is_archive_type = any(ct in content_type for ct in ARCHIVE_CONTENT_TYPES)
                is_large_enough = content_length >= MIN_ARCHIVE_SIZE

                if is_archive_type and is_large_enough:
                    confirmed = True
                    size_mb = content_length / (1024 * 1024)
                    detail = f"Type: {content_type}, Taille: {size_mb:.2f} MB"
                elif is_large_enough and not content_type.startswith("text/"):
                    # Large non-text response — likely a real file
                    confirmed = True
                    size_mb = content_length / (1024 * 1024)
                    detail = f"Type: {content_type}, Taille: {size_mb:.2f} MB (type non-textuel)"

            elif file_type == "directory":
                # Check for directory listing
                body = ""
                try:
                    body = resp.text[:10000]
                except Exception:
                    continue

                body_lower = body.lower()
                # Directory listing signatures
                has_listing = (
                    "index of" in body_lower
                    or "<title>index of" in body_lower
                    or "parent directory" in body_lower
                )

                if has_listing:
                    # Check for actual backup files in the listing
                    backup_extensions = re.findall(
                        r'href=["\']([^"\']*\.(?:sql|zip|gz|tar|wpress|bak|sql\.gz|sql\.bz2))["\']',
                        body,
                        re.IGNORECASE,
                    )
                    if backup_extensions:
                        confirmed = True
                        files_found = backup_extensions[:5]
                        detail = f"Listing de repertoire avec fichiers backup: {', '.join(files_found)}"
                    else:
                        # Directory listing exists but no backup files found — still notable
                        confirmed = True
                        detail = "Listing de repertoire de backup actif (verifier manuellement le contenu)"

            if not confirmed:
                continue

            finding_count += 1

            body_excerpt = ""
            if file_type == "sql":
                try:
                    body_excerpt = resp.text[:200]
                except Exception:
                    pass

            result.add_finding(Finding(
                id=f"VULN-BKPDL-{finding_count:03d}",
                title=f"Backup telechargeable detecte: {path}",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"Un fichier de backup est telechargeable a {url} (HTTP {resp.status_code}). "
                    f"{detail}. "
                    "Les backups contiennent potentiellement la base de donnees complete, "
                    "les fichiers du site, et les credentials."
                ),
                evidence=Evidence(
                    request=f"GET {url}",
                    response_status=resp.status_code,
                    response_headers={
                        "Content-Type": resp.headers.get("content-type", ""),
                        "Content-Length": resp.headers.get("content-length", str(len(resp.content))),
                    },
                    response_body_excerpt=body_excerpt[:200] if body_excerpt else None,
                ),
                impact=(
                    "Compromission totale du site: la base de donnees contient les hash des mots de passe, "
                    "les donnees utilisateurs, les emails, et potentiellement les cles secretes WordPress. "
                    "Les archives contiennent le code source complet incluant wp-config.php."
                ),
                remediation=(
                    "Supprimer immediatement tous les fichiers de backup du webroot. "
                    "Stocker les backups hors du repertoire web (hors DocumentRoot). "
                    "Bloquer l'acces aux extensions .sql, .zip, .tar.gz via le serveur web. "
                    "Desactiver le directory listing."
                ),
                compliance=Compliance(
                    owasp_2021="A01:2021 - Broken Access Control",
                    cwe="CWE-530",
                    mitre_attack="T1530 - Data from Cloud Storage",
                ),
                references=[
                    "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                    "https://cwe.mitre.org/data/definitions/530.html",
                ],
                phase="vuln",
                module=self.name,
                tags=["backup", "download", "data-exposure", file_type],
            ))

        return result
