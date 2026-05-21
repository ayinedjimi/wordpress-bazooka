"""TmmDbMigrate (ThemeMakers) exposed backup detection.

The ThemeMakers theme framework drops the entire database (and sometimes
the whole wp-content/uploads tree) into a ZIP at:

    /wp-content/uploads/tmm_db_migrate/tmm_db_migrate.zip

When publicly downloadable this is a full database compromise. We validate
the response is a real ZIP by checking the magic bytes (PK\\x03\\x04) and/or
the Content-Type. Substring matching on the decoded body is unreliable for
binary data, hence this dedicated module.

Author: Ayi NEDJIMI <ayinedjimi@users.noreply.github.com>
"""

from __future__ import annotations

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


ZIP_MAGIC = b"PK\x03\x04"
ZIP_EMPTY_MAGIC = b"PK\x05\x06"  # empty archive (still valid)

TMM_PATH = "/wp-content/uploads/tmm_db_migrate/tmm_db_migrate.zip"


class TmmDbMigrateModule(BazookaModule):
    name = "enum.tmm_db_migrate"
    phase = "enum"
    description = "TmmDbMigrate (ThemeMakers) exposed DB backup detection"
    profiles = ["quick", "standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        url = f"{base}{TMM_PATH}"

        try:
            resp = await session.get(url, use_cache=True)
        except Exception:
            return result

        if resp.status_code != 200:
            return result

        # Validate it's a real ZIP — either by magic bytes OR explicit content-type.
        raw = b""
        try:
            raw = resp.content[:8]
        except Exception:
            pass

        ctype = ""
        try:
            ctype = (resp.headers.get("content-type") or "").lower()
        except Exception:
            pass

        is_zip_magic = raw.startswith(ZIP_MAGIC) or raw.startswith(ZIP_EMPTY_MAGIC)
        is_zip_ctype = (
            "application/zip" in ctype
            or "application/octet-stream" in ctype
            or "application/x-zip" in ctype
        )

        if not (is_zip_magic or is_zip_ctype):
            return result

        size = 0
        try:
            size = len(resp.content)
        except Exception:
            pass

        result.add_finding(Finding(
            id="ENUM-TMM-001",
            title=f"TmmDbMigrate ZIP backup exposed: {TMM_PATH}",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            confidence=Confidence.CONFIRMED,
            finding_type=FindingType.INFORMATION_DISCLOSURE,
            description=(
                f"Archive ZIP de TmmDbMigrate (ThemeMakers) telechargeable "
                f"publiquement a {url} (HTTP 200, {size} bytes, "
                f"magic={'PK' if is_zip_magic else 'N/A'}, ctype='{ctype}')."
            ),
            evidence=Evidence(
                request=f"GET {url}",
                response_status=resp.status_code,
                response_body_excerpt=f"<binary ZIP, {size} bytes, magic={raw[:4]!r}>",
            ),
            impact=(
                "Compromis total de la base de donnees: l'archive contient "
                "typiquement le dump SQL complet (utilisateurs, hashes de mots "
                "de passe, contenu prive, cles API) ainsi que les fichiers du "
                "site. Un attaquant peut recuperer le tout sans authentification."
            ),
            remediation=(
                "Supprimer immediatement le repertoire tmm_db_migrate/ du "
                "webroot. Bloquer l'acces aux *.zip dans wp-content/uploads "
                "via .htaccess ou la config nginx. Rotation des credentials "
                "BDD et invalidation des sessions WordPress. Auditer les logs "
                "d'acces pour identifier d'eventuels telechargements."
            ),
            compliance=Compliance(
                owasp_2021="A05:2021 - Security Misconfiguration",
                cwe="CWE-538",
            ),
            phase="enum",
            module=self.name,
            tags=["backup", "themakers", "tmm_db_migrate", "database"],
        ))

        return result
