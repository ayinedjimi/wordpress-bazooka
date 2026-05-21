"""Wayback Machine — search for sensitive files in web archives."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

SENSITIVE_EXTENSIONS = ["env", "sql", "bak", "old", "log", "conf", "config", "yml", "yaml", "json", "xml", "php~"]
SENSITIVE_PATHS = [".git/", "wp-config", ".env", "debug.log", "phpinfo", "adminer", "phpmyadmin"]


class WaybackMachineModule(BazookaModule):
    name = "recon.wayback_machine"
    phase = "recon"
    description = "Wayback Machine search for archived sensitive files"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        domain = ctx.target.domain

        # Query Wayback Machine CDX API
        cdx_url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original,statuscode,mimetype,timestamp&limit=500&collapse=urlkey"

        try:
            resp = await session.get(cdx_url, use_cache=True, cache_ttl=3600)
            if resp.status_code != 200:
                return result

            data = resp.json()
            if not data or len(data) < 2:
                return result

            # First row is headers, rest is data
            headers = data[0]
            rows = data[1:]

        except Exception:
            result.add_finding(Finding(
                id="RECON-WBM-ERR",
                title="Wayback Machine: requete echouee",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=f"Impossible d'interroger le Wayback Machine pour {domain}.",
                phase="recon", module=self.name,
            ))
            return result

        # Analyze archived URLs for sensitive files
        sensitive_urls: list[dict] = []
        all_urls = set()

        for row in rows:
            if len(row) < 4:
                continue
            url = row[0]
            status = row[1]
            mimetype = row[2]
            timestamp = row[3]
            all_urls.add(url)

            url_lower = url.lower()

            # Check for sensitive extensions
            is_sensitive = False
            reason = ""
            for ext in SENSITIVE_EXTENSIONS:
                if url_lower.endswith(f".{ext}"):
                    is_sensitive = True
                    reason = f"Extension sensible: .{ext}"
                    break

            # Check for sensitive paths
            if not is_sensitive:
                for path in SENSITIVE_PATHS:
                    if path in url_lower:
                        is_sensitive = True
                        reason = f"Chemin sensible: {path}"
                        break

            if is_sensitive and status == "200":
                sensitive_urls.append({
                    "url": url,
                    "timestamp": timestamp,
                    "mimetype": mimetype,
                    "reason": reason,
                    "archive_url": f"https://web.archive.org/web/{timestamp}/{url}",
                })

        result.add_data("wayback_total_urls", len(all_urls))
        result.add_data("wayback_sensitive_urls", sensitive_urls)

        if sensitive_urls:
            # Group by reason
            top_items = sensitive_urls[:10]
            desc_lines = "\n".join(
                f"  - {s['url']} ({s['reason']}, {s['timestamp'][:4]})"
                for s in top_items
            )
            result.add_finding(Finding(
                id="RECON-WBM-001",
                title=f"Wayback Machine: {len(sensitive_urls)} URL(s) sensible(s) archivee(s)",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                confidence=Confidence.LIKELY,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"Le Wayback Machine a archive {len(sensitive_urls)} URL(s) sensible(s) pour {domain} "
                    f"(sur {len(all_urls)} URLs totales):\n{desc_lines}"
                ),
                evidence=Evidence(
                    request=f"GET {cdx_url}",
                    response_status=200,
                    response_body_excerpt=f"{len(all_urls)} URLs indexed, {len(sensitive_urls)} sensitive",
                ),
                impact="Des fichiers sensibles (anciens) peuvent toujours etre accessibles via les archives web.",
                remediation="Demander la suppression des snapshots sensibles via le formulaire Wayback Machine. Verifier que les fichiers ne sont plus accessibles.",
                compliance=Compliance(owasp_2021="A05:2021", cwe="CWE-538"),
                phase="recon", module=self.name,
            ))
        else:
            result.add_finding(Finding(
                id="RECON-WBM-000",
                title=f"Wayback Machine: {len(all_urls)} URLs archivees, 0 sensible",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=f"{len(all_urls)} URLs archivees pour {domain}, aucune ne correspond a des fichiers sensibles.",
                phase="recon", module=self.name,
            ))

        return result
