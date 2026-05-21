"""CVE matcher — local DB + Wordfence feed, only on detected plugins."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

ACTIVE_SOURCES = {"html_passive", "readme_active", "rest_namespace"}


def _version_lte(version: str, max_version: str) -> bool:
    try:
        v1 = tuple(int(x) for x in version.split("."))
        v2 = tuple(int(x) for x in max_version.split("."))
        return v1 <= v2
    except (ValueError, AttributeError):
        return False


class CVEMatcherModule(BazookaModule):
    name = "vuln.cve_matcher"
    phase = "vuln"
    description = "CVE lookup (local DB + Wordfence) on detected plugins only"
    profiles = ["quick", "standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()

        from cve_db.manager import get_db
        from cve_db.wordfence_fetcher import (
            match_plugin_cves_async,
            match_infra_cves_async,
            match_core_cves_async,
        )
        db = get_db()

        plugins_detected = ctx.get_data("plugins_detected") or []
        detected_slugs = {p["slug"].lower() for p in plugins_detected if p.get("slug")}

        total_cves = 0
        emitted_keys: set[str] = set()

        # 1. Plugins — only those in plugins_detected (fixes Elementor FP)
        for plugin in ctx.target.plugins:
            slug_l = plugin.slug.lower()
            if slug_l not in detected_slugs:
                continue

            # Confidence baseline depends on detection source strength
            src = (plugin.discovery_method or "").lower()
            slug_active = any(s in src for s in ACTIVE_SOURCES) or "wordlist" in src

            # === Local DB matches ===
            local_cves = db.lookup_plugin(plugin.slug, plugin.version)
            for cve in local_cves:
                if plugin.version and cve.get("affected_version_max"):
                    if not _version_lte(plugin.version, cve["affected_version_max"]):
                        continue
                key = f"{plugin.slug}:{cve['cve_id']}"
                if key in emitted_keys:
                    continue
                emitted_keys.add(key)

                total_cves += 1
                sev = SEVERITY_MAP.get(cve.get("severity", "MEDIUM"), Severity.MEDIUM)
                plugin.cves.append({"cve_id": cve["cve_id"], "cvss": cve["cvss_score"]})

                if plugin.version:
                    conf = Confidence.LIKELY if slug_active else Confidence.POSSIBLE
                else:
                    conf = Confidence.POSSIBLE if slug_active else Confidence.POSSIBLE

                fixed = cve.get("fixed_version", "N/A")
                result.add_finding(Finding(
                    id=f"VULN-CVE-{total_cves:03d}",
                    title=f"{cve['cve_id']} - {plugin.slug} {plugin.version or '?'} ({cve.get('vuln_type', '?')})",
                    severity=sev,
                    cvss_score=cve.get("cvss_score", 0),
                    cvss_vector=cve.get("cvss_vector", ""),
                    confidence=conf,
                    finding_type=FindingType.CVE,
                    description=f"{cve.get('description', cve['title'])} (version detectee: {plugin.version or 'inconnue'}, corrigee en {fixed}).",
                    evidence=Evidence(
                        request=f"Plugin {plugin.slug} v{plugin.version} vs CVE DB (source={src})",
                        response_body_excerpt=f"Affected: <= {cve.get('affected_version_max', '?')}, Fixed: {fixed}",
                    ),
                    impact=f"Type: {cve.get('vuln_type', 'Unknown')}.",
                    remediation=f"Mettre a jour {plugin.slug} vers {fixed} ou superieur.",
                    compliance=Compliance(
                        owasp_2021="A06:2021 - Vulnerable and Outdated Components",
                        cwe=f"CWE-{1104 if cve.get('vuln_type') != 'RCE' else 94}",
                    ),
                    references=[f"https://nvd.nist.gov/vuln/detail/{cve['cve_id']}"],
                    phase="vuln",
                    module=self.name,
                    tags=["cve", plugin.slug, "local_db"],
                ))

            # === wpvulnerability.net matches (live, per plugin) ===
            try:
                wf_cves = await match_plugin_cves_async(plugin.slug, plugin.version)
            except Exception:
                wf_cves = []
            # Prefer entries that have a real CVE-XXXX id; dedupe by title to merge duplicates
            seen_titles: set[str] = set()
            for wf in wf_cves:
                cve_id = wf.get("cve_id", "")
                is_real_cve = cve_id.startswith("CVE-")
                # Skip entries without a real CVE id — keeps the report clean (UUIDs hidden)
                if not is_real_cve:
                    continue
                # Dedupe by normalized title (different sources, same vuln)
                norm_title = (wf.get("title") or "").lower().strip()[:80]
                if norm_title in seen_titles:
                    continue
                seen_titles.add(norm_title)
                key = f"{plugin.slug}:{cve_id}"
                if key in emitted_keys:
                    continue
                emitted_keys.add(key)

                total_cves += 1
                sev = SEVERITY_MAP.get(wf.get("severity", "MEDIUM"), Severity.MEDIUM)
                plugin.cves.append({"cve_id": cve_id, "cvss": wf["cvss_score"]})

                if not slug_active:
                    conf = Confidence.POSSIBLE
                elif plugin.version:
                    conf = Confidence.LIKELY
                else:
                    conf = Confidence.POSSIBLE

                fixed = wf.get("fixed_version") or "N/A"
                result.add_finding(Finding(
                    id=f"VULN-CVE-{total_cves:03d}",
                    title=f"{cve_id} - {plugin.slug} {plugin.version or '?'} ({wf.get('vuln_type','vuln')})",
                    severity=sev,
                    cvss_score=wf.get("cvss_score", 0.0),
                    cvss_vector=wf.get("cvss_vector", ""),
                    confidence=conf,
                    finding_type=FindingType.CVE,
                    description=f"{wf.get('description', wf['title'])} (version detectee: {plugin.version or 'inconnue'}, corrigee en {fixed}).",
                    evidence=Evidence(
                        request=f"Plugin {plugin.slug} v{plugin.version} vs Wordfence feed",
                        response_body_excerpt=f"Wordfence ID: {wf.get('wf_id')}, Fixed: {fixed}",
                    ),
                    impact=wf.get("vuln_type") or "Vulnerability flagged by Wordfence Intelligence.",
                    remediation=f"Mettre a jour {plugin.slug} vers {fixed} ou superieur.",
                    compliance=Compliance(
                        owasp_2021="A06:2021 - Vulnerable and Outdated Components",
                        cwe="CWE-1104",
                    ),
                    references=(wf.get("references") or [])[:5],
                    phase="vuln",
                    module=self.name,
                    tags=["cve", plugin.slug, "wordfence"],
                ))

        # 2. Themes (unchanged, local DB only)
        for theme in ctx.target.themes:
            cves = db.lookup_theme(theme.slug, theme.version)
            for cve in cves:
                if theme.version and cve.get("affected_version_max"):
                    if not _version_lte(theme.version, cve["affected_version_max"]):
                        continue
                key = f"theme:{theme.slug}:{cve['cve_id']}"
                if key in emitted_keys:
                    continue
                emitted_keys.add(key)
                total_cves += 1
                sev = SEVERITY_MAP.get(cve.get("severity", "MEDIUM"), Severity.MEDIUM)
                theme.cves.append({"cve_id": cve["cve_id"], "cvss": cve["cvss_score"]})
                result.add_finding(Finding(
                    id=f"VULN-CVE-{total_cves:03d}",
                    title=f"{cve['cve_id']} - theme {theme.slug} {theme.version or '?'}",
                    severity=sev,
                    cvss_score=cve.get("cvss_score", 0),
                    cvss_vector=cve.get("cvss_vector", ""),
                    confidence=Confidence.LIKELY,
                    finding_type=FindingType.CVE,
                    description=cve.get("description", cve["title"]),
                    remediation=f"Mettre a jour le theme {theme.slug}.",
                    compliance=Compliance(owasp_2021="A06:2021", cwe="CWE-1104"),
                    phase="vuln", module=self.name,
                ))

        # 3. Core
        wp_version = ctx.target.wp_version
        if wp_version:
            core_cves = db.lookup_core(wp_version)
            for cve in core_cves:
                if cve.get("affected_version_max"):
                    if not _version_lte(wp_version, cve["affected_version_max"]):
                        continue
                key = f"core:{cve['cve_id']}"
                if key in emitted_keys:
                    continue
                emitted_keys.add(key)
                total_cves += 1
                sev = SEVERITY_MAP.get(cve.get("severity", "MEDIUM"), Severity.MEDIUM)
                result.add_finding(Finding(
                    id=f"VULN-CVE-{total_cves:03d}",
                    title=f"{cve['cve_id']} - WordPress {wp_version} ({cve.get('vuln_type', '?')})",
                    severity=sev,
                    cvss_score=cve.get("cvss_score", 0),
                    cvss_vector=cve.get("cvss_vector", ""),
                    confidence=Confidence.LIKELY,
                    finding_type=FindingType.CVE,
                    description=cve.get("description", cve["title"]),
                    remediation=f"Mettre a jour WordPress.",
                    compliance=Compliance(owasp_2021="A06:2021", cwe="CWE-1104"),
                    phase="vuln", module=self.name,
                ))

        # 3b. Core CVEs from wpvulnerability.net (in addition to local DB)
        if wp_version:
            try:
                core_wf_cves = await match_core_cves_async(wp_version)
            except Exception:
                core_wf_cves = []
            core_wf_cves.sort(key=lambda w: w.get("cvss_score", 0), reverse=True)
            seen_core_titles: set[str] = set()
            for wf in core_wf_cves[:15]:  # cap to top 15 core CVEs
                cid = wf.get("cve_id", "")
                if not cid.startswith("CVE-"):
                    continue
                norm = (wf.get("title") or "").lower().strip()[:80]
                if norm in seen_core_titles:
                    continue
                seen_core_titles.add(norm)
                key = f"core:{cid}"
                if key in emitted_keys:
                    continue
                emitted_keys.add(key)
                total_cves += 1
                sev = SEVERITY_MAP.get(wf.get("severity", "MEDIUM"), Severity.MEDIUM)
                result.add_finding(Finding(
                    id=f"VULN-CORE-{total_cves:03d}",
                    title=f"{cid} - WordPress core {wp_version}",
                    severity=sev,
                    cvss_score=wf.get("cvss_score", 0.0),
                    cvss_vector=wf.get("cvss_vector", ""),
                    confidence=Confidence.LIKELY,
                    finding_type=FindingType.CVE,
                    description=wf.get("description", wf.get("title", "")),
                    impact=wf.get("vuln_type") or f"WordPress core vulnerability in {wp_version}.",
                    remediation="Mettre a jour WordPress vers la derniere version.",
                    compliance=Compliance(owasp_2021="A06:2021", cwe="CWE-1104"),
                    references=(wf.get("references") or [])[:5],
                    phase="vuln", module=self.name,
                    tags=["cve", "core", "wpvulnerability"],
                ))

        # 4. Infrastructure CVEs (PHP, Apache, nginx, MySQL, MariaDB...)
        tech = ctx.get_data("technology_stack") or {}
        infra_lookups: list[tuple[str, str]] = []
        if tech.get("server_software", "").lower() == "apache" and tech.get("server_version"):
            infra_lookups.append(("apache", tech["server_version"]))
        if tech.get("server_software", "").lower() == "nginx" and tech.get("server_version"):
            infra_lookups.append(("nginx", tech["server_version"]))
        if tech.get("php_version"):
            infra_lookups.append(("php", tech["php_version"]))

        # Cap per category to avoid flooding (rank by CVSS desc, keep top 10)
        MAX_PER_KIND = 10
        for kind, ver in infra_lookups:
            try:
                infra_cves = await match_infra_cves_async(kind, ver)
            except Exception:
                infra_cves = []
            # Sort by CVSS desc, dedupe by normalized title, keep top MAX_PER_KIND
            infra_cves.sort(key=lambda w: w.get("cvss_score", 0), reverse=True)
            seen_inf_titles: set[str] = set()
            emitted_for_kind = 0
            for wf in infra_cves:
                if emitted_for_kind >= MAX_PER_KIND:
                    break
                cid = wf.get("cve_id", "")
                if not cid.startswith("CVE-"):
                    continue
                norm = (wf.get("title") or "").lower().strip()[:80]
                if norm in seen_inf_titles:
                    continue
                seen_inf_titles.add(norm)
                key = f"infra:{kind}:{cid}"
                if key in emitted_keys:
                    continue
                emitted_keys.add(key)
                emitted_for_kind += 1
                total_cves += 1
                sev = SEVERITY_MAP.get(wf.get("severity", "MEDIUM"), Severity.MEDIUM)
                result.add_finding(Finding(
                    id=f"VULN-INFRA-{total_cves:03d}",
                    title=f"{cid} - {kind} {ver}",
                    severity=sev,
                    cvss_score=wf.get("cvss_score", 0.0),
                    cvss_vector=wf.get("cvss_vector", ""),
                    confidence=Confidence.LIKELY,
                    finding_type=FindingType.CVE,
                    description=wf.get("description", wf.get("title", "")),
                    impact=wf.get("vuln_type") or f"Vulnerability in {kind} {ver}.",
                    remediation=f"Update {kind} to a patched version.",
                    compliance=Compliance(
                        owasp_2021="A06:2021 - Vulnerable and Outdated Components",
                        cwe="CWE-1104",
                    ),
                    references=(wf.get("references") or [])[:5],
                    phase="vuln", module=self.name,
                    tags=["cve", "infra", kind],
                ))

        if total_cves > 0:
            result.add_data("cve_matches_total", total_cves)
        else:
            result.add_finding(Finding(
                id="VULN-CVE-000",
                title="Aucune CVE connue trouvee pour les composants detectes",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description="Aucune correspondance CVE (DB locale + Wordfence) pour les plugins/themes/core detectes.",
                phase="vuln", module=self.name,
            ))

        db.close()
        return result
