"""WordPress core version identification by MD5 fingerprint of static assets.

Downloads a small set of always-present, publicly-served files (JS/CSS),
computes their MD5 and looks them up in data/wp_fingerprints.json. A hash
that is unique to a single WordPress release identifies that release with
100% confidence — much stronger than the regex/meta-based detection in
modules/enum/wp_version.py.

Author: Ayi NEDJIMI <ayinedjimi@users.noreply.github.com>
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING

from core.models import Confidence, Evidence, Finding, FindingType, Severity
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


_DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "wp_fingerprints.json"
_DB_CACHE: dict | None = None


def _load_db() -> dict:
    global _DB_CACHE
    if _DB_CACHE is not None:
        return _DB_CACHE
    if not _DB_PATH.exists():
        _DB_CACHE = {"files": {}, "_meta": {}}
        return _DB_CACHE
    try:
        _DB_CACHE = json.loads(_DB_PATH.read_text(encoding="utf-8"))
    except Exception:
        _DB_CACHE = {"files": {}, "_meta": {}}
    return _DB_CACHE


class WPVersionFingerprintModule(BazookaModule):
    name = "enum.wp_version_fingerprint"
    phase = "enum"
    description = "WordPress core version identification via MD5 fingerprint of static assets"
    profiles = ["quick", "standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()

        # Skip if a previous run already fingerprinted this target.
        if getattr(ctx.target, "wp_version_fingerprinted", None):
            result.status = "skipped"
            return result

        db = _load_db()
        files = db.get("files", {}) or {}
        if not files:
            result.status = "skipped"
            result.add_data("reason", "fingerprint DB unavailable")
            return result

        base = ctx.target.url.rstrip("/")
        matches: dict[str, str] = {}  # file_path -> version
        any_file_accessible = False

        for fp_path in files.keys():
            url = f"{base}/{fp_path}"
            try:
                resp = await session.get(url, use_cache=True)
            except Exception:
                continue
            if resp.status_code != 200 or not resp.content:
                continue
            any_file_accessible = True
            md5 = hashlib.md5(resp.content).hexdigest()
            ver = files[fp_path].get(md5)
            if ver:
                matches[fp_path] = ver

        if not any_file_accessible:
            result.status = "skipped"
            result.add_data("reason", "no fingerprintable asset accessible")
            return result

        if matches:
            # Pick the version cited by the most files; in case of consistency,
            # there will only be one. List discrepancies in the description.
            from collections import Counter
            counter = Counter(matches.values())
            best_ver, _ = counter.most_common(1)[0]
            consistent_files = [f for f, v in matches.items() if v == best_ver]
            other_files = {f: v for f, v in matches.items() if v != best_ver}

            ctx.target.wp_version_fingerprinted = best_ver
            result.add_data("wp_version_fingerprinted", best_ver)
            result.add_data("matched_files", consistent_files)
            if other_files:
                result.add_data("conflicting_matches", other_files)

            primary = consistent_files[0]
            desc = (
                f"MD5 fingerprint match identifies WordPress {best_ver} with "
                f"100% confidence on the following file(s): "
                f"{', '.join(consistent_files)}."
            )
            if other_files:
                desc += (
                    " Note: other files reported a different version "
                    f"({other_files}); installation may be partially patched."
                )
            result.add_finding(Finding(
                id="ENUM-VERFP-001",
                title=f"WordPress core version fingerprinted: {best_ver} "
                      f"(MD5 match on {primary})",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=desc,
                evidence=Evidence(
                    request=f"GET {base}/{primary}",
                    response_body_excerpt=f"md5={[md5 for md5, v in files[primary].items() if v == best_ver][0]} -> {best_ver}",
                ),
                impact="Exact WP version exposure allows precise CVE targeting.",
                remediation="Restrict access to static asset paths, or use a reverse proxy that strips/normalizes them.",
                phase="enum",
                module=self.name,
            ))
        else:
            result.add_finding(Finding(
                id="ENUM-VERFP-002",
                title="WordPress core version unrecognized (no MD5 match — likely modified files or post-6.8 release)",
                severity=Severity.INFO,
                confidence=Confidence.TENTATIVE,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    "Fingerprintable static assets were reachable but none of their "
                    "MD5 hashes matched the local WordPress fingerprint database. "
                    "The target is likely running a release newer than the DB, or "
                    "the files have been modified (CDN minification, security plugin)."
                ),
                evidence=Evidence(request=f"GET {base}/<fingerprint files>"),
                impact="Version cannot be confirmed by hash; rely on weaker detection methods.",
                remediation="N/A (informational).",
                phase="enum",
                module=self.name,
            ))

        return result
