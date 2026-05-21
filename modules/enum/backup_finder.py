"""Sensitive files and backup detection module.

Anti-false-positive strategy:
1. Calibrate both 404 AND 403 baselines with multiple random paths
2. For 200 responses: validate content matches expected file type
3. For 403 responses: group by size — if many 403s share the same size, it's a WAF generic page
4. Never flag a 403 as "exists" if WAF is detected and size matches WAF pattern
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

DB_BACKUP_PATHS_FILE = Path(__file__).parent.parent.parent / "data" / "db_backup_paths.txt"
DEV_TOOLS_FILE = Path(__file__).parent.parent.parent / "data" / "dev_admin_tools.txt"

_SEV_MAP = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


def _load_dev_tool_paths() -> list[tuple[str, str, Severity, bool, list[str]]]:
    entries: list[tuple[str, str, Severity, bool, list[str]]] = []
    if not DEV_TOOLS_FILE.exists():
        return entries
    try:
        with open(DEV_TOOLS_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("|")
                if len(parts) < 4:
                    continue
                path, desc, sev_s, sigs_s = parts[0], parts[1], parts[2], parts[3]
                sev = _SEV_MAP.get(sev_s.upper(), Severity.MEDIUM)
                sigs = [s.strip() for s in sigs_s.split(";;") if s.strip()]
                entries.append((path, desc, sev, False, sigs))
    except Exception:
        pass
    return entries
SQL_MAGIC = (b"-- MySQL", b"-- mysql", b"-- phpMyAdmin", b"-- phpmyadmin",
             b"-- Adminer", b"INSERT INTO", b"CREATE TABLE",
             b"DROP TABLE", b"-- Dump")
ZIP_MAGIC = b"PK\x03\x04"
GZIP_MAGIC = b"\x1f\x8b"

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

SENSITIVE_PATHS = [
    # (path, description, severity, is_wp_content, content_signatures)
    # content_signatures: if 200, body MUST contain one of these strings to be valid
    ("/debug.log", "WordPress debug log", Severity.HIGH, True,
     ["PHP Warning", "PHP Notice", "PHP Fatal", "Stack trace", "WordPress database error"]),
    ("/uploads/", "Directory listing uploads", Severity.HIGH, True,
     ["Index of", "<title>Index of", "Parent Directory"]),
    ("/updraft/", "UpdraftPlus backup directory", Severity.CRITICAL, True,
     ["Index of", "backup_", "updraft"]),
    ("/ai1wm-backups/", "All-in-One WP Migration backups", Severity.CRITICAL, True,
     ["Index of", ".wpress"]),
    ("/backups-dup-lite/", "Duplicator backup directory", Severity.CRITICAL, True,
     ["Index of", "dup-installer"]),
    ("/backup-db/", "WP-DB-Backup directory", Severity.CRITICAL, True,
     ["Index of"]),
    ("/mu-plugins/", "Must-Use plugins directory", Severity.MEDIUM, True,
     ["Index of", "<?php"]),
    ("/.git/HEAD", "Git repository exposed", Severity.CRITICAL, False,
     ["ref: refs/"]),
    ("/.git/config", "Git config exposed", Severity.CRITICAL, False,
     ["[core]", "[remote", "repositoryformatversion"]),
    ("/.env", "Environment file exposed", Severity.CRITICAL, False,
     ["DB_PASSWORD", "DB_HOST", "APP_KEY", "SECRET", "AWS_", "DATABASE_URL"]),
    ("/.wp-env.json", "WP-Env config (dev credentials)", Severity.CRITICAL, False,
     ['"core"', '"plugins"', '"themes"', '"wp-env"']),
    ("/.htpasswd", "Apache htpasswd file", Severity.HIGH, False,
     ["$apr1$", "$2y$", ":{SHA}", "$P$", "$H$"]),
    ("/wp-config.php.bak", "wp-config backup", Severity.CRITICAL, False,
     ["DB_NAME", "DB_USER", "DB_PASSWORD", "AUTH_KEY", "table_prefix"]),
    ("/wp-config.php.old", "wp-config backup", Severity.CRITICAL, False,
     ["DB_NAME", "DB_USER", "DB_PASSWORD"]),
    ("/wp-config.php~", "wp-config editor backup", Severity.CRITICAL, False,
     ["DB_NAME", "DB_USER", "DB_PASSWORD"]),
    ("/wp-config.php.save", "wp-config nano/vim backup", Severity.CRITICAL, False,
     ["DB_NAME", "DB_USER", "DB_PASSWORD"]),
    ("/wp-config.php.swp", "wp-config vim swap", Severity.CRITICAL, False,
     ["b0VIM"]),  # vim swap magic bytes
    ("/wp-config.php.txt", "wp-config renamed to text", Severity.CRITICAL, False,
     ["DB_NAME", "DB_USER", "DB_PASSWORD"]),
    ("/wp-config-sample.php", "WordPress config sample", Severity.LOW, False,
     ["DB_NAME", "define(", "table_prefix"]),
    ("/phpinfo.php", "PHP info page", Severity.HIGH, False,
     ["phpinfo()", "PHP Version", "Configuration File"]),
    ("/phpmyadmin/", "phpMyAdmin panel", Severity.CRITICAL, False,
     ["phpMyAdmin", "pma_", "login_form"]),
    ("/adminer.php", "Adminer database manager", Severity.CRITICAL, False,
     ["adminer", "login-driver", "Login - Adminer"]),
    ("/readme.html", "WordPress readme (version)", Severity.LOW, False,
     ["wordpress.org", "semantic personal publishing"]),
    ("/wp-admin/install.php", "WordPress installation page", Severity.CRITICAL, False,
     ["wp-signup.php", "language-chooser", "setup-config.php", "Already Installed", "createtables"]),
    ("/xmlrpc.php", "XML-RPC endpoint", Severity.MEDIUM, False,
     ["XML-RPC server accepts POST requests only"]),
]


class BackupFinderModule(BazookaModule):
    name = "enum.backup_finder"
    phase = "enum"
    description = "Sensitive files and backup detection"
    profiles = ["quick", "standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        wp_content = ctx.target.wp_content_path

        # === CALIBRATION PHASE ===
        # Send requests to establish baselines: normal 404, dotfile 403, and WAF pages
        calibration_paths = [
            f"{base}/bazooka_nonexistent_abc123/",
            f"{base}/bazooka_fakefile_xyz789.php",
            f"{base}/bazooka_nodir_def456/test.html",
            # Dotfile calibration — servers/WAFs often block ALL dotfiles with same response
            f"{base}/.bazooka_calibration_test",
            f"{base}/.bazooka_fake_dotfile",
            # wp-content calibration
            f"{base}{wp_content}bazooka_nonexistent_dir/",
        ]
        baseline_responses: list[tuple[int, int]] = []  # (status_code, content_length)
        for cal_url in calibration_paths:
            try:
                cal_resp = await session.get(cal_url, use_cache=False)
                baseline_responses.append((cal_resp.status_code, len(cal_resp.content)))
            except Exception:
                pass

        if not baseline_responses:
            return result

        # Determine baseline sizes per status code
        baseline_sizes: dict[int, list[int]] = {}
        for status, size in baseline_responses:
            baseline_sizes.setdefault(status, []).append(size)

        # Get the "normal not-found" size (could be 404 or 403 if WAF blocks everything)
        not_found_sizes: set[int] = set()
        for status, sizes in baseline_sizes.items():
            for s in sizes:
                # Add tolerance band: +/- 50 bytes (WAF pages vary slightly)
                for delta in range(-50, 51):
                    not_found_sizes.add(s + delta)

        waf_active = ctx.target.waf_detected is not None

        # === SCAN PHASE ===
        responses: list[tuple[str, str, Severity, list[str], int, int, str]] = []
        # (path, desc, severity, sigs, status, size, body)

        # Build extended DB backup paths from data file
        db_backup_entries: list[tuple[str, str, Severity, bool, list[str]]] = []
        if DB_BACKUP_PATHS_FILE.exists():
            try:
                with open(DB_BACKUP_PATHS_FILE, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        p = line.strip()
                        if not p or p.startswith("#"):
                            continue
                        if not p.startswith("/"):
                            p = "/" + p
                        db_backup_entries.append(
                            (p, "Possible DB backup/export", Severity.HIGH, False, [])
                        )
            except Exception:
                pass

        all_paths = list(SENSITIVE_PATHS) + db_backup_entries + _load_dev_tool_paths()

        for path, desc, severity, is_wp_content, sigs in all_paths:
            if is_wp_content:
                full_url = f"{base}{wp_content}{path.lstrip('/')}"
            else:
                full_url = f"{base}{path}"

            try:
                resp = await session.get(full_url, use_cache=True)
                body = ""
                raw = b""
                try:
                    raw = resp.content[:4096]
                    body = resp.text[:5000]
                except Exception:
                    pass
                # DB backup magic-byte gate: only keep if real SQL/ZIP/GZIP confirmed
                if desc == "Possible DB backup/export":
                    if resp.status_code == 200 and (
                        raw.startswith(ZIP_MAGIC) or raw.startswith(GZIP_MAGIC)
                        or any(m in raw for m in SQL_MAGIC)
                    ):
                        severity = Severity.CRITICAL
                        desc = "Database backup downloadable"
                        sigs = ["__magic_confirmed__"]  # sentinel; we'll set exists in analysis
                    else:
                        # No magic bytes → skip entirely, prevents 301→404 false positives
                        continue
                responses.append((path, desc, severity, sigs, resp.status_code, len(resp.content), body))
                # Special path: emit a CRITICAL finding right away for confirmed DB backup
                if resp.status_code == 200 and desc == "Database backup downloadable":
                    pass  # handled later in analysis with confirmed confidence
            except Exception:
                continue

        # === ANTI-FALSE-POSITIVE: group 403 responses by size ===
        forbidden_sizes = Counter()
        for path, desc, severity, sigs, status, size, body in responses:
            if status == 403:
                forbidden_sizes[size] += 1

        # If a 403 size appears 3+ times, it's a WAF/server generic block page
        waf_block_sizes: set[int] = set()
        for size, count in forbidden_sizes.items():
            if count >= 3:
                waf_block_sizes.add(size)

        # === ANALYSIS PHASE ===
        finding_count = 0
        for path, desc, severity, sigs, status, size, body in responses:
            exists = False
            confidence = Confidence.POSSIBLE

            if status == 200:
                # 200 response: MUST contain at least one expected signature
                body_lower = body.lower()
                has_signature = any(sig.lower() in body_lower for sig in sigs)

                if has_signature:
                    exists = True
                    confidence = Confidence.CONFIRMED
                elif desc == "Database backup downloadable" or (sigs and sigs[0] == "__magic_confirmed__"):
                    # Already validated via magic bytes earlier
                    exists = True
                    confidence = Confidence.CONFIRMED
                elif not sigs:
                    # No signatures defined, accept 200 with substantial content
                    if size > 500:
                        exists = True
                        confidence = Confidence.LIKELY

                # Special case: xmlrpc.php returns 405 sometimes but content says XML-RPC
                if not exists and path == "/xmlrpc.php" and ("xml-rpc" in body_lower or "xmlrpc" in body_lower):
                    exists = True
                    confidence = Confidence.CONFIRMED

            elif status == 405 and path == "/xmlrpc.php":
                # XML-RPC returns 405 for GET but exists
                exists = True
                confidence = Confidence.CONFIRMED

            elif status == 403:
                # 403: only flag if size is NOT a known WAF/generic block page
                if size in waf_block_sizes:
                    # This is a WAF generic page — skip
                    continue
                if size in not_found_sizes:
                    # Same size as 404 baseline — skip
                    continue
                if waf_active:
                    # WAF detected: be very conservative with 403s
                    # Only flag if the 403 size is truly unique (not matching any baseline)
                    is_unique = size not in not_found_sizes and size not in waf_block_sizes
                    other_403_same_size = forbidden_sizes.get(size, 0)
                    if is_unique and other_403_same_size <= 1:
                        exists = True
                        confidence = Confidence.POSSIBLE
                    # Otherwise skip — too risky
                else:
                    # No WAF: 403 with different size from baseline = likely exists
                    exists = True
                    confidence = Confidence.LIKELY

            if exists:
                finding_count += 1
                body_excerpt = ""
                if status == 200:
                    body_excerpt = body[:300]

                result.add_finding(Finding(
                    id=f"ENUM-BKP-{finding_count:03d}",
                    title=f"{desc} detecte: {path}",
                    severity=severity,
                    cvss_score=9.8 if severity == Severity.CRITICAL else 7.5 if severity == Severity.HIGH else 5.3 if severity == Severity.MEDIUM else 2.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    confidence=confidence,
                    finding_type=FindingType.INFORMATION_DISCLOSURE,
                    description=f"{desc} accessible a {base}{path} (HTTP {status}, {size} bytes).",
                    evidence=Evidence(
                        request=f"GET {base}{path}",
                        response_status=status,
                        response_body_excerpt=body_excerpt[:200] if body_excerpt else None,
                    ),
                    impact="Exposition de fichiers sensibles (credentials, backups, configuration).",
                    remediation="Bloquer l'acces via .htaccess, supprimer les fichiers inutiles, desactiver le debug en production.",
                    compliance=Compliance(owasp_2021="A05:2021", cwe="CWE-538"),
                    phase="enum",
                    module=self.name,
                ))

        return result
