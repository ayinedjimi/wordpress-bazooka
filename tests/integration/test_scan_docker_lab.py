"""Integration tests — Real scans against the Docker WordPress lab (localhost:8888).

These tests verify that BAZOOKA correctly detects ALL the vulnerabilities
that were intentionally planted in the Docker lab.

Prerequisites: Docker lab must be running on http://localhost:8888
Launch with: wsl -e bash -c "cd /mnt/c/WORDPRESSBAZOOKA/testlab && docker compose up -d"
Then run: wsl -e bash -c "cd /mnt/c/WORDPRESSBAZOOKA/testlab && bash setup-after.sh"
"""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.engine import ScanEngine, ScanContext
from core.models import Severity

LAB_URL = "http://localhost:8888"


_LAB_AVAILABLE_CACHE: list = []  # one-element memo to defer the network check


def _check_lab_available() -> bool:
    """Skip tests if Docker lab is not running. Cached after first call so we
    don't probe the network on every test, but still NOT called at import time
    (which would stall every pytest invocation by 1s+ even on unit-only runs)."""
    if _LAB_AVAILABLE_CACHE:
        return _LAB_AVAILABLE_CACHE[0]
    import httpx
    try:
        r = httpx.get(LAB_URL, timeout=1, follow_redirects=True)
        ok = r.status_code == 200
    except Exception:
        ok = False
    _LAB_AVAILABLE_CACHE.append(ok)
    return ok


# Lazy skip marker: the condition is re-evaluated on each test collection but
# only HITS the network the first time, then uses the memo.
skip_no_lab = pytest.mark.skipif(
    "not __import__('tests.integration.test_scan_docker_lab', fromlist=['_check_lab_available'])._check_lab_available()",
    reason="Docker lab not running on localhost:8888",
)


def _run_scan(profile="standard", pentest=False) -> ScanContext:
    """Run a real scan and return context."""
    engine = ScanEngine(
        url=LAB_URL,
        profile=profile,
        pentest=pentest,
        rate_limit=50,
        threads=10,
    )
    return asyncio.run(engine.run())


# Cache the scan result so we don't rescan for every test
_cached_ctx = None

def _get_ctx() -> ScanContext:
    global _cached_ctx
    if _cached_ctx is None:
        _cached_ctx = _run_scan("standard")
    return _cached_ctx


def _has_finding(ctx: ScanContext, substring: str) -> bool:
    return any(substring.lower() in f.title.lower() for f in ctx.findings)


def _has_finding_id(ctx: ScanContext, finding_id: str) -> bool:
    return any(f.id == finding_id for f in ctx.findings)


def _has_severity(ctx: ScanContext, substring: str, severity: Severity) -> bool:
    return any(substring.lower() in f.title.lower() and f.severity == severity for f in ctx.findings)


# =====================================================================
# RECON TESTS
# =====================================================================

@skip_no_lab
class TestReconFindings:
    def test_no_waf_detected(self):
        ctx = _get_ctx()
        assert _has_finding(ctx, "aucun waf") or _has_finding(ctx, "no waf")

    def test_hsts_absent(self):
        ctx = _get_ctx()
        assert _has_finding(ctx, "strict-transport-security absent")

    def test_csp_absent(self):
        ctx = _get_ctx()
        assert _has_finding(ctx, "content-security-policy absent")

    def test_xframe_absent(self):
        ctx = _get_ctx()
        assert _has_finding(ctx, "x-frame-options absent")

    def test_no_https(self):
        ctx = _get_ctx()
        assert _has_finding(ctx, "https") or _has_finding(ctx, "http")

    def test_server_detected(self):
        ctx = _get_ctx()
        assert _has_finding(ctx, "apache") or _has_finding(ctx, "stack technologique")


# =====================================================================
# ENUM — WORDPRESS DETECTION
# =====================================================================

@skip_no_lab
class TestEnumWordPress:
    def test_wp_version_detected(self):
        ctx = _get_ctx()
        assert ctx.target.wp_version is not None
        assert "6.4" in ctx.target.wp_version

    def test_theme_detected(self):
        ctx = _get_ctx()
        assert _has_finding(ctx, "theme")
        assert len(ctx.target.themes) >= 1

    def test_plugins_detected(self):
        ctx = _get_ctx()
        assert _has_finding(ctx, "plugin")
        assert len(ctx.target.plugins) >= 1

    def test_contact_form_7_detected(self):
        ctx = _get_ctx()
        cf7 = [p for p in ctx.target.plugins if "contact-form" in p.slug]
        assert len(cf7) >= 1, "Contact Form 7 should be detected"


# =====================================================================
# ENUM — SENSITIVE FILES (planted vulnerabilities)
# =====================================================================

@skip_no_lab
class TestEnumSensitiveFiles:
    def test_git_head_detected(self):
        """We planted .git/HEAD in the lab."""
        ctx = _get_ctx()
        assert _has_finding(ctx, ".git/head") or _has_finding(ctx, "git repository")

    def test_git_config_detected(self):
        """We planted .git/config in the lab."""
        ctx = _get_ctx()
        assert _has_finding(ctx, ".git/config") or _has_finding(ctx, "git config")

    def test_env_file_detected(self):
        """We planted .env with credentials in the lab."""
        ctx = _get_ctx()
        assert _has_finding(ctx, ".env") or _has_finding(ctx, "environment")

    def test_debug_log_detected(self):
        """We planted debug.log with secrets in the lab."""
        ctx = _get_ctx()
        assert _has_finding(ctx, "debug.log")

    def test_debug_log_smtp_secret(self):
        """debug.log contains SMTP password — should be flagged."""
        ctx = _get_ctx()
        assert _has_finding(ctx, "smtp") or _has_finding(ctx, "secret")

    def test_directory_listing_uploads(self):
        """uploads/ has Options +Indexes enabled."""
        ctx = _get_ctx()
        assert _has_finding(ctx, "directory listing") or _has_finding(ctx, "uploads")

    def test_readme_html_detected(self):
        ctx = _get_ctx()
        assert _has_finding(ctx, "readme.html") or _has_finding(ctx, "readme")


# =====================================================================
# ENUM — XML-RPC
# =====================================================================

@skip_no_lab
class TestEnumXMLRPC:
    def test_xmlrpc_active(self):
        ctx = _get_ctx()
        assert _has_finding(ctx, "xml-rpc actif") or _has_finding(ctx, "xmlrpc")

    def test_multicall_active(self):
        ctx = _get_ctx()
        assert _has_finding(ctx, "multicall")

    def test_pingback_active(self):
        ctx = _get_ctx()
        assert _has_finding(ctx, "pingback")


# =====================================================================
# ENUM — REGISTRATION & CRON
# =====================================================================

@skip_no_lab
class TestEnumMisc:
    def test_registration_open(self):
        """We enabled user registration in the lab."""
        ctx = _get_ctx()
        assert _has_finding(ctx, "inscription") or _has_finding(ctx, "registration")

    def test_wp_cron_accessible(self):
        ctx = _get_ctx()
        assert _has_finding(ctx, "cron") or _has_finding(ctx, "wp-cron")


# =====================================================================
# VULN — CORS
# =====================================================================

@skip_no_lab
class TestVulnCORS:
    def test_cors_wildcard_detected(self):
        """We configured CORS wildcard with credentials in .htaccess."""
        ctx = _get_ctx()
        assert _has_finding(ctx, "cors wildcard") or _has_finding(ctx, "cors")

    def test_cors_is_critical(self):
        ctx = _get_ctx()
        assert _has_severity(ctx, "cors", Severity.CRITICAL)


# =====================================================================
# VULN — CVE MATCHING
# =====================================================================

@skip_no_lab
class TestVulnCVE:
    def test_cf7_cve_matched(self):
        """Contact Form 7 5.8.1 should match known CVEs."""
        ctx = _get_ctx()
        cve_findings = [f for f in ctx.findings if "CVE-" in f.title and "contact-form" in f.title]
        assert len(cve_findings) >= 1, "CF7 5.8.1 should match at least 1 CVE"

    def test_wordpress_core_cve_matched(self):
        """WordPress 6.4.3 should match known core CVEs."""
        ctx = _get_ctx()
        core_cves = [f for f in ctx.findings if "CVE-" in f.title and "WordPress 6.4" in f.title]
        assert len(core_cves) >= 1, "WP 6.4.3 should match at least 1 core CVE"


# =====================================================================
# VULN — RATE LIMITING
# =====================================================================

@skip_no_lab
class TestVulnRateLimit:
    def test_no_rate_limit_on_login(self):
        """The lab has no rate limiting."""
        ctx = _get_ctx()
        assert _has_finding(ctx, "rate-limit") or _has_finding(ctx, "rate limit")


# =====================================================================
# VULN — XSS
# =====================================================================

@skip_no_lab
class TestVulnXSS:
    def test_xss_detected(self):
        """The lab WordPress reflects XSS in search."""
        ctx = _get_ctx()
        assert _has_finding(ctx, "xss")


# =====================================================================
# VULN — SESSION / AUTH
# =====================================================================

@skip_no_lab
class TestVulnSessionAuth:
    def test_cookie_flags_missing(self):
        ctx = _get_ctx()
        assert _has_finding(ctx, "cookie") or _has_finding(ctx, "flags")

    def test_csrf_missing_on_login(self):
        ctx = _get_ctx()
        assert _has_finding(ctx, "csrf") or _has_finding(ctx, "nonce")

    def test_auth_bypass_admin_post(self):
        ctx = _get_ctx()
        assert _has_finding(ctx, "admin-post") or _has_finding(ctx, "auth")


# =====================================================================
# VULN — MISCONFIG
# =====================================================================

@skip_no_lab
class TestVulnMisconfig:
    def test_misconfig_registration_flagged(self):
        ctx = _get_ctx()
        misconfig_findings = [f for f in ctx.findings if "misconfig" in f.module]
        # Should have at least registration open
        assert len(misconfig_findings) >= 1 or _has_finding(ctx, "inscription")

    def test_honeypot_not_detected(self):
        """The lab is NOT a honeypot — should be clear."""
        ctx = _get_ctx()
        honeypot = [f for f in ctx.findings if "honeypot" in f.title.lower()]
        for h in honeypot:
            assert "aucun" in h.title.lower() or h.severity == Severity.INFO


# =====================================================================
# SCORE & SEVERITY DISTRIBUTION
# =====================================================================

@skip_no_lab
class TestScoreAndSeverity:
    def test_total_findings_minimum(self):
        """The lab has many vulns — should find at least 30."""
        ctx = _get_ctx()
        assert len(ctx.findings) >= 30, f"Expected >= 30 findings, got {len(ctx.findings)}"

    def test_critical_findings_minimum(self):
        """At least 5 CRITICAL: .git, .env, debug secret, CORS, SPF/DMARC."""
        ctx = _get_ctx()
        crits = [f for f in ctx.findings if f.severity == Severity.CRITICAL]
        assert len(crits) >= 5, f"Expected >= 5 CRITICAL, got {len(crits)}"

    def test_high_findings_minimum(self):
        ctx = _get_ctx()
        highs = [f for f in ctx.findings if f.severity == Severity.HIGH]
        assert len(highs) >= 5, f"Expected >= 5 HIGH, got {len(highs)}"

    def test_max_cvss_above_9(self):
        """With .git/.env exposed, max CVSS should be >= 9.0."""
        ctx = _get_ctx()
        assert ctx.max_cvss >= 9.0, f"Expected max CVSS >= 9.0, got {ctx.max_cvss}"

    def test_no_zero_cvss_for_critical(self):
        """CRITICAL findings should always have a CVSS score > 0."""
        ctx = _get_ctx()
        for f in ctx.findings:
            if f.severity == Severity.CRITICAL:
                assert f.cvss_score > 0, f"CRITICAL finding {f.id} has CVSS 0"


# =====================================================================
# REPORT GENERATION
# =====================================================================

@skip_no_lab
class TestReportGeneration:
    def test_reports_generated(self):
        """After scan, reports should exist in loot/."""
        import tempfile
        from report.generator import generate_reports
        ctx = _get_ctx()
        tmpdir = tempfile.mkdtemp()
        files = generate_reports(ctx, output_dir=tmpdir)
        assert len(files) >= 2  # JSON + HTML (+ DOCX if python-docx installed)
        for f in files:
            assert f.exists()
            assert f.stat().st_size > 100

    def test_html_report_contains_findings(self):
        import tempfile
        from report.generator import generate_html_report
        ctx = _get_ctx()
        tmpdir = Path(tempfile.mkdtemp())
        path = generate_html_report(ctx, tmpdir)
        content = path.read_text(encoding="utf-8")
        # Should contain critical findings
        assert "CRITICAL" in content
        assert "cors" in content.lower() or "CORS" in content
        assert "debug.log" in content.lower()

    def test_json_report_valid(self):
        import json
        import tempfile
        from report.generator import generate_json_report
        ctx = _get_ctx()
        tmpdir = Path(tempfile.mkdtemp())
        path = generate_json_report(ctx, tmpdir)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "findings" in data
        assert "meta" in data
        assert len(data["findings"]) == len(ctx.findings)
