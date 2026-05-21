"""Security regression tests.

Covers BUG-19 (path traversal on GUI routes) and BUG-20 (XSS escaping in
generated HTML report). These ensure the CRITICAL fixes from commit b549fa2
cannot silently regress.
"""

from __future__ import annotations

import pytest
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# BUG-20 — Report HTML escapes target-controlled content (XSS)
# ---------------------------------------------------------------------------

def test_report_escapes_xss_in_finding_title(tmp_path):
    from core.engine import ScanContext
    from core.models import (
        Confidence, Finding, FindingType, ScanMeta, Severity, Target,
    )
    from report.generator import generate_html_report

    target = Target(url="http://demo.test", domain="demo.test", scheme="http",
                    host="demo.test", port=80)
    target.meta = ScanMeta(
        start_time=datetime.now(), end_time=datetime.now(),
        duration_seconds=1.0, bazooka_version="1.0.0", profile="quick",
        total_requests=1, modules_executed=1, modules_skipped=0, modules_failed=0,
    )
    ctx = ScanContext(target=target)
    ctx.add_finding(Finding(
        id="XSS-1",
        title="<script>alert('xss-title')</script>",
        severity=Severity.HIGH, cvss_score=7.0,
        confidence=Confidence.LIKELY, finding_type=FindingType.MISCONFIGURATION,
        description="<img src=x onerror=alert('xss-desc')>",
        module="test", phase="vuln",
    ))

    out = generate_html_report(ctx, tmp_path)
    html = out.read_text(encoding="utf-8")

    # Raw script tag MUST NOT appear (would execute when auditor opens report)
    assert "<script>alert('xss-title')</script>" not in html
    # Escaped form MUST appear
    assert "&lt;script&gt;alert(" in html
    # Same for the onerror payload
    assert "<img src=x onerror=" not in html
    assert "&lt;img src=x onerror=" in html


def test_report_escapes_xss_in_finding_description(tmp_path):
    """Same path as title — confirm description field is also escaped."""
    from core.engine import ScanContext
    from core.models import (
        Confidence, Finding, FindingType, ScanMeta, Severity, Target,
    )
    from report.generator import generate_html_report

    target = Target(url="http://demo.test", domain="demo.test", scheme="http",
                    host="demo.test", port=80)
    target.meta = ScanMeta(
        start_time=datetime.now(), end_time=datetime.now(),
        duration_seconds=1.0, bazooka_version="1.0.0", profile="quick",
        total_requests=1, modules_executed=1, modules_skipped=0, modules_failed=0,
    )
    ctx = ScanContext(target=target)
    ctx.add_finding(Finding(
        id="XSS-2", title="safe-title",
        severity=Severity.LOW, cvss_score=3.0,
        confidence=Confidence.LIKELY, finding_type=FindingType.MISCONFIGURATION,
        description="<iframe src=javascript:alert(1)></iframe>",
        impact="<script>alert('impact')</script>",
        remediation="<a href='javascript:alert(1)'>click</a>",
        module="test", phase="vuln",
    ))
    out = generate_html_report(ctx, tmp_path)
    html = out.read_text(encoding="utf-8")
    assert "<iframe src=javascript:alert(1)>" not in html
    assert "<script>alert('impact')</script>" not in html
    assert "&lt;iframe" in html or "&lt;script" in html


# ---------------------------------------------------------------------------
# BUG-19 — Path traversal guard on GUI routes /report/{domain} and /api/findings/{domain}
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("hostile_domain", [
    "../etc/passwd",
    "..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "../../../",
    "..",
    ".",
    "",
    "/etc/passwd",
    "x/../y",
    "valid\x00null",
])
def test_safe_domain_dir_rejects_traversal(hostile_domain):
    from gui.app import _safe_domain_dir

    assert _safe_domain_dir(hostile_domain) is None, (
        f"path-traversal candidate {hostile_domain!r} was NOT rejected"
    )


@pytest.mark.parametrize("good_domain", [
    "example.com",
    "sub.example.com",
    "localhost",
    "127.0.0.1",
    "wp.lab.test",
    "demo-site.fr",
    "site_with_underscore",
])
def test_safe_domain_dir_accepts_valid(good_domain):
    from gui.app import _safe_domain_dir

    assert _safe_domain_dir(good_domain) is not None, (
        f"legitimate domain {good_domain!r} was rejected"
    )
