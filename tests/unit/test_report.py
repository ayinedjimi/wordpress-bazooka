"""Tests for report generation logic."""

import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.models import Finding, Severity, Confidence, Target, ScanMeta, Evidence, Compliance
from core.engine import ScanContext
from report.generator import generate_json_report, generate_html_report, _score_class, _build_remediation_plan


def _make_ctx_with_findings():
    target = Target(url="https://test.com", domain="test.com", wp_version="6.4.3")
    target.meta = ScanMeta(target="https://test.com", profile="standard", total_requests=42)
    ctx = ScanContext(target)
    ctx.add_finding(Finding(
        id="TEST-001", title="Critical finding", severity=Severity.CRITICAL, cvss_score=9.8,
        description="Test critical", remediation="Fix it now",
        compliance=Compliance(owasp_2021="A01:2021", cwe="CWE-346"),
    ))
    ctx.add_finding(Finding(
        id="TEST-002", title="High finding", severity=Severity.HIGH, cvss_score=7.5,
        description="Test high", remediation="Fix it soon",
    ))
    ctx.add_finding(Finding(
        id="TEST-003", title="Info finding", severity=Severity.INFO,
        description="Just info", remediation="",
    ))
    return ctx


def test_score_class():
    assert _score_class(9.5) == "score-critical"
    assert _score_class(8.0) == "score-high"
    assert _score_class(5.0) == "score-medium"
    assert _score_class(2.0) == "score-low"
    assert _score_class(0.0) == "score-good"


def test_remediation_plan():
    ctx = _make_ctx_with_findings()
    plan = _build_remediation_plan(ctx.findings)
    assert len(plan) >= 2
    # First item should be CRITICAL
    assert plan[0]["severity"] == "CRITICAL"


def test_json_report_generation():
    ctx = _make_ctx_with_findings()
    tmpdir = Path(tempfile.mkdtemp())
    path = generate_json_report(ctx, tmpdir)
    assert path.exists()
    content = path.read_text(encoding="utf-8")
    assert "TEST-001" in content
    assert "Critical finding" in content
    assert "test.com" in content


def test_html_report_generation():
    ctx = _make_ctx_with_findings()
    tmpdir = Path(tempfile.mkdtemp())
    path = generate_html_report(ctx, tmpdir)
    assert path.exists()
    content = path.read_text(encoding="utf-8")
    assert "BAZOOKA" in content
    assert "test.com" in content
    assert "Critical finding" in content
    assert "CRITICAL" in content
    assert "A01:2021" in content


def test_html_report_has_table():
    ctx = _make_ctx_with_findings()
    tmpdir = Path(tempfile.mkdtemp())
    path = generate_html_report(ctx, tmpdir)
    content = path.read_text(encoding="utf-8")
    assert "data-toggle=\"table\"" in content
    assert "TEST-001" in content
    assert "TEST-002" in content


def test_html_report_has_remediation():
    ctx = _make_ctx_with_findings()
    tmpdir = Path(tempfile.mkdtemp())
    path = generate_html_report(ctx, tmpdir)
    content = path.read_text(encoding="utf-8")
    assert "Plan de Remediation" in content
    assert "Fix it now" in content


def test_empty_findings_report():
    target = Target(url="https://empty.com", domain="empty.com")
    target.meta = ScanMeta(target="https://empty.com")
    ctx = ScanContext(target)
    tmpdir = Path(tempfile.mkdtemp())
    json_path = generate_json_report(ctx, tmpdir)
    assert json_path.exists()
    html_path = generate_html_report(ctx, tmpdir)
    assert html_path.exists()
