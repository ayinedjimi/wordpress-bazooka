"""Tests for Pydantic models."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.models import (
    Finding, Severity, Confidence, FPPotential, FindingType,
    Evidence, Compliance, Target, ScanMeta, WPUser, WPPlugin, WPTheme,
)


def test_finding_creation():
    f = Finding(
        id="TEST-001",
        title="Test finding",
        severity=Severity.HIGH,
        cvss_score=7.5,
    )
    assert f.id == "TEST-001"
    assert f.severity == Severity.HIGH
    assert f.cvss_score == 7.5
    assert f.confidence == Confidence.CONFIRMED  # default
    assert f.false_positive_potential == FPPotential.LOW  # default


def test_finding_with_evidence():
    e = Evidence(
        request="GET /test",
        response_status=200,
        response_headers={"Content-Type": "text/html"},
        response_body_excerpt="<html>test</html>",
    )
    f = Finding(
        id="TEST-002",
        title="With evidence",
        severity=Severity.CRITICAL,
        evidence=e,
    )
    assert f.evidence.response_status == 200
    assert "Content-Type" in f.evidence.response_headers


def test_finding_with_compliance():
    c = Compliance(
        owasp_2021="A01:2021",
        cwe="CWE-346",
        mitre_attack="T1189",
    )
    f = Finding(
        id="TEST-003",
        title="With compliance",
        severity=Severity.MEDIUM,
        compliance=c,
    )
    assert f.compliance.owasp_2021 == "A01:2021"
    assert f.compliance.cwe == "CWE-346"


def test_severity_values():
    assert Severity.CRITICAL.value == "CRITICAL"
    assert Severity.HIGH.value == "HIGH"
    assert Severity.MEDIUM.value == "MEDIUM"
    assert Severity.LOW.value == "LOW"
    assert Severity.INFO.value == "INFO"


def test_target_creation():
    t = Target(url="https://test.com", domain="test.com")
    assert t.url == "https://test.com"
    assert t.wp_content_path == "/wp-content/"
    assert t.users == []
    assert t.plugins == []


def test_target_with_users():
    t = Target(url="https://test.com", domain="test.com")
    t.users.append(WPUser(id=1, username="admin", display_name="Admin"))
    t.users.append(WPUser(id=2, username="editor", email="editor@test.com"))
    assert len(t.users) == 2
    assert t.users[0].username == "admin"
    assert t.users[1].email == "editor@test.com"


def test_plugin_model():
    p = WPPlugin(slug="contact-form-7", version="5.8.1", name="Contact Form 7")
    assert p.slug == "contact-form-7"
    assert p.version == "5.8.1"
    assert p.cves == []


def test_theme_model():
    t = WPTheme(slug="flavor", version="1.2", parent="flavor-starter")
    assert t.slug == "flavor"
    assert t.parent == "flavor-starter"


def test_scan_meta_defaults():
    m = ScanMeta()
    assert m.bazooka_version == "1.0.0"
    assert m.schema_version == "2.0"
    assert m.total_requests == 0


def test_finding_serialization():
    f = Finding(
        id="TEST-SERIAL",
        title="Serialization test",
        severity=Severity.HIGH,
        cvss_score=6.5,
        confidence=Confidence.LIKELY,
    )
    data = f.model_dump(mode="json")
    assert data["severity"] == "HIGH"
    assert data["confidence"] == "likely"
    assert isinstance(data["timestamp"], str)
