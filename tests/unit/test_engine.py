"""Tests for scan engine context and module discovery."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.models import Finding, Severity, Target, ScanMeta
from core.engine import ScanContext, ScanEngine


def test_scan_context_creation():
    target = Target(url="https://test.com", domain="test.com")
    ctx = ScanContext(target)
    assert ctx.target.url == "https://test.com"
    assert ctx.findings == []
    assert ctx.data == {}


def test_scan_context_add_finding():
    target = Target(url="https://test.com", domain="test.com")
    ctx = ScanContext(target)
    f = Finding(id="TEST-001", title="Test", severity=Severity.HIGH, cvss_score=7.5)
    ctx.add_finding(f)
    assert len(ctx.findings) == 1
    assert len(ctx.target.findings) == 1
    assert ctx.findings[0].id == "TEST-001"


def test_severity_counts():
    target = Target(url="https://test.com", domain="test.com")
    ctx = ScanContext(target)
    ctx.add_finding(Finding(id="1", title="C1", severity=Severity.CRITICAL))
    ctx.add_finding(Finding(id="2", title="C2", severity=Severity.CRITICAL))
    ctx.add_finding(Finding(id="3", title="H1", severity=Severity.HIGH))
    ctx.add_finding(Finding(id="4", title="L1", severity=Severity.LOW))

    counts = ctx.severity_counts
    assert counts["CRITICAL"] == 2
    assert counts["HIGH"] == 1
    assert counts["MEDIUM"] == 0
    assert counts["LOW"] == 1


def test_max_cvss():
    target = Target(url="https://test.com", domain="test.com")
    ctx = ScanContext(target)
    ctx.add_finding(Finding(id="1", title="Low", severity=Severity.LOW, cvss_score=2.0))
    ctx.add_finding(Finding(id="2", title="Crit", severity=Severity.CRITICAL, cvss_score=9.8))
    ctx.add_finding(Finding(id="3", title="Med", severity=Severity.MEDIUM, cvss_score=5.5))

    assert ctx.max_cvss == 9.8


def test_max_cvss_empty():
    target = Target(url="https://test.com", domain="test.com")
    ctx = ScanContext(target)
    assert ctx.max_cvss == 0.0


def test_scan_context_data():
    target = Target(url="https://test.com", domain="test.com")
    ctx = ScanContext(target)
    ctx.set_data("wp_version", "6.4.3")
    ctx.set_data("plugins", ["cf7", "elementor"])

    assert ctx.get_data("wp_version") == "6.4.3"
    assert ctx.get_data("plugins") == ["cf7", "elementor"]
    assert ctx.get_data("nonexistent") is None
    assert ctx.get_data("nonexistent", "default") == "default"


def test_engine_module_discovery():
    engine = ScanEngine("https://test.com", profile="standard")
    engine.discover_modules()

    # Should find modules in recon, enum, vuln
    recon_count = len(engine._modules["recon"])
    enum_count = len(engine._modules["enum"])
    vuln_count = len(engine._modules["vuln"])

    assert recon_count >= 3, f"Expected >= 3 recon modules, got {recon_count}"
    assert enum_count >= 4, f"Expected >= 4 enum modules, got {enum_count}"
    assert vuln_count >= 1, f"Expected >= 1 vuln modules, got {vuln_count}"


def test_engine_quick_profile():
    engine = ScanEngine("https://test.com", profile="quick")
    engine.discover_modules()

    # Quick profile should have fewer modules
    total_quick = sum(len(mods) for mods in engine._modules.values())

    engine2 = ScanEngine("https://test.com", profile="standard")
    engine2.discover_modules()
    total_standard = sum(len(mods) for mods in engine2._modules.values())

    assert total_quick <= total_standard, "Quick should have fewer modules than standard"


def test_engine_domain_extraction():
    engine = ScanEngine("https://www.example.com/path/")
    assert engine.target.domain == "example.com"  # www stripped

    engine2 = ScanEngine("https://example.com")
    assert engine2.target.domain == "example.com"

    engine3 = ScanEngine("https://sub.example.com")
    assert engine3.target.domain == "sub.example.com"  # non-www kept


def test_engine_no_exploit_without_pentest():
    engine = ScanEngine("https://test.com", pentest=False)
    engine.discover_modules()
    assert len(engine._modules["exploit"]) == 0


def test_engine_no_infra_without_flag():
    engine = ScanEngine("https://test.com", infra=False)
    engine.discover_modules()
    assert len(engine._modules["infra"]) == 0
