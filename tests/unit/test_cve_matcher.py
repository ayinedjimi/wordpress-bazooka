"""Tests for CVE matcher version comparison logic."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def test_version_lte_basic():
    from modules.vuln.cve_matcher import _version_lte
    assert _version_lte("5.8.1", "5.9.4") is True
    assert _version_lte("5.9.4", "5.9.4") is True
    assert _version_lte("5.9.5", "5.9.4") is False


def test_version_lte_major():
    from modules.vuln.cve_matcher import _version_lte
    assert _version_lte("3.18.0", "3.20.0") is True
    assert _version_lte("4.0.0", "3.20.0") is False


def test_version_lte_equal():
    from modules.vuln.cve_matcher import _version_lte
    assert _version_lte("1.0.0", "1.0.0") is True
    assert _version_lte("6.4.3", "6.4.3") is True


def test_version_lte_two_parts():
    from modules.vuln.cve_matcher import _version_lte
    assert _version_lte("5.8", "5.9") is True
    assert _version_lte("5.9", "5.8") is False


def test_version_lte_invalid():
    from modules.vuln.cve_matcher import _version_lte
    assert _version_lte("abc", "5.0") is False
    assert _version_lte("5.0", "xyz") is False
    assert _version_lte("", "") is False


def test_cve_db_lookup_elementor():
    from cve_db.manager import get_db
    db = get_db()
    cves = db.lookup_plugin("elementor")
    assert len(cves) >= 5, f"Expected >= 5 Elementor CVEs, got {len(cves)}"
    # Should include the RCE
    rce_cves = [c for c in cves if c["vuln_type"] == "RCE"]
    assert len(rce_cves) >= 1
    db.close()


def test_cve_db_lookup_litespeed():
    from cve_db.manager import get_db
    db = get_db()
    cves = db.lookup_plugin("litespeed-cache")
    assert len(cves) >= 3
    # Should have the critical privilege escalation
    critical = [c for c in cves if c["severity"] == "CRITICAL"]
    assert len(critical) >= 1
    db.close()


def test_cve_db_lookup_really_simple_ssl():
    from cve_db.manager import get_db
    db = get_db()
    cves = db.lookup_plugin("really-simple-ssl")
    assert len(cves) >= 1
    assert any(c["cve_id"] == "CVE-2024-10924" for c in cves)
    db.close()


def test_cve_db_core_wordpress():
    from cve_db.manager import get_db
    db = get_db()
    cves = db.lookup_core("6.4.2")
    assert len(cves) >= 1
    db.close()


def test_cve_db_search_xss():
    from cve_db.manager import get_db
    db = get_db()
    results = db.search("XSS")
    assert len(results) >= 10, f"Expected >= 10 XSS CVEs, got {len(results)}"
    db.close()


def test_cve_db_search_rce():
    from cve_db.manager import get_db
    db = get_db()
    results = db.search("RCE")
    assert len(results) >= 3
    db.close()


def test_cve_db_total_over_100():
    from cve_db.manager import get_db
    db = get_db()
    stats = db.stats()
    assert stats["total"] >= 100, f"Expected >= 100 CVEs, got {stats['total']}"
    db.close()
