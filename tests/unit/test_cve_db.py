"""Tests for CVE database manager."""

import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from cve_db.manager import CVEDatabase


def _get_temp_db():
    """Create a temporary CVE database for testing."""
    tmp = tempfile.mktemp(suffix=".db")
    db = CVEDatabase(db_path=Path(tmp))
    db.initialize()
    return db


def test_database_init():
    db = _get_temp_db()
    stats = db.stats()
    assert stats["total"] > 0
    assert stats["version"] == "2026.03.31"
    db.close()


def test_lookup_plugin_by_slug():
    db = _get_temp_db()
    cves = db.lookup_plugin("contact-form-7")
    assert len(cves) >= 1
    assert any(c["cve_id"] == "CVE-2024-6625" for c in cves)
    db.close()


def test_lookup_plugin_with_version():
    db = _get_temp_db()
    cves = db.lookup_plugin("contact-form-7", "5.8.1")
    assert len(cves) >= 1
    # CF7 5.8.1 should match CVEs with affected_version_max >= 5.8.1
    db.close()


def test_lookup_plugin_not_found():
    db = _get_temp_db()
    cves = db.lookup_plugin("nonexistent-plugin-xyz")
    assert len(cves) == 0
    db.close()


def test_lookup_updraftplus():
    db = _get_temp_db()
    cves = db.lookup_plugin("updraftplus")
    assert len(cves) >= 1
    assert cves[0]["cve_id"] == "CVE-2022-0633"
    assert cves[0]["cvss_score"] == 8.5
    db.close()


def test_lookup_core():
    db = _get_temp_db()
    cves = db.lookup_core()
    # Should find wordpress core CVEs
    wp_cves = [c for c in cves if c["component_slug"] == "wordpress"]
    assert len(wp_cves) >= 1
    db.close()


def test_lookup_core_with_version():
    db = _get_temp_db()
    cves = db.lookup_core("6.4.2")
    # WP 6.4.2 should match CVE-2024-31210 (affected <= 6.4.2)
    assert any(c["cve_id"] == "CVE-2024-31210" for c in cves)
    db.close()


def test_lookup_theme():
    db = _get_temp_db()
    cves = db.lookup_theme("flavor")
    assert len(cves) >= 1
    db.close()


def test_search():
    db = _get_temp_db()
    results = db.search("RCE")
    assert len(results) >= 1
    assert any("RCE" in r.get("title", "") or "RCE" in r.get("vuln_type", "") for r in results)
    db.close()


def test_search_by_cve_id():
    db = _get_temp_db()
    results = db.search("CVE-2024-6386")
    assert len(results) == 1
    assert results[0]["component_slug"] == "sitepress-multilingual-cms"
    db.close()


def test_stats():
    db = _get_temp_db()
    stats = db.stats()
    assert "total" in stats
    assert "by_type" in stats
    assert "by_severity" in stats
    assert stats["total"] >= 20  # At least 20 CVEs seeded
    assert stats["by_type"].get("plugin", 0) > 0
    db.close()


def test_severity_distribution():
    db = _get_temp_db()
    stats = db.stats()
    assert stats["by_severity"].get("CRITICAL", 0) >= 5
    assert stats["by_severity"].get("HIGH", 0) >= 1
    db.close()


def test_double_init_no_duplicate():
    db = _get_temp_db()
    count1 = db.stats()["total"]
    db.initialize()  # Call init again
    count2 = db.stats()["total"]
    assert count1 == count2  # No duplicates
    db.close()
