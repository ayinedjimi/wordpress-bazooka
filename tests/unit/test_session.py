"""Tests for HTTP session and WAF detection."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.session import BazookaSession, ResponseCache, WAFProfile


def test_cache_put_get():
    cache = ResponseCache()
    # Simulate a response-like object
    class FakeResp:
        status_code = 200
        text = "hello"

    cache.put("GET", "https://test.com/", FakeResp())
    result = cache.get("GET", "https://test.com/", ttl=300)
    assert result is not None
    assert result.status_code == 200


def test_cache_miss():
    cache = ResponseCache()
    result = cache.get("GET", "https://test.com/nonexistent", ttl=300)
    assert result is None


def test_cache_different_urls():
    cache = ResponseCache()
    class FakeResp200:
        status_code = 200
    class FakeResp404:
        status_code = 404

    cache.put("GET", "https://test.com/a", FakeResp200())
    cache.put("GET", "https://test.com/b", FakeResp404())

    assert cache.get("GET", "https://test.com/a", ttl=300).status_code == 200
    assert cache.get("GET", "https://test.com/b", ttl=300).status_code == 404


def test_cache_clear():
    cache = ResponseCache()
    class FakeResp:
        status_code = 200
    cache.put("GET", "https://test.com/", FakeResp())
    cache.clear()
    assert cache.get("GET", "https://test.com/", ttl=300) is None


def test_waf_profile_defaults():
    waf = WAFProfile()
    assert waf.name is None
    assert waf.detected is False
    assert waf.blocks_dotfiles is False
    assert waf.calibrated is False


def test_waf_profile_to_dict():
    waf = WAFProfile()
    waf.name = "Cloudflare"
    waf.detected = True
    waf.blocks_dotfiles = True
    d = waf.to_dict()
    assert d["name"] == "Cloudflare"
    assert d["detected"] is True
    assert d["blocks_dotfiles"] is True


def test_session_creation():
    s = BazookaSession(rate_limit=5, timeout=10)
    assert s.rate_limit == 5
    assert s.timeout == 10
    assert s.waf_detected is None
    assert s.request_count == 0


def test_session_waf_generic_page_uncalibrated():
    s = BazookaSession()
    # Before calibration, should always return False
    assert s.is_waf_generic_page(404, 500) is False
    assert s.is_waf_generic_page(403, 500) is False


def test_session_waf_generic_page_calibrated():
    s = BazookaSession()
    s.waf.calibrated = True
    s.waf.baseline_404_sizes = {500, 495, 505}
    s.waf.baseline_403_sizes = {300, 295, 305}

    # Exact match = generic page
    assert s.is_waf_generic_page(404, 500) is True
    assert s.is_waf_generic_page(403, 300) is True

    # Within tolerance (must be in the set)
    assert s.is_waf_generic_page(404, 505) is True

    # Different size = not generic
    assert s.is_waf_generic_page(404, 1000) is False
    assert s.is_waf_generic_page(403, 50) is False

    # 403 same size as 404 baseline = WAF transforming 404→403
    assert s.is_waf_generic_page(403, 500) is True
