"""Tests for WAF detection and adaptation logic."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.session import BazookaSession, WAFProfile, WAF_SIGNATURES


def test_waf_signatures_exist():
    """Ensure we have signatures for major WAFs."""
    expected = ["Cloudflare", "SecuPress", "Wordfence", "Sucuri", "ModSecurity"]
    for waf in expected:
        assert waf in WAF_SIGNATURES, f"Missing signature for {waf}"


def test_waf_signature_structure():
    """Each signature must have headers, body, and behavior."""
    for name, sig in WAF_SIGNATURES.items():
        assert "headers" in sig, f"{name} missing headers"
        assert "body" in sig, f"{name} missing body"
        assert "behavior" in sig, f"{name} missing behavior"
        assert isinstance(sig["headers"], list)
        assert isinstance(sig["body"], list)
        assert isinstance(sig["behavior"], dict)


def test_waf_profile_defaults():
    waf = WAFProfile()
    assert waf.detected is False
    assert waf.name is None
    assert waf.blocks_dotfiles is False
    assert waf.generic_403_size is False
    assert waf.rate_limit_aggressive is False
    assert waf.calibrated is False
    assert waf.baseline_404_sizes == set()
    assert waf.baseline_403_sizes == set()


def test_waf_profile_to_dict():
    waf = WAFProfile()
    waf.name = "Cloudflare"
    waf.detected = True
    waf.blocks_dotfiles = True
    waf.generic_403_size = True
    d = waf.to_dict()
    assert d["name"] == "Cloudflare"
    assert d["detected"] is True
    assert d["blocks_dotfiles"] is True
    assert d["generic_403_size"] is True


def test_session_waf_not_detected_initially():
    s = BazookaSession()
    assert s.waf_detected is None
    assert s.waf.detected is False


def test_session_is_waf_generic_uncalibrated():
    s = BazookaSession()
    assert s.is_waf_generic_page(404, 1000) is False
    assert s.is_waf_generic_page(403, 500) is False


def test_session_is_waf_generic_calibrated():
    s = BazookaSession()
    s.waf.calibrated = True
    s.waf.baseline_404_sizes = {1000, 995, 1005}
    s.waf.baseline_403_sizes = {550, 545, 555}

    # Exact matches
    assert s.is_waf_generic_page(404, 1000) is True
    assert s.is_waf_generic_page(403, 550) is True

    # 403 with 404 size = WAF converting 404→403
    assert s.is_waf_generic_page(403, 1000) is True

    # Different sizes
    assert s.is_waf_generic_page(404, 2000) is False
    assert s.is_waf_generic_page(403, 100) is False


def test_session_rate_limit_default():
    s = BazookaSession(rate_limit=10)
    assert s.rate_limit == 10.0
    assert s._original_rate_limit == 10.0


def test_waf_behavior_cloudflare():
    cf = WAF_SIGNATURES["Cloudflare"]
    assert cf["behavior"]["blocks_dotfiles"] is True
    assert cf["behavior"]["generic_403_size"] is True
    assert cf["behavior"]["challenges_js"] is True


def test_waf_behavior_wordfence():
    wf = WAF_SIGNATURES["Wordfence"]
    assert wf["behavior"]["rate_limit_aggressive"] is True
