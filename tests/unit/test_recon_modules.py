"""Tests for recon modules — DNS enum, headers analysis, WAF detect."""

import asyncio
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.models import Target, Severity
from core.engine import ScanContext
from modules.base import ModuleResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class MockResponse:
    """Fake HTTP response object matching the interface used by modules."""

    def __init__(self, status_code=200, text="", headers=None, content=None, json_data=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.content = content if content is not None else text.encode("utf-8", errors="replace")
        self._json_data = json_data

    def json(self):
        if self._json_data is not None:
            return self._json_data
        import json
        return json.loads(self.text)


class MockWAF:
    """Minimal WAF profile stand-in."""

    def __init__(self):
        self.calibrated = False
        self.baseline_404_sizes: set[int] = set()
        self.baseline_403_sizes: set[int] = set()


class MockSession:
    """Mock BazookaSession that returns predefined responses for specific URLs.

    Usage::

        session = MockSession({
            "https://test.com": MockResponse(200, "<html>OK</html>"),
            "https://test.com/feed/": MockResponse(404, "Not Found"),
        })
    """

    def __init__(self, responses: dict[str, MockResponse] | None = None, default_response: MockResponse | None = None):
        self._responses = responses or {}
        self._default = default_response or MockResponse(404, "Not Found")
        self.waf = MockWAF()

    @property
    def waf_detected(self):
        return None

    def _resolve(self, url: str) -> MockResponse:
        return self._responses.get(url, self._default)

    async def get(self, url: str, **kwargs) -> MockResponse:
        return self._resolve(url)

    async def post(self, url: str, **kwargs) -> MockResponse:
        return self._resolve(url)

    async def head(self, url: str, **kwargs) -> MockResponse:
        return self._resolve(url)


def make_ctx(url: str = "https://test.com", domain: str = "test.com", profile: str = "standard") -> ScanContext:
    """Return a ScanContext with a basic Target."""
    target = Target(url=url, domain=domain)
    ctx = ScanContext(target)
    ctx.profile = profile
    return ctx


# ---------------------------------------------------------------------------
# DNS Enum tests
# ---------------------------------------------------------------------------

class FakeDNSAnswer:
    """Fake dns.resolver answer yielding string records."""

    def __init__(self, records: list[str]):
        self._records = records

    def __iter__(self):
        return iter(self._records)


def _mock_resolve_factory(records_by_query: dict[tuple[str, str], list[str]]):
    """Return a function that mimics dns.resolver.resolve based on a lookup table.

    *records_by_query* maps ``(name, rtype)`` to a list of record strings.
    Missing keys raise ``dns.resolver.NoAnswer``.
    """
    import dns.resolver

    def _resolve(qname, rdtype):
        key = (str(qname), str(rdtype))
        if key in records_by_query:
            return FakeDNSAnswer(records_by_query[key])
        raise dns.resolver.NoAnswer()

    return _resolve


def test_dns_enum_missing_spf_and_dmarc():
    """No SPF and no DMARC records -> two CRITICAL findings."""
    from modules.recon.dns_enum import DNSEnumModule

    # All DNS lookups return empty
    mock_resolve = _mock_resolve_factory({})

    ctx = make_ctx()
    session = MockSession()
    module = DNSEnumModule()

    with patch("dns.resolver.resolve", side_effect=mock_resolve):
        result: ModuleResult = asyncio.run(module.run(ctx, session))

    ids = [f.id for f in result.findings]
    assert "RECON-SPF-001" in ids, "Missing SPF finding expected"
    assert "RECON-DMARC-001" in ids, "Missing DMARC finding expected"
    assert all(f.severity == Severity.CRITICAL for f in result.findings)


def test_dns_enum_spf_soft_fail():
    """SPF with ~all -> MEDIUM finding about soft fail."""
    from modules.recon.dns_enum import DNSEnumModule

    records = {
        ("test.com", "TXT"): ['"v=spf1 include:_spf.google.com ~all"'],
        ("test.com", "A"): ["1.2.3.4"],
    }
    # `mock_resolve` from `_mock_resolve_factory(records)` is superseded by
    # `resolve_with_dmarc` defined right below; only the latter is patched in.
    # DMARC lookup also needs to succeed — provide a proper DMARC
    def resolve_with_dmarc(qname, rdtype):
        key = (str(qname), str(rdtype))
        if key == ("_dmarc.test.com", "TXT"):
            return FakeDNSAnswer(['"v=DMARC1; p=reject; rua=mailto:dmarc@test.com"'])
        return _mock_resolve_factory(records)(qname, rdtype)

    ctx = make_ctx()
    session = MockSession()
    module = DNSEnumModule()

    with patch("dns.resolver.resolve", side_effect=resolve_with_dmarc):
        result = asyncio.run(module.run(ctx, session))

    ids = [f.id for f in result.findings]
    assert "RECON-SPF-002" in ids, "SPF soft fail finding expected"
    assert "RECON-DMARC-001" not in ids, "DMARC should NOT be flagged (p=reject)"
    spf_finding = [f for f in result.findings if f.id == "RECON-SPF-002"][0]
    assert spf_finding.severity == Severity.MEDIUM


def test_dns_enum_dmarc_policy_none():
    """DMARC with p=none -> HIGH finding."""
    from modules.recon.dns_enum import DNSEnumModule

    records = {
        ("test.com", "TXT"): ['"v=spf1 -all"'],
    }

    def resolve_side(qname, rdtype):
        key = (str(qname), str(rdtype))
        if key == ("_dmarc.test.com", "TXT"):
            return FakeDNSAnswer(['"v=DMARC1; p=none; rua=mailto:d@test.com"'])
        return _mock_resolve_factory(records)(qname, rdtype)

    ctx = make_ctx()
    module = DNSEnumModule()

    with patch("dns.resolver.resolve", side_effect=resolve_side):
        result = asyncio.run(module.run(ctx, MockSession()))

    ids = [f.id for f in result.findings]
    assert "RECON-DMARC-002" in ids
    dmarc_finding = [f for f in result.findings if f.id == "RECON-DMARC-002"][0]
    assert dmarc_finding.severity == Severity.HIGH


def test_dns_enum_good_spf_hard_fail():
    """SPF with -all (hard fail) + proper DMARC -> no SPF/DMARC findings."""
    from modules.recon.dns_enum import DNSEnumModule

    records = {
        ("test.com", "TXT"): ['"v=spf1 include:_spf.google.com -all"'],
        ("test.com", "A"): ["93.184.216.34"],
    }

    def resolve_all(qname, rdtype):
        key = (str(qname), str(rdtype))
        if key == ("_dmarc.test.com", "TXT"):
            return FakeDNSAnswer(['"v=DMARC1; p=reject; rua=mailto:d@test.com"'])
        return _mock_resolve_factory(records)(qname, rdtype)

    ctx = make_ctx()
    module = DNSEnumModule()

    with patch("dns.resolver.resolve", side_effect=resolve_all):
        result = asyncio.run(module.run(ctx, MockSession()))

    assert len(result.findings) == 0, "No findings expected for a well-configured SPF/DMARC"


def test_dns_enum_sets_ip():
    """A record should populate ctx.target.ip."""
    from modules.recon.dns_enum import DNSEnumModule

    records = {
        ("test.com", "A"): ["10.0.0.1"],
        ("test.com", "TXT"): ['"v=spf1 -all"'],
    }

    def resolve_all(qname, rdtype):
        key = (str(qname), str(rdtype))
        if key == ("_dmarc.test.com", "TXT"):
            return FakeDNSAnswer(['"v=DMARC1; p=reject"'])
        return _mock_resolve_factory(records)(qname, rdtype)

    ctx = make_ctx()
    module = DNSEnumModule()

    with patch("dns.resolver.resolve", side_effect=resolve_all):
        asyncio.run(module.run(ctx, MockSession()))

    assert ctx.target.ip == "10.0.0.1"


# ---------------------------------------------------------------------------
# Headers Analysis tests
# ---------------------------------------------------------------------------

def test_headers_analysis_missing_all_security_headers():
    """Response with NO security headers -> one finding per missing header."""
    from modules.recon.headers_analysis import HeadersAnalysisModule, HEADER_CHECKS

    resp = MockResponse(200, "<html></html>", headers={"Content-Type": "text/html"})
    session = MockSession({"https://test.com": resp})
    ctx = make_ctx()
    module = HeadersAnalysisModule()

    result = asyncio.run(module.run(ctx, session))

    # Should have one finding per HEADER_CHECKS entry
    ids = {f.id for f in result.findings}
    for check in HEADER_CHECKS:
        assert check["id"] in ids, f"Expected finding {check['id']} for missing {check['header']}"


def test_headers_analysis_all_headers_present():
    """Response WITH all security headers -> no missing-header findings."""
    from modules.recon.headers_analysis import HeadersAnalysisModule

    headers = {
        "Content-Type": "text/html",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=()",
    }
    resp = MockResponse(200, "<html></html>", headers=headers)
    session = MockSession({"https://test.com": resp})
    ctx = make_ctx()
    module = HeadersAnalysisModule()

    result = asyncio.run(module.run(ctx, session))

    # No missing-header findings
    assert len(result.findings) == 0


def test_headers_analysis_x_powered_by_exposed():
    """X-Powered-By in response -> RECON-HDR-010 finding."""
    from modules.recon.headers_analysis import HeadersAnalysisModule

    headers = {
        "Content-Type": "text/html",
        "X-Powered-By": "PHP/8.2.4",
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin",
        "Permissions-Policy": "camera=()",
    }
    resp = MockResponse(200, "<html></html>", headers=headers)
    session = MockSession({"https://test.com": resp})
    ctx = make_ctx()
    module = HeadersAnalysisModule()

    result = asyncio.run(module.run(ctx, session))

    ids = [f.id for f in result.findings]
    assert "RECON-HDR-010" in ids
    finding = [f for f in result.findings if f.id == "RECON-HDR-010"][0]
    assert "PHP/8.2.4" in finding.title


def test_headers_analysis_partial_headers():
    """Only HSTS and CSP present -> findings for the missing ones."""
    from modules.recon.headers_analysis import HeadersAnalysisModule

    headers = {
        "Content-Type": "text/html",
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
    }
    resp = MockResponse(200, "<html></html>", headers=headers)
    session = MockSession({"https://test.com": resp})
    ctx = make_ctx()
    module = HeadersAnalysisModule()

    result = asyncio.run(module.run(ctx, session))

    ids = {f.id for f in result.findings}
    # HSTS (001) and CSP (002) should NOT be in findings
    assert "RECON-HDR-001" not in ids
    assert "RECON-HDR-002" not in ids
    # But the rest should be
    assert "RECON-HDR-003" in ids  # X-Frame-Options
    assert "RECON-HDR-004" in ids  # X-Content-Type-Options
    assert "RECON-HDR-005" in ids  # Referrer-Policy
    assert "RECON-HDR-006" in ids  # Permissions-Policy


def test_headers_analysis_stores_server_header():
    """Server header should be stored in result data."""
    from modules.recon.headers_analysis import HeadersAnalysisModule

    headers = {
        "Content-Type": "text/html",
        "Server": "Apache/2.4.52 (Ubuntu)",
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin",
        "Permissions-Policy": "camera=()",
    }
    resp = MockResponse(200, "<html></html>", headers=headers)
    session = MockSession({"https://test.com": resp})
    ctx = make_ctx()
    module = HeadersAnalysisModule()

    result = asyncio.run(module.run(ctx, session))

    assert result.data.get("server_header") == "Apache/2.4.52 (Ubuntu)"


# ---------------------------------------------------------------------------
# WAF Detect tests
# ---------------------------------------------------------------------------

def test_waf_detect_waf_present():
    """session.waf_detected returns a name -> finding with WAF info."""
    from modules.recon.waf_detect import WAFDetectModule

    session = MockSession()
    # Override waf_detected to return a WAF name
    session.__class__ = type("WAFSession", (MockSession,), {"waf_detected": property(lambda self: "Cloudflare")})

    ctx = make_ctx()
    module = WAFDetectModule()

    result = asyncio.run(module.run(ctx, session))

    ids = [f.id for f in result.findings]
    assert "RECON-WAF-001" in ids
    assert "Cloudflare" in result.findings[0].title
    assert ctx.target.waf_detected == "Cloudflare"


def test_waf_detect_no_waf():
    """session.waf_detected returns None -> MEDIUM finding: no WAF."""
    from modules.recon.waf_detect import WAFDetectModule

    session = MockSession()  # waf_detected returns None by default
    ctx = make_ctx()
    module = WAFDetectModule()

    result = asyncio.run(module.run(ctx, session))

    ids = [f.id for f in result.findings]
    assert "RECON-WAF-002" in ids
    assert result.findings[0].severity == Severity.MEDIUM


def test_waf_detect_stores_data():
    """WAF detection stores waf_detected list in data."""
    from modules.recon.waf_detect import WAFDetectModule

    session = MockSession()
    ctx = make_ctx()
    module = WAFDetectModule()

    result = asyncio.run(module.run(ctx, session))

    assert "waf_detected" in result.data
    assert result.data["waf_detected"] == []


def test_waf_detect_with_waf_stores_data():
    """WAF detection stores waf name in data list."""
    from modules.recon.waf_detect import WAFDetectModule

    session = MockSession()
    session.__class__ = type("WAFSession2", (MockSession,), {"waf_detected": property(lambda self: "Wordfence")})
    ctx = make_ctx()
    module = WAFDetectModule()

    result = asyncio.run(module.run(ctx, session))

    assert result.data["waf_detected"] == ["Wordfence"]


def test_dns_enum_data_records_stored():
    """DNS records should be stored in result.data."""
    from modules.recon.dns_enum import DNSEnumModule

    records = {
        ("test.com", "A"): ["1.2.3.4"],
        ("test.com", "MX"): ["10 mail.test.com."],
        ("test.com", "TXT"): ['"v=spf1 -all"'],
    }

    def resolve_all(qname, rdtype):
        key = (str(qname), str(rdtype))
        if key == ("_dmarc.test.com", "TXT"):
            return FakeDNSAnswer(['"v=DMARC1; p=reject"'])
        return _mock_resolve_factory(records)(qname, rdtype)

    ctx = make_ctx()
    module = DNSEnumModule()

    with patch("dns.resolver.resolve", side_effect=resolve_all):
        result = asyncio.run(module.run(ctx, MockSession()))

    assert "dns_records" in result.data
    assert result.data["dns_records"]["A"] == ["1.2.3.4"]
    assert result.data["spf_record"] == '"v=spf1 -all"'
    # The dns module strips surrounding quotes via str(r).strip('"')
    assert "v=DMARC1" in result.data["dmarc_record"]
