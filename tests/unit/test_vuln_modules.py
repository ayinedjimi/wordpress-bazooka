"""Tests for vuln modules — cors_check, rate_limit, xss_scanner, sqli_scanner,
cve_matcher, session_auth."""

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.models import Target, Severity, WPPlugin
from core.engine import ScanContext
from modules.base import ModuleResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class MockResponse:
    """Fake HTTP response object."""

    def __init__(self, status_code=200, text="", headers=None, content=None, json_data=None):
        self.status_code = status_code
        self.text = text
        self.headers = _MultiHeaders(headers or {})
        self.content = content if content is not None else text.encode("utf-8", errors="replace")
        self._json_data = json_data

    def json(self):
        if self._json_data is not None:
            return self._json_data
        return json.loads(self.text)


class _MultiHeaders(dict):
    """Dict subclass that also supports multi_items() for Set-Cookie tests."""

    def __init__(self, data=None):
        super().__init__(data or {})
        self._raw_items: list[tuple[str, str]] = []
        if data:
            for k, v in (data.items() if isinstance(data, dict) else data):
                self._raw_items.append((k, v))

    @classmethod
    def from_pairs(cls, pairs: list[tuple[str, str]]):
        """Create from a list of (key, value) pairs — supports duplicate keys."""
        obj = cls()
        for k, v in pairs:
            obj[k] = v  # last value wins for dict access
            obj._raw_items.append((k, v))
        return obj

    def multi_items(self):
        if self._raw_items:
            return self._raw_items
        return list(self.items())


class MockWAF:
    def __init__(self):
        self.calibrated = False
        self.baseline_404_sizes: set[int] = set()
        self.baseline_403_sizes: set[int] = set()


class MockSession:
    def __init__(self, responses=None, default_response=None):
        self._responses = responses or {}
        self._default = default_response or MockResponse(404, "Not Found")
        self.waf = MockWAF()

    @property
    def waf_detected(self):
        return None

    def _resolve(self, url):
        return self._responses.get(url, self._default)

    async def get(self, url, **kwargs):
        return self._resolve(url)

    async def post(self, url, **kwargs):
        return self._resolve(url)

    async def head(self, url, **kwargs):
        return self._resolve(url)


class SequentialMockSession(MockSession):
    """Session that returns different responses for successive POST calls to the same URL."""

    def __init__(self, post_sequences=None, **kwargs):
        super().__init__(**kwargs)
        self._post_sequences = post_sequences or {}
        self._post_counters = {}

    async def post(self, url, **kwargs):
        if url in self._post_sequences:
            idx = self._post_counters.get(url, 0)
            seq = self._post_sequences[url]
            resp = seq[min(idx, len(seq) - 1)]
            self._post_counters[url] = idx + 1
            return resp
        return self._resolve(url)


def make_ctx(url="https://test.com", domain="test.com", profile="standard"):
    target = Target(url=url, domain=domain)
    ctx = ScanContext(target)
    ctx.profile = profile
    return ctx


# ---------------------------------------------------------------------------
# CORS Check
# ---------------------------------------------------------------------------

def test_cors_reflected_origin_with_credentials():
    """Origin reflected + Credentials:true -> CRITICAL finding."""
    from modules.vuln.cors_check import CORSCheckModule

    headers = {
        "Access-Control-Allow-Origin": "https://evil.com",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET, POST",
    }
    resp = MockResponse(200, "[]", headers=headers)
    # The module tests multiple origins; evil.com is the first
    session = MockSession({"https://test.com/wp-json/wp/v2/posts": resp})
    ctx = make_ctx()
    module = CORSCheckModule()

    result = asyncio.run(module.run(ctx, session))

    ids = [f.id for f in result.findings]
    assert "VULN-CORS-001" in ids
    finding = result.findings[0]
    assert finding.severity == Severity.CRITICAL
    assert finding.cvss_score == 9.1


def test_cors_reflected_origin_without_credentials():
    """Origin reflected but no credentials -> HIGH finding."""
    from modules.vuln.cors_check import CORSCheckModule

    headers = {
        "Access-Control-Allow-Origin": "https://evil.com",
        "Access-Control-Allow-Credentials": "false",
    }
    resp = MockResponse(200, "[]", headers=headers)
    session = MockSession({"https://test.com/wp-json/wp/v2/posts": resp})
    ctx = make_ctx()
    module = CORSCheckModule()

    result = asyncio.run(module.run(ctx, session))

    ids = [f.id for f in result.findings]
    assert "VULN-CORS-001" in ids
    finding = result.findings[0]
    assert finding.severity == Severity.HIGH
    assert finding.cvss_score == 7.4


def test_cors_no_reflection():
    """No ACAO header -> no finding."""
    from modules.vuln.cors_check import CORSCheckModule

    resp = MockResponse(200, "[]", headers={"Content-Type": "application/json"})
    session = MockSession({"https://test.com/wp-json/wp/v2/posts": resp})
    ctx = make_ctx()
    module = CORSCheckModule()

    result = asyncio.run(module.run(ctx, session))

    assert len(result.findings) == 0


def test_cors_wildcard_star():
    """ACAO: * -> HIGH finding (no credentials)."""
    from modules.vuln.cors_check import CORSCheckModule

    headers = {"Access-Control-Allow-Origin": "*"}
    resp = MockResponse(200, "[]", headers=headers)
    session = MockSession({"https://test.com/wp-json/wp/v2/posts": resp})
    ctx = make_ctx()
    module = CORSCheckModule()

    result = asyncio.run(module.run(ctx, session))

    # * matches the `acao == "*"` branch
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Rate Limit
# ---------------------------------------------------------------------------

def test_rate_limit_no_blocking():
    """10 POST responses all 200 -> 'no rate limiting' finding."""
    from modules.vuln.rate_limit import RateLimitModule

    login_resp = MockResponse(200, "<html>Error: wrong password</html>")
    session = MockSession({"https://test.com/wp-login.php": login_resp})
    ctx = make_ctx()
    module = RateLimitModule()

    result = asyncio.run(module.run(ctx, session))

    ids = [f.id for f in result.findings]
    assert "VULN-RATE-001" in ids
    finding = [f for f in result.findings if f.id == "VULN-RATE-001"][0]
    assert finding.severity == Severity.HIGH
    assert "rate-limiting" in finding.title.lower() or "rate" in finding.title.lower()


def test_rate_limit_blocked_after_3():
    """Returns 429 after 3 requests -> 'rate limiting active' INFO finding."""
    from modules.vuln.rate_limit import RateLimitModule

    responses_200 = [MockResponse(200, "error")] * 3
    response_429 = MockResponse(429, "Too many requests")

    session = SequentialMockSession(
        post_sequences={
            "https://test.com/wp-login.php": responses_200 + [response_429],
        }
    )
    ctx = make_ctx()
    module = RateLimitModule()

    result = asyncio.run(module.run(ctx, session))

    rate_finding = [f for f in result.findings if f.id == "VULN-RATE-001"][0]
    assert rate_finding.severity == Severity.INFO
    assert result.data.get("login_rate_limit") is True
    assert result.data.get("login_rate_limit_after") == 4


def test_rate_limit_should_run_skips_bugbounty():
    """rate_limit.should_run returns False for bugbounty profile."""
    from modules.vuln.rate_limit import RateLimitModule

    module = RateLimitModule()
    ctx = make_ctx(profile="bugbounty")
    assert module.should_run(ctx) is False


def test_rate_limit_should_run_allows_standard():
    """rate_limit.should_run returns True for standard profile."""
    from modules.vuln.rate_limit import RateLimitModule

    module = RateLimitModule()
    ctx = make_ctx(profile="standard")
    assert module.should_run(ctx) is True


# ---------------------------------------------------------------------------
# XSS Scanner
# ---------------------------------------------------------------------------

def test_xss_reflected_payload():
    """Search page reflects the module's exact payload unencoded -> XSS finding."""
    from modules.vuln.xss_scanner import XSSScannerModule, XSS_PAYLOADS
    from urllib.parse import unquote

    # Echo back whatever the module sends in `?<param>=<payload>` — this models
    # a target that reflects every query param value verbatim into the body.
    session = MockSession()

    async def echo_get(url, **kwargs):
        # Extract whatever value comes after the first '=' (raw URL value),
        # url-decode it, and reflect it into the body.
        if "=" in url:
            raw = url.split("=", 1)[1]
            value = unquote(raw)
        else:
            value = ""
        return MockResponse(200,
            f'<html><body><p>Search results for: {value}</p></body></html>')

    session.get = echo_get
    ctx = make_ctx()
    module = XSSScannerModule()

    result = asyncio.run(module.run(ctx, session))

    ids = [f.id for f in result.findings]
    # First reflected payload yields VULN-XSS-001 (per-payload incrementing id)
    assert "VULN-XSS-001" in ids, f"got {ids}"
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert high_findings, "expected at least one HIGH XSS finding"


def test_xss_encoded_output():
    """Search page encodes the payload -> no XSS finding (INFO "clear" emitted)."""
    from modules.vuln.xss_scanner import XSSScannerModule

    async def safe_get(url, **kwargs):
        return MockResponse(200, "<html><body>Search results for: &lt;script&gt;alert(&quot;BZ&quot;)&lt;/script&gt;</body></html>")

    session = MockSession()
    session.get = safe_get
    ctx = make_ctx()
    module = XSSScannerModule()

    result = asyncio.run(module.run(ctx, session))

    ids = [f.id for f in result.findings]
    # Module no longer emits "VULN-XSS-001" when nothing reflects; the
    # "no XSS detected" sentinel was renamed from VULN-XSS-000 -> VULN-XSS-CLEAR
    assert not any(i.startswith("VULN-XSS-0") for i in ids), f"unexpected XSS finding: {ids}"
    assert "VULN-XSS-CLEAR" in ids
    info_finding = [f for f in result.findings if f.id == "VULN-XSS-CLEAR"][0]
    assert info_finding.severity == Severity.INFO


def test_xss_should_run_allows_bugbounty():
    """XSS scanner runs on the bugbounty profile (the most permissive)."""
    from modules.vuln.xss_scanner import XSSScannerModule

    module = XSSScannerModule()
    ctx = make_ctx(profile="bugbounty")
    assert module.should_run(ctx) is True


# ---------------------------------------------------------------------------
# SQLi Scanner
# ---------------------------------------------------------------------------

def test_sqli_error_based():
    """Response contains MySQL error pattern -> CRITICAL SQLi finding."""
    from modules.vuln.sqli_scanner import SQLiScannerModule

    error_body = '<html><body>You have an error in your SQL syntax near "\'" at line 1</body></html>'

    async def sqli_get(url, **kwargs):
        if "'" in url or "SLEEP" in url or "UNION" in url or "EXTRACTVALUE" in url or "BENCHMARK" in url or '"' in url:
            return MockResponse(200, error_body)
        return MockResponse(200, "<html>Normal search</html>")

    session = MockSession()
    session.get = sqli_get
    ctx = make_ctx()
    module = SQLiScannerModule()

    result = asyncio.run(module.run(ctx, session))

    ids = [f.id for f in result.findings]
    assert "VULN-SQLI-001" in ids
    finding = result.findings[0]
    assert finding.severity == Severity.CRITICAL


def test_sqli_no_error():
    """No SQL error in any response -> INFO finding."""
    from modules.vuln.sqli_scanner import SQLiScannerModule

    async def safe_get(url, **kwargs):
        return MockResponse(200, "<html>No results found.</html>")

    session = MockSession()
    session.get = safe_get
    ctx = make_ctx()
    module = SQLiScannerModule()

    result = asyncio.run(module.run(ctx, session))

    ids = [f.id for f in result.findings]
    # No SQL error in any response -> only the "clear" sentinel emitted (renamed
    # from VULN-SQLI-000 -> VULN-SQLI-CLEAR)
    assert not any(i.startswith("VULN-SQLI-0") for i in ids), f"unexpected SQLi finding: {ids}"
    assert "VULN-SQLI-CLEAR" in ids
    info_finding = [f for f in result.findings if f.id == "VULN-SQLI-CLEAR"][0]
    assert info_finding.severity == Severity.INFO


def test_sqli_should_run_allows_bugbounty():
    """SQLi scanner runs on the bugbounty profile (the most permissive)."""
    from modules.vuln.sqli_scanner import SQLiScannerModule

    module = SQLiScannerModule()
    ctx = make_ctx(profile="bugbounty")
    assert module.should_run(ctx) is True


# ---------------------------------------------------------------------------
# CVE Matcher
# ---------------------------------------------------------------------------

def test_cve_matcher_plugin_match():
    """Plugin contact-form-7 v5.8.1 matches CVEs from the DB."""
    from modules.vuln.cve_matcher import CVEMatcherModule

    fake_cves = [
        {
            "cve_id": "CVE-2023-6449",
            "component_type": "plugin",
            "component_slug": "contact-form-7",
            "title": "Contact Form 7 Open Redirect",
            "description": "CF7 < 5.8.4 open redirect.",
            "cvss_score": 5.4,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            "severity": "MEDIUM",
            "vuln_type": "InfoDisclosure",
            "affected_version_min": None,
            "affected_version_max": "5.8.3",
            "fixed_version": "5.8.4",
        },
        {
            "cve_id": "CVE-2024-6625",
            "component_type": "plugin",
            "component_slug": "contact-form-7",
            "title": "Contact Form 7 XSS",
            "description": "CF7 < 5.9.5 stored XSS.",
            "cvss_score": 6.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "severity": "MEDIUM",
            "vuln_type": "XSS",
            "affected_version_min": None,
            "affected_version_max": "5.9.4",
            "fixed_version": "5.9.5",
        },
    ]

    mock_db = MagicMock()
    mock_db.lookup_plugin.return_value = fake_cves
    mock_db.lookup_theme.return_value = []
    mock_db.lookup_core.return_value = []

    ctx = make_ctx()
    plugin = WPPlugin(slug="contact-form-7", version="5.8.1", discovery_method="html_passive")
    ctx.target.plugins = [plugin]
    # cve_matcher only scans plugins that are also in ctx.data["plugins_detected"]
    # (FP-guard introduced after the Elementor false-positive incident)
    ctx.set_data("plugins_detected", [{"slug": "contact-form-7", "version": "5.8.1"}])

    session = MockSession()
    module = CVEMatcherModule()

    with patch("cve_db.manager.get_db", return_value=mock_db):
        result = asyncio.run(module.run(ctx, session))

    cve_ids = [f.title.split(" ")[0] for f in result.findings if f.id.startswith("VULN-CVE-")]
    # Both CVEs affect 5.8.1 (5.8.1 <= 5.8.3, 5.8.1 <= 5.9.4)
    assert "CVE-2023-6449" in cve_ids
    assert "CVE-2024-6625" in cve_ids
    # Total >= 2 because the module also queries the embedded prewarm cache
    # (wpvulnerability.net) which has additional contact-form-7 CVEs.
    assert result.data.get("cve_matches_total", 0) >= 2


def test_cve_matcher_no_match():
    """No CVEs found -> INFO finding about no matches."""
    from modules.vuln.cve_matcher import CVEMatcherModule

    mock_db = MagicMock()
    mock_db.lookup_plugin.return_value = []
    mock_db.lookup_theme.return_value = []
    mock_db.lookup_core.return_value = []

    ctx = make_ctx()
    ctx.target.plugins = [WPPlugin(slug="some-plugin", version="99.0")]

    session = MockSession()
    module = CVEMatcherModule()

    with patch("cve_db.manager.get_db", return_value=mock_db):
        result = asyncio.run(module.run(ctx, session))

    ids = [f.id for f in result.findings]
    assert "VULN-CVE-000" in ids  # no CVE found info


def test_cve_matcher_version_not_affected():
    """Plugin version is NEWER than affected range -> CVE skipped."""
    from modules.vuln.cve_matcher import CVEMatcherModule

    fake_cve = [{
        "cve_id": "CVE-2024-9999",
        "component_type": "plugin",
        "component_slug": "test-plugin",
        "title": "Test CVE",
        "description": "Test",
        "cvss_score": 7.0,
        "cvss_vector": "",
        "severity": "HIGH",
        "vuln_type": "XSS",
        "affected_version_min": None,
        "affected_version_max": "2.0.0",
        "fixed_version": "2.0.1",
    }]

    mock_db = MagicMock()
    mock_db.lookup_plugin.return_value = fake_cve
    mock_db.lookup_theme.return_value = []
    mock_db.lookup_core.return_value = []

    ctx = make_ctx()
    # Plugin is at version 3.0.0, above affected_version_max 2.0.0
    ctx.target.plugins = [WPPlugin(slug="test-plugin", version="3.0.0")]

    session = MockSession()
    module = CVEMatcherModule()

    with patch("cve_db.manager.get_db", return_value=mock_db):
        result = asyncio.run(module.run(ctx, session))

    # The CVE should be skipped (version 3.0.0 > 2.0.0)
    ids = [f.id for f in result.findings]
    assert "VULN-CVE-000" in ids  # "no CVEs found" info
    assert result.data.get("cve_matches_total") is None


# ---------------------------------------------------------------------------
# Session Auth
# ---------------------------------------------------------------------------

def test_session_auth_missing_httponly():
    """Set-Cookie without HttpOnly flag -> VULN-SESS-001 finding."""
    from modules.vuln.session_auth import SessionAuthModule

    cookie_headers = _MultiHeaders.from_pairs([
        ("Content-Type", "text/html"),
        ("set-cookie", "wordpress_test_cookie=WP+Cookie+check; path=/; Secure; SameSite=Lax"),
    ])
    login_resp = MockResponse(200, "<html><form>login form</form></html>")
    login_resp.headers = cookie_headers

    # For user enumeration part, return generic error messages
    login_post_resp = MockResponse(200, "<html>ERROR: generic error</html>")

    session = MockSession({
        "https://test.com/wp-login.php": login_resp,
    })
    session.post = lambda url, **kw: _async_return(login_post_resp)

    ctx = make_ctx()
    module = SessionAuthModule()

    result = asyncio.run(module.run(ctx, session))

    ids = [f.id for f in result.findings]
    assert "VULN-SESS-001" in ids
    finding = [f for f in result.findings if f.id == "VULN-SESS-001"][0]
    assert finding.severity == Severity.MEDIUM
    assert "HttpOnly" in finding.description


def test_session_auth_all_flags_present():
    """Set-Cookie with all security flags -> no VULN-SESS-001 finding."""
    from modules.vuln.session_auth import SessionAuthModule

    cookie_headers = _MultiHeaders.from_pairs([
        ("Content-Type", "text/html"),
        ("set-cookie", "wordpress_test_cookie=check; path=/; HttpOnly; Secure; SameSite=Lax"),
    ])
    login_resp = MockResponse(200, "<html><form>login form</form></html>")
    login_resp.headers = cookie_headers

    login_post_resp = MockResponse(200, "<html>ERROR: generic error</html>")

    session = MockSession({
        "https://test.com/wp-login.php": login_resp,
    })
    session.post = lambda url, **kw: _async_return(login_post_resp)

    ctx = make_ctx()
    module = SessionAuthModule()

    result = asyncio.run(module.run(ctx, session))

    ids = [f.id for f in result.findings]
    assert "VULN-SESS-001" not in ids


def test_session_auth_user_enumeration():
    """Different error messages for fake vs real user -> VULN-SESS-002."""
    from modules.vuln.session_auth import SessionAuthModule

    cookie_headers = _MultiHeaders.from_pairs([
        ("set-cookie", "wp_cookie=test; HttpOnly; Secure; SameSite=Lax"),
    ])
    login_resp = MockResponse(200, "<html><form>login</form></html>")
    login_resp.headers = cookie_headers

    # Track which user is being tested
    post_count = {"n": 0}

    async def login_post(url, **kwargs):
        post_count["n"] += 1
        data = kwargs.get("data", {})
        username = data.get("log", "")
        if "nonexistent" in username or "bz_" in username:
            return MockResponse(200, "<html>ERROR: Invalid username. <a>Lost your password?</a></html>")
        else:
            return MockResponse(200, "<html>ERROR: The password you entered for the username admin is incorrect.</html>")

    session = MockSession({"https://test.com/wp-login.php": login_resp})
    session.post = login_post

    ctx = make_ctx()
    module = SessionAuthModule()

    result = asyncio.run(module.run(ctx, session))

    ids = [f.id for f in result.findings]
    assert "VULN-SESS-002" in ids
    finding = [f for f in result.findings if f.id == "VULN-SESS-002"][0]
    assert finding.severity == Severity.MEDIUM


def test_session_auth_no_user_enumeration():
    """Same generic error for both users -> no VULN-SESS-002."""
    from modules.vuln.session_auth import SessionAuthModule

    cookie_headers = _MultiHeaders.from_pairs([
        ("set-cookie", "wp_cookie=test; HttpOnly; Secure; SameSite=Lax"),
    ])
    login_resp = MockResponse(200, "<html><form>login</form></html>")
    login_resp.headers = cookie_headers

    async def generic_post(url, **kwargs):
        return MockResponse(200, "<html>ERROR: Identifiant ou mot de passe incorrect.</html>")

    session = MockSession({"https://test.com/wp-login.php": login_resp})
    session.post = generic_post

    ctx = make_ctx()
    module = SessionAuthModule()

    result = asyncio.run(module.run(ctx, session))

    ids = [f.id for f in result.findings]
    assert "VULN-SESS-002" not in ids


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

async def _async_return(value):
    return value
