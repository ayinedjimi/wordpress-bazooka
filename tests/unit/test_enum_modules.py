"""Tests for enum modules — wp_version, wp_users, wp_plugins, backup_finder,
debug_log, xmlrpc_methods, rest_api."""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.models import Target, Severity, WPPlugin
from core.engine import ScanContext
from modules.base import ModuleResult


# ---------------------------------------------------------------------------
# Helpers  (shared mock infrastructure)
# ---------------------------------------------------------------------------

class MockResponse:
    """Fake HTTP response object."""

    def __init__(self, status_code=200, text="", headers=None, content=None, json_data=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.content = content if content is not None else text.encode("utf-8", errors="replace")
        self._json_data = json_data

    def json(self):
        if self._json_data is not None:
            return self._json_data
        return json.loads(self.text)


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


def make_ctx(url="https://test.com", domain="test.com", profile="standard"):
    target = Target(url=url, domain=domain)
    ctx = ScanContext(target)
    ctx.profile = profile
    return ctx


# ---------------------------------------------------------------------------
# WP Version
# ---------------------------------------------------------------------------

def test_wp_version_meta_generator():
    """Meta generator tag with WordPress version -> version detected."""
    from modules.enum.wp_version import WPVersionModule

    homepage = '<html><head><meta name="generator" content="WordPress 6.4.3" /></head></html>'
    session = MockSession({
        "https://test.com": MockResponse(200, homepage),
    })
    ctx = make_ctx()
    module = WPVersionModule()

    result = asyncio.run(module.run(ctx, session))

    assert result.data.get("wp_version") == "6.4.3"
    assert ctx.target.wp_version == "6.4.3"
    ids = [f.id for f in result.findings]
    assert "ENUM-VER-001" in ids
    ver_finding = [f for f in result.findings if f.id == "ENUM-VER-001"][0]
    assert "6.4.3" in ver_finding.title


def test_wp_version_readme_fallback():
    """No meta generator but readme.html has version -> version detected via readme."""
    from modules.enum.wp_version import WPVersionModule

    homepage = "<html><head><title>Test</title></head></html>"
    readme = "<html><body>WordPress — Version 6.3.2</body></html>"
    session = MockSession({
        "https://test.com": MockResponse(200, homepage),
        "https://test.com/readme.html": MockResponse(200, readme),
    })
    ctx = make_ctx()
    module = WPVersionModule()

    result = asyncio.run(module.run(ctx, session))

    assert result.data.get("wp_version") == "6.3.2"


def test_wp_version_rss_feed():
    """RSS feed contains generator URL with version."""
    from modules.enum.wp_version import WPVersionModule

    homepage = "<html></html>"
    feed = '<rss><channel><generator>https://wordpress.org/?v=6.5.0</generator></channel></rss>'
    session = MockSession({
        "https://test.com": MockResponse(200, homepage),
        "https://test.com/feed/": MockResponse(200, feed),
    })
    ctx = make_ctx()
    module = WPVersionModule()

    result = asyncio.run(module.run(ctx, session))

    assert result.data.get("wp_version") == "6.5.0"


def test_wp_version_not_found():
    """No version found anywhere -> wp_version = None."""
    from modules.enum.wp_version import WPVersionModule

    session = MockSession()
    ctx = make_ctx()
    module = WPVersionModule()

    result = asyncio.run(module.run(ctx, session))

    assert result.data.get("wp_version") is None
    assert ctx.target.wp_version is None
    assert len(result.findings) == 0


def test_wp_version_css_js_ver():
    """Multiple ?ver= strings -> most common version picked."""
    from modules.enum.wp_version import WPVersionModule

    homepage = (
        '<link rel="stylesheet" href="/style.css?ver=6.4.3">'
        '<script src="/script.js?ver=6.4.3"></script>'
        '<script src="/other.js?ver=2.1.0"></script>'
    )
    session = MockSession({
        "https://test.com": MockResponse(200, homepage),
    })
    ctx = make_ctx()
    module = WPVersionModule()

    result = asyncio.run(module.run(ctx, session))

    assert result.data.get("wp_version") == "6.4.3"


# ---------------------------------------------------------------------------
# WP Users
# ---------------------------------------------------------------------------

def test_wp_users_rest_api_two_users():
    """REST API returns 2 users -> ctx.target.users populated."""
    from modules.enum.wp_users import WPUsersModule

    users_json = [
        {"id": 1, "slug": "admin", "name": "Administrator", "avatar_urls": {"24": "https://gravatar.com/avatar/abc123"}},
        {"id": 2, "slug": "editor", "name": "Editor User", "avatar_urls": {}},
    ]
    session = MockSession({
        "https://test.com/wp-json/wp/v2/users": MockResponse(200, json.dumps(users_json), json_data=users_json),
    })
    ctx = make_ctx(profile="quick")  # quick -> skip author archive, sitemap
    module = WPUsersModule()

    result = asyncio.run(module.run(ctx, session))

    assert len(ctx.target.users) == 2
    assert ctx.target.users[0].username == "admin"
    assert ctx.target.users[1].username == "editor"
    ids = [f.id for f in result.findings]
    assert "ENUM-USR-001" in ids


def test_wp_users_rest_api_401():
    """REST API returns 401 -> no users found."""
    from modules.enum.wp_users import WPUsersModule

    session = MockSession({
        "https://test.com/wp-json/wp/v2/users": MockResponse(401, '{"code":"rest_not_logged_in"}'),
    })
    ctx = make_ctx(profile="quick")
    module = WPUsersModule()

    result = asyncio.run(module.run(ctx, session))

    assert len(ctx.target.users) == 0
    assert len(result.findings) == 0


def test_wp_users_email_exposure():
    """REST API exposes emails -> CRITICAL finding ENUM-USR-002."""
    from modules.enum.wp_users import WPUsersModule

    users_json = [
        {"id": 1, "slug": "admin", "name": "Admin", "avatar_urls": {}},
    ]
    users_fields_json = [
        {"id": 1, "slug": "admin", "name": "Admin", "email": "admin@test.com"},
    ]
    session = MockSession({
        "https://test.com/wp-json/wp/v2/users": MockResponse(200, json.dumps(users_json), json_data=users_json),
        "https://test.com/wp-json/wp/v2/users?_fields=id,slug,name,email": MockResponse(200, json.dumps(users_fields_json), json_data=users_fields_json),
    })
    ctx = make_ctx(profile="standard")
    module = WPUsersModule()

    result = asyncio.run(module.run(ctx, session))

    ids = [f.id for f in result.findings]
    assert "ENUM-USR-002" in ids
    email_finding = [f for f in result.findings if f.id == "ENUM-USR-002"][0]
    assert email_finding.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# WP Plugins
# ---------------------------------------------------------------------------

def test_wp_plugins_passive_html_detection():
    """Homepage HTML references two plugin slugs -> 2 plugins detected."""
    from modules.enum.wp_plugins import WPPluginsModule

    homepage = """<html>
    <link rel="stylesheet" href="/wp-content/plugins/contact-form-7/assets/style.css">
    <script src="/wp-content/plugins/elementor/assets/js/frontend.js"></script>
    </html>"""
    session = MockSession({
        "https://test.com": MockResponse(200, homepage),
    })
    ctx = make_ctx()
    module = WPPluginsModule()

    result = asyncio.run(module.run(ctx, session))

    slugs = [p.slug for p in ctx.target.plugins]
    assert "contact-form-7" in slugs
    assert "elementor" in slugs
    assert len(ctx.target.plugins) == 2
    ids = [f.id for f in result.findings]
    assert "ENUM-PLG-001" in ids


def test_wp_plugins_readme_version_extraction():
    """Plugin readme.txt with Stable tag -> version extracted."""
    from modules.enum.wp_plugins import WPPluginsModule

    homepage = '<link href="/wp-content/plugins/contact-form-7/style.css">'
    readme = """=== Contact Form 7 ===
Contributors: takayukister
Stable tag: 5.8.1
Requires at least: 6.0
"""
    session = MockSession({
        "https://test.com": MockResponse(200, homepage),
        "https://test.com/wp-content/plugins/contact-form-7/readme.txt": MockResponse(200, readme),
    })
    ctx = make_ctx()
    module = WPPluginsModule()

    result = asyncio.run(module.run(ctx, session))

    cf7 = [p for p in ctx.target.plugins if p.slug == "contact-form-7"]
    assert len(cf7) == 1
    assert cf7[0].version == "5.8.1"
    assert cf7[0].name == "Contact Form 7"


def test_wp_plugins_no_plugins():
    """Homepage with no plugin references -> empty list."""
    from modules.enum.wp_plugins import WPPluginsModule

    session = MockSession({
        "https://test.com": MockResponse(200, "<html><body>Hello</body></html>"),
    })
    ctx = make_ctx()
    module = WPPluginsModule()

    result = asyncio.run(module.run(ctx, session))

    assert len(ctx.target.plugins) == 0
    assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# Backup Finder
# ---------------------------------------------------------------------------

def test_backup_finder_200_with_signature():
    """200 response with matching content signature -> finding generated."""
    from modules.enum.backup_finder import BackupFinderModule

    git_head_content = "ref: refs/heads/main\n"
    session = MockSession(
        responses={
            "https://test.com/.git/HEAD": MockResponse(200, git_head_content),
        },
        # Calibration paths all return genuine 404
        default_response=MockResponse(404, "Page not found — this is a standard 404 page."),
    )
    ctx = make_ctx()
    module = BackupFinderModule()

    result = asyncio.run(module.run(ctx, session))

    # Should detect .git/HEAD
    titles = [f.title for f in result.findings]
    git_findings = [t for t in titles if ".git" in t.lower()]
    assert len(git_findings) >= 1, f"Expected git finding, got: {titles}"


def test_backup_finder_200_without_signature():
    """200 response WITHOUT matching content -> no finding (WAF/custom 200 page)."""
    from modules.enum.backup_finder import BackupFinderModule

    # .env returns 200 but body is a generic page, not real .env content
    generic_page = "<html><body>Welcome to our site!</body></html>"
    session = MockSession(
        responses={
            "https://test.com/.env": MockResponse(200, generic_page),
        },
        default_response=MockResponse(404, "Not Found"),
    )
    ctx = make_ctx()
    module = BackupFinderModule()

    result = asyncio.run(module.run(ctx, session))

    # .env finding should NOT appear (no signature match)
    env_findings = [f for f in result.findings if ".env" in f.title and ".wp-env" not in f.title]
    assert len(env_findings) == 0, f"Should not flag .env without signature, got: {[f.title for f in env_findings]}"


def test_backup_finder_404_no_finding():
    """All paths return 404 -> no findings."""
    from modules.enum.backup_finder import BackupFinderModule

    session = MockSession(
        default_response=MockResponse(404, "Not Found"),
    )
    ctx = make_ctx()
    module = BackupFinderModule()

    result = asyncio.run(module.run(ctx, session))

    assert len(result.findings) == 0


def test_backup_finder_xmlrpc_405():
    """xmlrpc.php returns 405 -> finding generated (exists but GET not allowed)."""
    from modules.enum.backup_finder import BackupFinderModule

    session = MockSession(
        responses={
            "https://test.com/xmlrpc.php": MockResponse(405, "XML-RPC server accepts POST requests only"),
        },
        default_response=MockResponse(404, "Not Found"),
    )
    ctx = make_ctx()
    module = BackupFinderModule()

    result = asyncio.run(module.run(ctx, session))

    xmlrpc_findings = [f for f in result.findings if "xmlrpc" in f.title.lower() or "xml-rpc" in f.title.lower()]
    assert len(xmlrpc_findings) >= 1


# ---------------------------------------------------------------------------
# Debug Log
# ---------------------------------------------------------------------------

def test_debug_log_accessible_with_secrets():
    """debug.log accessible with PHP warnings and SMTP password -> secrets found."""
    from modules.enum.debug_log import DebugLogModule

    debug_content = """[25-Dec-2025 10:00:00 UTC] PHP Warning: Undefined variable $foo in /var/www/html/wp-content/plugins/test.php on line 42
[25-Dec-2025 10:01:00 UTC] SMTP password = "S3cretP@ss"
[25-Dec-2025 10:02:00 UTC] PHP Notice: Trying to get property of non-object in /home/user/public_html/test.php
"""
    session = MockSession({
        "https://test.com/wp-content/debug.log": MockResponse(200, debug_content),
    })
    ctx = make_ctx()
    module = DebugLogModule()

    result = asyncio.run(module.run(ctx, session))

    assert result.data.get("debug_log_accessible") is True
    ids = [f.id for f in result.findings]
    assert "ENUM-DBG-001" in ids  # debug.log accessible
    # Should have found SMTP password
    secret_findings = [f for f in result.findings if "SMTP" in f.title]
    assert len(secret_findings) >= 1


def test_debug_log_404():
    """debug.log returns 404 -> no findings."""
    from modules.enum.debug_log import DebugLogModule

    session = MockSession({
        "https://test.com/wp-content/debug.log": MockResponse(404, "Not Found"),
    })
    ctx = make_ctx()
    module = DebugLogModule()

    result = asyncio.run(module.run(ctx, session))

    assert result.data.get("debug_log_accessible") is False
    assert len(result.findings) == 0


def test_debug_log_200_but_not_real_log():
    """debug.log returns 200 but body is not a real log -> no findings."""
    from modules.enum.debug_log import DebugLogModule

    session = MockSession({
        "https://test.com/wp-content/debug.log": MockResponse(200, "<html>WAF block page</html>"),
    })
    ctx = make_ctx()
    module = DebugLogModule()

    result = asyncio.run(module.run(ctx, session))

    assert len(result.findings) == 0


def test_debug_log_server_paths():
    """debug.log with server paths -> paths extracted to data."""
    from modules.enum.debug_log import DebugLogModule

    debug_content = """[25-Dec-2025] PHP Warning: Something in /var/www/html/wp-includes/functions.php on line 100
[25-Dec-2025] PHP Notice: test in /home/wpuser/public_html/wp-content/plugins/foo.php on line 5
"""
    session = MockSession({
        "https://test.com/wp-content/debug.log": MockResponse(200, debug_content),
    })
    ctx = make_ctx()
    module = DebugLogModule()

    result = asyncio.run(module.run(ctx, session))

    assert result.data.get("debug_log_server_path") is not None or result.data.get("debug_log_home_directory") is not None


# ---------------------------------------------------------------------------
# XML-RPC Methods
# ---------------------------------------------------------------------------

def test_xmlrpc_methods_enumeration():
    """POST to xmlrpc.php returns 80 methods including system.multicall -> findings."""
    from modules.enum.xmlrpc_methods import XMLRPCMethodsModule

    # Build XML response with 80 methods
    method_names = [f"wp.method{i}" for i in range(77)]
    method_names += ["system.multicall", "system.listMethods", "pingback.ping"]
    method_xml = "".join(f"<value><string>{m}</string></value>" for m in method_names)
    xmlrpc_response = f"""<?xml version="1.0"?>
<methodResponse><params><param><value><array><data>
{method_xml}
</data></array></value></param></params></methodResponse>"""

    multicall_response = """<?xml version="1.0"?>
<methodResponse><params><param><value><array><data>
<value><array><data><value><array><data>
<value><string>method1</string></value>
</data></array></value></data></array></value>
</data></array></value></param></params></methodResponse>"""

    session = MockSession({
        "https://test.com/xmlrpc.php": MockResponse(200, xmlrpc_response),
    })
    # Override post to also return multicall response for second call
    call_count = {"n": 0}
    original_post = session.post

    async def smart_post(url, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return MockResponse(200, xmlrpc_response)
        return MockResponse(200, multicall_response)

    session.post = smart_post

    ctx = make_ctx()
    module = XMLRPCMethodsModule()

    result = asyncio.run(module.run(ctx, session))

    assert result.data.get("xmlrpc_accessible") is True
    assert result.data.get("xmlrpc_method_count") == 80
    ids = [f.id for f in result.findings]
    assert "ENUM-RPC-001" in ids  # methods exposed
    assert "ENUM-RPC-002" in ids  # multicall active
    assert "ENUM-RPC-003" in ids  # pingback SSRF


def test_xmlrpc_methods_not_accessible():
    """xmlrpc.php returns 403 -> not accessible."""
    from modules.enum.xmlrpc_methods import XMLRPCMethodsModule

    session = MockSession(default_response=MockResponse(403, "Forbidden"))
    ctx = make_ctx()
    module = XMLRPCMethodsModule()

    result = asyncio.run(module.run(ctx, session))

    assert result.data.get("xmlrpc_accessible") is False
    assert len(result.findings) == 0


def test_xmlrpc_methods_no_multicall():
    """XML-RPC accessible but system.multicall NOT in methods -> no ENUM-RPC-002."""
    from modules.enum.xmlrpc_methods import XMLRPCMethodsModule

    method_names = ["wp.getUsersBlogs", "wp.getPost", "system.listMethods"]
    method_xml = "".join(f"<value><string>{m}</string></value>" for m in method_names)
    xmlrpc_response = f"""<?xml version="1.0"?>
<methodResponse><params><param><value><array><data>
{method_xml}
</data></array></value></param></params></methodResponse>"""

    session = MockSession()

    async def _post(url, **kw):
        return MockResponse(200, xmlrpc_response)

    session.post = _post

    ctx = make_ctx()
    module = XMLRPCMethodsModule()

    result = asyncio.run(module.run(ctx, session))

    ids = [f.id for f in result.findings]
    assert "ENUM-RPC-001" in ids
    assert "ENUM-RPC-002" not in ids


# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------

def test_rest_api_full_enumeration():
    """REST API root returns namespaces and routes, posts return data."""
    from modules.enum.rest_api import RestAPIModule

    root_json = {
        "namespaces": ["wp/v2", "contact-form-7/v1"],
        "routes": {"/": {}, "/wp/v2/posts": {}, "/wp/v2/pages": {}, "/wp/v2/media": {}},
    }
    posts_json = [{"id": 1, "title": {"rendered": "Hello"}}, {"id": 2, "title": {"rendered": "World"}}]
    pages_json = [{"id": 10, "title": {"rendered": "About"}}]
    media_json = []
    comments_json = []

    session = MockSession({
        "https://test.com/wp-json/": MockResponse(200, json.dumps(root_json), json_data=root_json, headers={}),
        "https://test.com/wp-json/wp/v2/posts?per_page=100": MockResponse(200, json.dumps(posts_json), json_data=posts_json, headers={"X-WP-Total": "2"}),
        "https://test.com/wp-json/wp/v2/pages?per_page=100": MockResponse(200, json.dumps(pages_json), json_data=pages_json, headers={"X-WP-Total": "1"}),
        "https://test.com/wp-json/wp/v2/media?per_page=100": MockResponse(200, json.dumps(media_json), json_data=media_json, headers={"X-WP-Total": "0"}),
        "https://test.com/wp-json/wp/v2/comments?per_page=20": MockResponse(200, json.dumps(comments_json), json_data=comments_json),
        "https://test.com/wp-json/wp/v2/posts?status=draft": MockResponse(401, ""),
        "https://test.com/wp-json/wp/v2/posts?status=private": MockResponse(401, ""),
        "https://test.com/wp-json/wp/v2/settings": MockResponse(401, ""),
    })
    ctx = make_ctx()
    module = RestAPIModule()

    result = asyncio.run(module.run(ctx, session))

    assert result.data["rest_api_root"]["route_count"] == 4
    assert result.data["rest_api_root"]["namespaces"] == ["wp/v2", "contact-form-7/v1"]
    assert result.data.get("posts_count") == 2
    assert result.data.get("pages_count") == 1

    ids = [f.id for f in result.findings]
    assert "ENUM-API-001" in ids
    assert "ENUM-API-002" in ids


def test_rest_api_not_available():
    """REST API root returns 404 -> partial status."""
    from modules.enum.rest_api import RestAPIModule

    session = MockSession()
    ctx = make_ctx()
    module = RestAPIModule()

    result = asyncio.run(module.run(ctx, session))

    assert result.status == "partial"
    assert len(result.findings) == 0


def test_rest_api_exposed_drafts():
    """Drafts accessible without auth -> CRITICAL finding."""
    from modules.enum.rest_api import RestAPIModule

    root_json = {"namespaces": ["wp/v2"], "routes": {"/": {}, "/wp/v2/posts": {}}}
    drafts_json = [{"id": 99, "title": {"rendered": "Secret Draft"}}]

    session = MockSession({
        "https://test.com/wp-json/": MockResponse(200, json.dumps(root_json), json_data=root_json),
        "https://test.com/wp-json/wp/v2/posts?per_page=100": MockResponse(200, "[]", json_data=[]),
        "https://test.com/wp-json/wp/v2/pages?per_page=100": MockResponse(200, "[]", json_data=[]),
        "https://test.com/wp-json/wp/v2/media?per_page=100": MockResponse(200, "[]", json_data=[]),
        "https://test.com/wp-json/wp/v2/comments?per_page=20": MockResponse(200, "[]", json_data=[]),
        "https://test.com/wp-json/wp/v2/posts?status=draft": MockResponse(200, json.dumps(drafts_json), json_data=drafts_json),
        "https://test.com/wp-json/wp/v2/posts?status=private": MockResponse(401, ""),
        "https://test.com/wp-json/wp/v2/settings": MockResponse(401, ""),
    })
    ctx = make_ctx()
    module = RestAPIModule()

    result = asyncio.run(module.run(ctx, session))

    ids = [f.id for f in result.findings]
    assert "ENUM-API-005-draft" in ids
    draft_finding = [f for f in result.findings if f.id == "ENUM-API-005-draft"][0]
    assert draft_finding.severity == Severity.CRITICAL
