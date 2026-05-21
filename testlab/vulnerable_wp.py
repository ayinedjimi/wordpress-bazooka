#!/usr/bin/env python3
"""
Vulnerable WordPress Test Server
=================================
A lightweight simulated WordPress installation with intentional vulnerabilities
for testing the BAZOOKA scanner. Runs on Python stdlib only (http.server).

Usage:
    python testlab/vulnerable_wp.py

Listens on http://127.0.0.1:8888
"""

import json
import time
import hashlib
import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

HOST = "127.0.0.1"
PORT = 8888
WP_VERSION = "6.4.3"
SERVER_HEADER = "Apache/2.4.54"
PHP_HEADER = "PHP/8.1.2"

# ---------------------------------------------------------------------------
# Static response payloads
# ---------------------------------------------------------------------------

HOME_PAGE_HTML = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="WordPress {WP_VERSION}" />
<title>Vulnerable Test Site &#8211; Just another WordPress site</title>
<link rel="stylesheet" href="/wp-content/themes/flavor/style.css?ver=1.2" type="text/css" />
<link rel="alternate" type="application/rss+xml" title="Feed" href="/feed/" />
<link rel="https://api.w.org/" href="/wp-json/" />
<link rel="pingback" href="/xmlrpc.php" />
</head>
<body class="home blog">
<header id="masthead" class="site-header">
  <h1 class="site-title"><a href="/">Vulnerable Test Site</a></h1>
  <p class="site-description">Just another WordPress site</p>
</header>
<div id="content" class="site-content">
  <article id="post-10" class="post">
    <h2 class="entry-title"><a href="/2024/12/hello-world/">Hello world!</a></h2>
    <div class="entry-content"><p>Welcome to WordPress. This is your first post.</p></div>
  </article>
</div>
<footer id="colophon" class="site-footer">
  <p>Powered by <a href="https://wordpress.org/">WordPress</a></p>
  <!-- Theme: flavor v1.2 -->
</footer>
<!-- plugins active: contact-form-7, elementor, updraftplus, wpml-sitepress-multilingual-cms, woocommerce -->
<script src="/wp-content/plugins/contact-form-7/includes/js/scripts.js?ver=5.8.1"></script>
<script src="/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=3.18.0"></script>
<script src="/wp-includes/js/wp-embed.min.js?ver={WP_VERSION}"></script>
<link rel="stylesheet" href="/wp-content/plugins/woocommerce/assets/css/woocommerce.css?ver=8.4.0" />
<link rel="stylesheet" href="/wp-content/plugins/wpml-sitepress-multilingual-cms/res/css/language-selector.css?ver=4.6.8" />
<script src="/wp-content/plugins/updraftplus/js/updraftplus.js?ver=1.24.1"></script>
</body>
</html>"""

WP_JSON_INDEX = {
    "name": "Vulnerable Test Site",
    "description": "Just another WordPress site",
    "url": f"http://{HOST}:{PORT}",
    "home": f"http://{HOST}:{PORT}",
    "gmt_offset": "0",
    "timezone_string": "UTC",
    "namespaces": [
        "oembed/1.0",
        "wp/v2",
        "wp-site-health/v1",
        "contact-form-7/v1",
        "elementor/v1",
        "wc/v3",
        "wpml/tm/v1"
    ],
    "authentication": {
        "application-passwords": {
            "endpoints": {
                "authorization": f"http://{HOST}:{PORT}/wp-admin/authorize-application.php"
            }
        }
    },
    "routes": {
        "/wp/v2/users": {"methods": ["GET"], "endpoints": [{"methods": ["GET"]}]},
        "/wp/v2/posts": {"methods": ["GET"], "endpoints": [{"methods": ["GET"]}]},
        "/wp/v2/pages": {"methods": ["GET"], "endpoints": [{"methods": ["GET"]}]},
        "/wp/v2/media": {"methods": ["GET"], "endpoints": [{"methods": ["GET"]}]},
        "/wp/v2/categories": {"methods": ["GET"], "endpoints": [{"methods": ["GET"]}]},
        "/wp/v2/tags": {"methods": ["GET"], "endpoints": [{"methods": ["GET"]}]},
        "/contact-form-7/v1/contact-forms": {"methods": ["GET"], "endpoints": [{"methods": ["GET"]}]},
    },
    "_links": {"self": [{"href": f"http://{HOST}:{PORT}/wp-json/"}]},
}


def _gravatar(email: str) -> str:
    h = hashlib.md5(email.lower().strip().encode()).hexdigest()
    return f"https://secure.gravatar.com/avatar/{h}?s=96&d=mm&r=g"


WP_USERS = [
    {
        "id": 1,
        "name": "admin",
        "url": f"http://{HOST}:{PORT}",
        "description": "Site Administrator",
        "link": f"http://{HOST}:{PORT}/author/admin/",
        "slug": "admin",
        "avatar_urls": {
            "24": _gravatar("admin@vulnerable-test.local"),
            "48": _gravatar("admin@vulnerable-test.local"),
            "96": _gravatar("admin@vulnerable-test.local"),
        },
        "meta": [],
        "_links": {
            "self": [{"href": f"http://{HOST}:{PORT}/wp-json/wp/v2/users/1"}],
            "collection": [{"href": f"http://{HOST}:{PORT}/wp-json/wp/v2/users"}],
        },
    },
    {
        "id": 2,
        "name": "editor",
        "url": "",
        "description": "Content Editor",
        "link": f"http://{HOST}:{PORT}/author/editor/",
        "slug": "editor",
        "avatar_urls": {
            "24": _gravatar("editor@vulnerable-test.local"),
            "48": _gravatar("editor@vulnerable-test.local"),
            "96": _gravatar("editor@vulnerable-test.local"),
        },
        "meta": [],
        "_links": {
            "self": [{"href": f"http://{HOST}:{PORT}/wp-json/wp/v2/users/2"}],
            "collection": [{"href": f"http://{HOST}:{PORT}/wp-json/wp/v2/users"}],
        },
    },
    {
        "id": 3,
        "name": "author",
        "url": "",
        "description": "Blog Author",
        "link": f"http://{HOST}:{PORT}/author/author/",
        "slug": "author",
        "avatar_urls": {
            "24": _gravatar("author@vulnerable-test.local"),
            "48": _gravatar("author@vulnerable-test.local"),
            "96": _gravatar("author@vulnerable-test.local"),
        },
        "meta": [],
        "_links": {
            "self": [{"href": f"http://{HOST}:{PORT}/wp-json/wp/v2/users/3"}],
            "collection": [{"href": f"http://{HOST}:{PORT}/wp-json/wp/v2/users"}],
        },
    },
]


def _make_post(pid, title, slug, author_id, date_str):
    return {
        "id": pid,
        "date": date_str,
        "date_gmt": date_str,
        "guid": {"rendered": f"http://{HOST}:{PORT}/?p={pid}"},
        "modified": date_str,
        "modified_gmt": date_str,
        "slug": slug,
        "status": "publish",
        "type": "post",
        "link": f"http://{HOST}:{PORT}/{slug}/",
        "title": {"rendered": title},
        "content": {"rendered": f"<p>Content of {title}.</p>", "protected": False},
        "excerpt": {"rendered": f"<p>Excerpt of {title}.</p>", "protected": False},
        "author": author_id,
        "featured_media": 0,
        "comment_status": "open",
        "ping_status": "open",
        "sticky": False,
        "template": "",
        "format": "standard",
        "meta": [],
        "categories": [1],
        "tags": [],
    }


WP_POSTS = [
    _make_post(10, "Hello world!", "hello-world", 1, "2024-12-15T10:00:00"),
    _make_post(15, "Getting Started with Security", "getting-started-security", 1, "2025-01-20T14:30:00"),
    _make_post(20, "Plugin Recommendations", "plugin-recommendations", 2, "2025-03-10T09:15:00"),
    _make_post(25, "Site Update March 2025", "site-update-march-2025", 2, "2025-03-25T16:45:00"),
    _make_post(30, "New Features Coming Soon", "new-features-coming-soon", 3, "2026-01-05T11:00:00"),
]


def _make_page(pid, title, slug):
    return {
        "id": pid,
        "date": "2024-12-01T08:00:00",
        "date_gmt": "2024-12-01T08:00:00",
        "guid": {"rendered": f"http://{HOST}:{PORT}/?page_id={pid}"},
        "slug": slug,
        "status": "publish",
        "type": "page",
        "link": f"http://{HOST}:{PORT}/{slug}/",
        "title": {"rendered": title},
        "content": {"rendered": f"<p>This is the {title} page.</p>", "protected": False},
        "author": 1,
        "parent": 0,
        "menu_order": 0,
        "template": "",
        "meta": [],
    }


WP_PAGES = [
    _make_page(2, "Sample Page", "sample-page"),
    _make_page(5, "About", "about"),
    _make_page(7, "Contact", "contact"),
]

WP_MEDIA = [
    {
        "id": 50,
        "date": "2025-01-15T12:00:00",
        "slug": "company-report",
        "status": "inherit",
        "type": "attachment",
        "link": f"http://{HOST}:{PORT}/company-report/",
        "title": {"rendered": "Company Report 2024"},
        "author": 1,
        "media_type": "file",
        "mime_type": "application/pdf",
        "source_url": f"http://{HOST}:{PORT}/wp-content/uploads/2025/01/company-report-2024.pdf",
        "media_details": {"file": "2025/01/company-report-2024.pdf"},
    },
    {
        "id": 51,
        "date": "2025-06-10T09:30:00",
        "slug": "banner-image",
        "status": "inherit",
        "type": "attachment",
        "link": f"http://{HOST}:{PORT}/banner-image/",
        "title": {"rendered": "Banner Image"},
        "author": 2,
        "media_type": "image",
        "mime_type": "image/jpeg",
        "source_url": f"http://{HOST}:{PORT}/wp-content/uploads/2025/06/banner.jpg",
        "media_details": {
            "width": 1920,
            "height": 600,
            "file": "2025/06/banner.jpg",
            "sizes": {
                "thumbnail": {
                    "file": "banner-150x150.jpg",
                    "width": 150,
                    "height": 150,
                    "source_url": f"http://{HOST}:{PORT}/wp-content/uploads/2025/06/banner-150x150.jpg",
                },
            },
        },
    },
    {
        "id": 52,
        "date": "2026-02-20T14:00:00",
        "slug": "internal-memo",
        "status": "inherit",
        "type": "attachment",
        "link": f"http://{HOST}:{PORT}/internal-memo/",
        "title": {"rendered": "Internal Memo Q1 2026"},
        "author": 1,
        "media_type": "file",
        "mime_type": "application/pdf",
        "source_url": f"http://{HOST}:{PORT}/wp-content/uploads/2026/02/internal-memo-q1.pdf",
        "media_details": {"file": "2026/02/internal-memo-q1.pdf"},
    },
]

CONTACT_FORMS = [
    {
        "id": 100,
        "slug": "contact-form-1",
        "title": "Contact form 1",
        "locale": "en_US",
        "properties": {
            "form": '<p>Your Name<br />\n[text* your-name]</p>\n<p>Your Email<br />\n[email* your-email]</p>\n<p>Subject<br />\n[text* your-subject]</p>\n<p>Your Message<br />\n[textarea your-message]</p>\n<p>[submit "Send"]</p>',
            "mail": {
                "active": True,
                "subject": "[_site_title] \"[your-subject]\"",
                "sender": "[_site_title] <wordpress@vulnerable-test.local>",
                "recipient": "admin@vulnerable-test.local",
                "body": "From: [your-name] <[your-email]>\nSubject: [your-subject]\n\nMessage Body:\n[your-message]",
                "additional_headers": "Reply-To: [your-email]",
            },
        },
    },
    {
        "id": 101,
        "slug": "newsletter-signup",
        "title": "Newsletter Signup",
        "locale": "en_US",
        "properties": {
            "form": '<p>Your Email<br />\n[email* subscriber-email]</p>\n<p>[submit "Subscribe"]</p>',
            "mail": {
                "active": True,
                "subject": "New newsletter subscriber",
                "sender": "[_site_title] <wordpress@vulnerable-test.local>",
                "recipient": "admin@vulnerable-test.local",
                "body": "New subscriber: [subscriber-email]",
            },
        },
    },
]

# 80 XML-RPC methods (realistic list)
XMLRPC_METHODS = [
    "system.multicall", "system.listMethods", "system.getCapabilities",
    "pingback.ping", "pingback.extensions.getPingbacks",
    "wp.getUsersBlogs", "wp.newPost", "wp.editPost", "wp.deletePost",
    "wp.getPost", "wp.getPosts", "wp.newTerm", "wp.editTerm", "wp.deleteTerm",
    "wp.getTerm", "wp.getTerms", "wp.getTaxonomy", "wp.getTaxonomies",
    "wp.getUser", "wp.getUsers", "wp.getProfile", "wp.editProfile",
    "wp.getPage", "wp.getPages", "wp.newPage", "wp.deletePage", "wp.editPage",
    "wp.getPageList", "wp.getAuthors", "wp.getCategories", "wp.getTags",
    "wp.newCategory", "wp.deleteCategory", "wp.suggestCategories",
    "wp.uploadFile", "wp.deleteFile",
    "wp.getCommentCount", "wp.getPostStatusList", "wp.getPageStatusList",
    "wp.getPageTemplates", "wp.getOptions", "wp.setOptions",
    "wp.getComment", "wp.getComments", "wp.deleteComment", "wp.editComment",
    "wp.newComment", "wp.getCommentStatusList",
    "wp.getMediaItem", "wp.getMediaLibrary",
    "wp.getPostType", "wp.getPostTypes", "wp.getPostFormats",
    "wp.getRevisions", "wp.restoreRevision",
    "blogger.getUsersBlogs", "blogger.getUserInfo",
    "blogger.getPost", "blogger.getRecentPosts",
    "blogger.newPost", "blogger.editPost", "blogger.deletePost",
    "metaWeblog.newPost", "metaWeblog.editPost", "metaWeblog.getPost",
    "metaWeblog.getRecentPosts", "metaWeblog.getCategories",
    "metaWeblog.newMediaObject", "metaWeblog.deletePost",
    "metaWeblog.getUsersBlogs",
    "mt.getCategoryList", "mt.getRecentPostTitles", "mt.getPostCategories",
    "mt.setPostCategories", "mt.supportedMethods", "mt.supportedTextFilters",
    "mt.getTrackbackPings", "mt.publishPost",
    "demo.sayHello", "demo.addTwoNumbers",
]


def _xmlrpc_list_methods_response():
    methods_xml = "\n".join(f"      <value><string>{m}</string></value>" for m in XMLRPC_METHODS)
    return f"""\
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
        <array>
          <data>
{methods_xml}
          </data>
        </array>
      </value>
    </param>
  </params>
</methodResponse>"""


XMLRPC_GREETING = f"""\
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value><string>XML-RPC server accepts POST requests only.</string></value>
    </param>
  </params>
</methodResponse>"""


DEBUG_LOG = """\
[15-Mar-2026 03:14:22 UTC] PHP Warning:  Undefined variable $user_role in /var/www/html/wp-content/plugins/custom-auth/auth.php on line 42
[15-Mar-2026 03:14:22 UTC] PHP Notice:  Trying to access array offset on value of type null in /var/www/html/wp-includes/meta.php on line 545
[15-Mar-2026 03:15:01 UTC] PHP Fatal error:  Uncaught Error: Call to undefined function wp_cache_flush_runtime() in /var/www/html/wp-includes/cache.php:258
Stack trace:
#0 /var/www/html/wp-includes/option.php(412): wp_cache_flush_runtime()
#1 /var/www/html/wp-settings.php(444): wp_load_alloptions()
#2 /var/www/html/wp-config.php(96): require_once('/var/www/html/w...')
#3 /var/www/html/wp-load.php(50): require_once('/var/www/html/w...')
#4 {main}
  thrown in /var/www/html/wp-includes/cache.php on line 258
[15-Mar-2026 03:16:45 UTC] WordPress database error Table 'wp_vulntest.wp_options' doesn't exist for query SELECT option_value FROM wp_options WHERE option_name = 'siteurl' LIMIT 1 made by require_once('wp-settings.php')
[15-Mar-2026 03:16:45 UTC] PHP Warning:  mysqli_real_connect(): (HY000/1045): Access denied for user 'wp_admin'@'localhost' (using password: YES) in /var/www/html/wp-includes/class-wpdb.php on line 1987
[15-Mar-2026 03:17:00 UTC] PHP Notice:  Function register_rest_route was called incorrectly in /var/www/html/wp-content/plugins/custom-auth/rest.php on line 18
[15-Mar-2026 08:22:10 UTC] PHP Warning:  file_get_contents(/var/www/html/wp-content/uploads/wpo-cache/index.html): Failed to open stream: No such file or directory in /var/www/html/wp-content/plugins/updraftplus/includes/class-wpo-cache.php on line 350
[15-Mar-2026 10:45:33 UTC] PHP Deprecated:  Function utf8_decode() is deprecated in /var/www/html/wp-content/plugins/wpml-sitepress-multilingual-cms/sitepress.php on line 2218
"""

UPLOADS_LISTING = f"""\
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
<head><title>Index of /wp-content/uploads</title></head>
<body>
<h1>Index of /wp-content/uploads</h1>
<pre>
<img src="/icons/blank.gif" alt="[ICO]"> <a href="?C=N;O=D">Name</a>           <a href="?C=M;O=A">Last modified</a>      <a href="?C=S;O=A">Size</a>  <a href="?C=D;O=A">Description</a>
<hr>
<img src="/icons/back.gif" alt="[PARENTDIR]"> <a href="/wp-content/">Parent Directory</a>                                    -
<img src="/icons/folder.gif" alt="[DIR]"> <a href="2024/">2024/</a>                  2024-12-20 14:30    -
<img src="/icons/folder.gif" alt="[DIR]"> <a href="2025/">2025/</a>                  2025-11-08 09:15    -
<img src="/icons/folder.gif" alt="[DIR]"> <a href="2026/">2026/</a>                  2026-03-15 16:42    -
<hr>
</pre>
<address>Apache/2.4.54 (Ubuntu) Server at {HOST} Port {PORT}</address>
</body>
</html>"""

GIT_HEAD = "ref: refs/heads/main\n"

GIT_CONFIG = """\
[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = https://github.com/vulntest-org/vulnerable-wp-site.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
"""

DOTENV = """\
APP_NAME=VulnerableTestSite
APP_ENV=production
APP_KEY=base64:r4nd0mG3n3r4t3dK3yV4lu3H3r3AAAAAAA=
APP_DEBUG=true
APP_URL=http://vulnerable-test.local

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=wp_vulntest
DB_USERNAME=wp_admin
DB_PASSWORD=S3cretP@ss!

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=vulnerable-test-assets

MAIL_MAILER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=587
MAIL_USERNAME=abcdef123456
MAIL_PASSWORD=ghijkl789012
"""

README_HTML = f"""\
<!DOCTYPE html>
<html>
<head><title>WordPress &rsaquo; ReadMe</title></head>
<body>
<h1 id="logo"><a href="https://wordpress.org/">WordPress</a></h1>
<p>Version {WP_VERSION}</p>
<p>Semantic Personal Publishing Platform</p>
<h2>First Things First</h2>
<p>Welcome. WordPress is a very special project to me.</p>
<h2>Installation: Famous 5-Minute Install</h2>
<ol>
<li>Unzip the package.</li>
<li>Upload everything to your web server.</li>
<li>Open wp-admin/install.php in your browser and follow the instructions.</li>
</ol>
<h2>System Requirements</h2>
<ul>
<li>PHP version 7.0 or greater.</li>
<li>MySQL version 5.7 or greater OR MariaDB version 10.3 or greater.</li>
</ul>
</body>
</html>"""

LOGIN_FORM = f"""\
<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Log In &lsaquo; Vulnerable Test Site &#8212; WordPress</title>
<link rel="stylesheet" href="/wp-admin/css/login.min.css?ver={WP_VERSION}" />
</head>
<body class="login">
<div id="login">
<h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
  <p>
    <label for="user_login">Username or Email Address</label>
    <input type="text" name="log" id="user_login" size="20" />
  </p>
  <p>
    <label for="user_pass">Password</label>
    <input type="password" name="pwd" id="user_pass" size="20" />
  </p>
  <p class="forgetmenot">
    <input name="rememberme" type="checkbox" id="rememberme" value="forever" />
    <label for="rememberme">Remember Me</label>
  </p>
  <p class="submit">
    <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
    <input type="hidden" name="redirect_to" value="/wp-admin/" />
    <input type="hidden" name="testcookie" value="1" />
  </p>
</form>
<p id="nav"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>
<p id="backtoblog"><a href="/">&larr; Go to Vulnerable Test Site</a></p>
</div>
</body>
</html>"""

LOGIN_ERROR_USER = f"""\
<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Log In &lsaquo; Vulnerable Test Site &#8212; WordPress</title>
</head>
<body class="login">
<div id="login">
<div id="login_error"><strong>Error:</strong> The username <strong>{{username}}</strong> is not registered on this site. If you are unsure of your username, try your email address instead.<br /></div>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
  <p><label for="user_login">Username or Email Address</label>
  <input type="text" name="log" id="user_login" size="20" value="{{username}}" /></p>
  <p><label for="user_pass">Password</label>
  <input type="password" name="pwd" id="user_pass" size="20" /></p>
  <p class="submit"><input type="submit" name="wp-submit" id="wp-submit" value="Log In" /></p>
</form>
</div>
</body>
</html>"""

LOGIN_ERROR_PASS = f"""\
<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Log In &lsaquo; Vulnerable Test Site &#8212; WordPress</title>
</head>
<body class="login">
<div id="login">
<div id="login_error"><strong>Error:</strong> The password you entered for the username <strong>{{username}}</strong> is incorrect. <a href="/wp-login.php?action=lostpassword">Lost your password?</a><br /></div>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
  <p><label for="user_login">Username or Email Address</label>
  <input type="text" name="log" id="user_login" size="20" value="{{username}}" /></p>
  <p><label for="user_pass">Password</label>
  <input type="password" name="pwd" id="user_pass" size="20" /></p>
  <p class="submit"><input type="submit" name="wp-submit" id="wp-submit" value="Log In" /></p>
</form>
</div>
</body>
</html>"""


def _rss_feed():
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    items = ""
    for p in WP_POSTS[:5]:
        items += f"""\
    <item>
      <title>{p["title"]["rendered"]}</title>
      <link>{p["link"]}</link>
      <pubDate>{now}</pubDate>
      <dc:creator><![CDATA[admin]]></dc:creator>
      <description><![CDATA[{p["excerpt"]["rendered"]}]]></description>
    </item>
"""
    return f"""\
<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"
  xmlns:content="http://purl.org/rss/1.0/modules/content/"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  xmlns:atom="http://www.w3.org/2005/Atom"
  xmlns:sy="http://purl.org/rss/1.0/modules/syndication/">
  <channel>
    <title>Vulnerable Test Site</title>
    <atom:link href="http://{HOST}:{PORT}/feed/" rel="self" type="application/rss+xml" />
    <link>http://{HOST}:{PORT}</link>
    <description>Just another WordPress site</description>
    <lastBuildDate>{now}</lastBuildDate>
    <language>en-US</language>
    <sy:updatePeriod>hourly</sy:updatePeriod>
    <sy:updateFrequency>1</sy:updateFrequency>
    <generator>https://wordpress.org/?v={WP_VERSION}</generator>
{items}  </channel>
</rss>"""


CF7_README = """\
=== Contact Form 7 ===
Contributors: takayukister
Donate link: https://contactform7.com/donate/
Tags: contact, form, contact form, feedback, email
Requires at least: 6.0
Tested up to: 6.4
Stable tag: 5.8.1
Requires PHP: 7.4
License: GPLv2 or later

Just another contact form plugin for WordPress. Simple but flexible.

== Description ==

Contact Form 7 can manage multiple contact forms, plus you can customize the
form and the mail contents flexibly with simple markup.

== Changelog ==

= 5.8.1 =
* Bug fix release.
"""

ELEMENTOR_README = """\
=== Elementor Website Builder ===
Contributors: flavor
Tags: page builder, editor, landing page, drag-and-drop, elementor
Requires at least: 6.0
Tested up to: 6.4
Stable tag: 3.18.0
Requires PHP: 7.4
License: GPLv3

The most advanced frontend drag & drop page builder.

== Description ==

Elementor is the platform web creators choose to build professional WordPress websites.

== Changelog ==

= 3.18.0 =
* New: Added custom breakpoints.
* Fix: Various security hardening.
"""

KNOWN_USERS = {"admin", "editor", "author"}


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

class VulnerableWPHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests and dispatches to simulated WP endpoints."""

    server_version = SERVER_HEADER

    # Suppress default stderr logging per-request (we log ourselves)
    def log_message(self, fmt, *args):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"  [{ts}] {self.address_string()} - {fmt % args}")

    # ---- helpers ----

    def _set_common_headers(self):
        """Add headers that every response should carry."""
        self.send_header("X-Powered-By", PHP_HEADER)
        # CORS: reflect Origin
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        # Intentionally NO security headers

    def _send_html(self, code, body):
        payload = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=UTF-8")
        self.send_header("Content-Length", str(len(payload)))
        self._set_common_headers()
        self.end_headers()
        self.wfile.write(payload)

    def _send_json(self, code, obj):
        payload = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=UTF-8")
        self.send_header("Content-Length", str(len(payload)))
        self._set_common_headers()
        self.end_headers()
        self.wfile.write(payload)

    def _send_text(self, code, text, content_type="text/plain; charset=UTF-8"):
        payload = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self._set_common_headers()
        self.end_headers()
        self.wfile.write(payload)

    def _send_xml(self, code, xml_text):
        payload = xml_text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/xml; charset=UTF-8")
        self.send_header("Content-Length", str(len(payload)))
        self._set_common_headers()
        self.end_headers()
        self.wfile.write(payload)

    def _send_redirect(self, location, code=302):
        self.send_response(code)
        self.send_header("Location", location)
        self._set_common_headers()
        self.end_headers()

    def _send_forbidden(self, message="Forbidden"):
        body = f"""\
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>403 Forbidden</title></head>
<body><h1>Forbidden</h1><p>You don't have permission to access this resource.</p>
<hr><address>Apache/2.4.54 (Ubuntu) Server at {HOST} Port {PORT}</address>
</body></html>"""
        self._send_html(403, body)

    # ---- routing ----

    def _route(self, method="GET"):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)

        # ---- Home / author enum ----
        if path == "/" and "author" in qs:
            author_id = qs["author"][0]
            user_map = {"1": "admin", "2": "editor", "3": "author"}
            slug = user_map.get(author_id, f"user-{author_id}")
            return self._send_redirect(f"/author/{slug}/")

        if path == "/":
            return self._send_html(200, HOME_PAGE_HTML)

        # ---- REST API ----
        if path == "/wp-json" or path == "/wp-json/":
            return self._send_json(200, WP_JSON_INDEX)

        if path == "/wp-json/wp/v2/users":
            return self._send_json(200, WP_USERS)

        if path == "/wp-json/wp/v2/posts":
            return self._send_json(200, WP_POSTS)

        if path == "/wp-json/wp/v2/pages":
            return self._send_json(200, WP_PAGES)

        if path == "/wp-json/wp/v2/media":
            return self._send_json(200, WP_MEDIA)

        if path == "/wp-json/contact-form-7/v1/contact-forms":
            return self._send_json(200, CONTACT_FORMS)

        # ---- XML-RPC ----
        if path == "/xmlrpc.php":
            if method == "POST":
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length).decode("utf-8", errors="replace") if content_length else ""
                if "system.listMethods" in body:
                    return self._send_xml(200, _xmlrpc_list_methods_response())
                # Default: accept any method call and return a generic fault for unknown
                return self._send_xml(200, """\
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value><struct>
      <member><name>faultCode</name><value><int>403</int></value></member>
      <member><name>faultString</name><value><string>Incorrect username or password.</string></value></member>
    </struct></value>
  </fault>
</methodResponse>""")
            # GET on xmlrpc
            return self._send_xml(200, XMLRPC_GREETING)

        # ---- Sensitive files ----
        if path == "/wp-content/debug.log":
            return self._send_text(200, DEBUG_LOG)

        if path == "/wp-content/uploads":
            return self._send_html(200, UPLOADS_LISTING)

        if path == "/wp-content/updraft":
            return self._send_forbidden()

        if path == "/.git/HEAD":
            return self._send_text(200, GIT_HEAD)

        if path == "/.git/config":
            return self._send_text(200, GIT_CONFIG)

        if path == "/.env":
            return self._send_text(200, DOTENV)

        if path == "/readme.html":
            return self._send_html(200, README_HTML)

        # ---- Login ----
        if path == "/wp-login.php":
            if method == "POST":
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length).decode("utf-8", errors="replace") if content_length else ""
                params = parse_qs(body)
                username = params.get("log", [""])[0]
                if username in KNOWN_USERS:
                    return self._send_html(200, LOGIN_ERROR_PASS.replace("{{username}}", username))
                else:
                    return self._send_html(200, LOGIN_ERROR_USER.replace("{{username}}", username))
            return self._send_html(200, LOGIN_FORM)

        if path == "/wp-admin/install.php":
            return self._send_redirect("/wp-login.php")

        # ---- Feed ----
        if path == "/feed":
            return self._send_xml(200, _rss_feed())

        # ---- Plugin readmes ----
        if path == "/wp-content/plugins/contact-form-7/readme.txt":
            return self._send_text(200, CF7_README)

        if path == "/wp-content/plugins/elementor/readme.txt":
            return self._send_text(200, ELEMENTOR_README)

        # ---- Fallback 404 ----
        self._send_html(404, f"""\
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>404 Not Found</title></head>
<body><h1>Not Found</h1>
<p>The requested URL {self.path} was not found on this server.</p>
<hr><address>Apache/2.4.54 (Ubuntu) Server at {HOST} Port {PORT}</address>
</body></html>""")

    # ---- HTTP verbs ----

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_HEAD(self):
        self._route("HEAD")

    def do_OPTIONS(self):
        self.send_response(200)
        self._set_common_headers()
        self.send_header("Allow", "GET, POST, OPTIONS, HEAD")
        self.end_headers()


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

def main():
    banner = rf"""
 __      __            _                     ___                 _
 \ \    / /__ _ _ __ _| |_ _ _ ___ ______   / __| ___ _ ___ ___| |_
  \ \/\/ / _ \ '_/ _` |  _| '_/ -_|_-<_-<  \__ \/ -_) '_\ V / -_) '_|
   \_/\_/\___/_| \__,_|\__|_| \___/__/__/   |___/\___|_|  \_/\___|_|

  Vulnerable WordPress Test Lab  v1.0
  ====================================
  WordPress Version : {WP_VERSION}
  Server            : {SERVER_HEADER}
  PHP               : {PHP_HEADER}
  Listening on      : http://{HOST}:{PORT}

  Simulated vulnerabilities:
    [!] REST API user enumeration       /wp-json/wp/v2/users
    [!] XML-RPC enabled                 /xmlrpc.php (80 methods incl. system.multicall)
    [!] Debug log exposed               /wp-content/debug.log
    [!] Directory listing               /wp-content/uploads/
    [!] Git repository exposed          /.git/HEAD , /.git/config
    [!] Environment file exposed        /.env (DB creds, AWS keys)
    [!] WordPress readme                /readme.html (version disclosure)
    [!] Author enumeration              /?author=1
    [!] Login error oracle              /wp-login.php (user vs password error)
    [!] CF7 forms unauthenticated       /wp-json/contact-form-7/v1/contact-forms
    [!] CORS misconfiguration           Reflects any Origin
    [!] Missing security headers        No HSTS, CSP, X-Frame-Options, etc.
    [!] Updraft backup dir detectable   /wp-content/updraft/ (403)

  Press Ctrl+C to stop.
"""
    print(banner)

    server = HTTPServer((HOST, PORT), VulnerableWPHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  [*] Shutting down server...")
        server.server_close()
        print("  [*] Done.")


if __name__ == "__main__":
    main()
