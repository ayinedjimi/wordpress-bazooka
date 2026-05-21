"""WordPress user enumeration — 4 vectors: REST, author-id, oEmbed, sitemap."""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING, Optional

from core.models import Evidence, Finding, Severity, Confidence, FindingType, WPUser, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


AUTHOR_URL_RE = re.compile(r'/author/([^/\s"\'?#]+)', re.IGNORECASE)
AUTHOR_BODY_CLASS_RE = re.compile(r'<body[^>]*?class="[^"]*?\bauthor-([a-zA-Z][^\s"]*)', re.IGNORECASE)


class WPUsersModule(BazookaModule):
    name = "enum.wp_users"
    phase = "enum"
    description = "WordPress user enumeration (REST + author-id + oEmbed + sitemap)"
    profiles = ["quick", "standard", "aggressive", "bugbounty"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        users: dict[str, WPUser] = {}  # key = username/slug

        def add(username: str, source: str, uid: int = 0,
                display_name: str = "", email: Optional[str] = None,
                avatar_url: str = "") -> None:
            if not username:
                return
            username = username.strip()
            if not username:
                return
            # Reject pure-numeric "usernames" (these are user IDs leaking from body class regex)
            if username.isdigit():
                return
            key = username.lower()
            if key in users:
                u = users[key]
                if uid and not u.id:
                    u.id = uid
                if email and not u.email:
                    u.email = email
                if display_name and not u.display_name:
                    u.display_name = display_name
                if avatar_url and not u.avatar_url:
                    u.avatar_url = avatar_url
                return
            grav = ""
            if avatar_url and "gravatar.com" in avatar_url:
                m = re.search(r'/avatar/([a-f0-9]+)', avatar_url)
                if m:
                    grav = m.group(1)
            users[key] = WPUser(
                id=uid or 0,
                username=username,
                display_name=display_name,
                slug=username,
                avatar_url=avatar_url,
                gravatar_hash=grav,
                email=email,
                discovery_method=source,
            )

        # Run 4 vectors concurrently
        await asyncio.gather(
            self._vector_rest(base, session, add, ctx),
            self._vector_author_id(base, session, add, ctx),
            self._vector_oembed(base, session, add),
            self._vector_sitemap(base, session, add),
            return_exceptions=True,
        )

        user_list = list(users.values())
        ctx.target.users = user_list
        result.add_data("users", [u.model_dump() for u in user_list])
        result.add_data(
            "users_detected",
            [{"username": u.username, "id": u.id, "source": u.discovery_method}
             for u in user_list],
        )

        for idx, u in enumerate(user_list, 1):
            result.add_finding(Finding(
                id=f"ENUM-USR-{idx:03d}",
                title=f"Utilisateur WordPress detecte: {u.username}",
                severity=Severity.HIGH,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=f"Utilisateur {u.username} (ID={u.id or '?'}, source={u.discovery_method}).",
                evidence=Evidence(request=f"GET {base} (vecteur {u.discovery_method})"),
                impact="Nom d'utilisateur exploitable pour brute-force ou phishing.",
                remediation="Restreindre l'API REST utilisateurs et masquer les archives auteurs.",
                compliance=Compliance(owasp_2021="A01:2021", cwe="CWE-200"),
                phase="enum",
                module=self.name,
                tags=["user", u.username],
            ))

        if user_list:
            emails_found = [u for u in user_list if u.email]
            if emails_found:
                result.add_finding(Finding(
                    id="ENUM-USR-EMAIL",
                    title=f"Email(s) expose(s) via REST API: {len(emails_found)}",
                    severity=Severity.CRITICAL,
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    confidence=Confidence.CONFIRMED,
                    finding_type=FindingType.INFORMATION_DISCLOSURE,
                    description=f"Emails: {', '.join(u.email for u in emails_found if u.email)}.",
                    impact="Emails utilisables pour phishing, brute-force.",
                    remediation="Bloquer le champ email dans la REST API.",
                    compliance=Compliance(owasp_2021="A01:2021", cwe="CWE-200"),
                    phase="enum",
                    module=self.name,
                ))

        return result

    async def _vector_rest(self, base: str, session, add, ctx) -> None:
        try:
            resp = await session.get(f"{base}/wp-json/wp/v2/users")
        except Exception:
            return
        if resp.status_code == 200:
            try:
                data = resp.json()
            except Exception:
                data = None
            if isinstance(data, list):
                for u in data:
                    uid = u.get("id", 0) or 0
                    avatars = u.get("avatar_urls") or {}
                    if not isinstance(avatars, dict):
                        avatars = {}
                    avatar_url = next(iter(avatars.values()), "") if avatars else ""
                    add(u.get("slug", "") or u.get("name", ""),
                        source="rest_api", uid=uid,
                        display_name=u.get("name", ""),
                        avatar_url=avatar_url)
        if ctx.profile in ("standard", "aggressive"):
            try:
                resp = await session.get(f"{base}/wp-json/wp/v2/users?_fields=id,slug,name,email")
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list):
                        for u in data:
                            add(u.get("slug", "") or u.get("name", ""),
                                source="rest_api_fields",
                                uid=u.get("id", 0) or 0,
                                display_name=u.get("name", ""),
                                email=u.get("email"))
            except Exception:
                pass

    async def _vector_author_id(self, base: str, session, add, ctx) -> None:
        max_id = 100 if ctx.profile == "aggressive" else 20
        sem = asyncio.Semaphore(10)

        async def one(author_id: int) -> None:
            async with sem:
                try:
                    resp = await session.get(
                        f"{base}/?author={author_id}",
                        follow_redirects=False, use_cache=True,
                    )
                except Exception:
                    return
            if resp.status_code in (301, 302):
                loc = resp.headers.get("Location", "")
                m = AUTHOR_URL_RE.search(loc)
                if m:
                    add(m.group(1), source="author_id_brute", uid=author_id)
                    return
            if resp.status_code == 200:
                body = resp.text or ""
                m = AUTHOR_URL_RE.search(body) or AUTHOR_BODY_CLASS_RE.search(body)
                if m:
                    add(m.group(1), source="author_id_brute", uid=author_id)

        await asyncio.gather(*(one(i) for i in range(1, max_id + 1)),
                             return_exceptions=True)

    async def _vector_oembed(self, base: str, session, add) -> None:
        try:
            url = f"{base}/wp-json/oembed/1.0/embed?url={base}"
            resp = await session.get(url)
        except Exception:
            return
        if resp.status_code != 200:
            return
        try:
            data = resp.json()
        except Exception:
            return
        if not isinstance(data, dict):
            return
        username = ""
        author_url = data.get("author_url") or ""
        if "/author/" in author_url:
            m = AUTHOR_URL_RE.search(author_url)
            if m:
                username = m.group(1)
        display = data.get("author_name") or ""
        if username:
            add(username, source="oembed", display_name=display)
        elif display:
            add(display, source="oembed", display_name=display)

    async def _vector_sitemap(self, base: str, session, add) -> None:
        try:
            resp = await session.get(f"{base}/wp-sitemap-users-1.xml")
        except Exception:
            return
        if resp.status_code == 200 and "<loc>" in (resp.text or ""):
            for slug in AUTHOR_URL_RE.findall(resp.text):
                add(slug, source="sitemap_users")
