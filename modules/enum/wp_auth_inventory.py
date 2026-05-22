"""Authenticated REST inventory via WordPress Application Password (`--wp-auth`).

When the user provides `--wp-auth username:xxxx-xxxx-xxxx-xxxx`, this module
hits the privileged REST endpoints (`/wp/v2/plugins`, `/wp/v2/themes`,
`/wp/v2/users?context=edit`) with HTTP Basic auth. The returned data is the
authoritative inventory — no bruteforce wordlist guessing, no false positives.

We populate `ctx.target.plugins` / `themes` / `users` directly. Downstream
modules (`enum.wp_plugins`, `enum.wp_themes`, `enum.wp_users`) detect that
the lists are already filled (via `ctx.get_data("wp_auth_inventory_done")`)
and short-circuit their own enumeration.

Runs first in the `enum` phase (priority via empty `dependencies`).
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

import httpx

from core.models import (
    Compliance, Evidence, Finding, FindingType, Severity, Confidence,
    WPPlugin, WPTheme, WPUser,
)
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class WPAuthInventoryModule(BazookaModule):
    name = "enum.wp_auth_inventory"
    phase = "enum"
    description = "Authoritative inventory via WP Application Password (--wp-auth)"
    # All profiles: if the user supplied creds, we always use them.
    profiles = ["quick", "standard", "aggressive", "bugbounty"]

    def should_run(self, ctx) -> bool:
        # Only run when --wp-auth was supplied.
        return bool(ctx.get_data("wp_auth"))

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        wp_auth = ctx.get_data("wp_auth") or ""
        if ":" not in wp_auth:
            result.status = "skipped"
            return result

        username, _, password = wp_auth.partition(":")
        # WP app passwords often contain spaces; strip them as the WP admin UI does.
        password = password.replace(" ", "")
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers = {"Authorization": f"Basic {token}", "Accept": "application/json"}

        base = ctx.target.url
        plugins: list[dict] = await self._get_json(session, f"{base}/wp-json/wp/v2/plugins", headers)
        themes:  list[dict] = await self._get_json(session, f"{base}/wp-json/wp/v2/themes", headers)
        users:   list[dict] = await self._get_json(session, f"{base}/wp-json/wp/v2/users?context=edit", headers)

        if not isinstance(plugins, list) and not isinstance(themes, list):
            # 401 / 403 — credentials rejected
            result.add_finding(Finding(
                id="ENUM-WPAUTH-FAIL",
                title=f"WP authentication failed for {username!r}",
                severity=Severity.LOW,
                cvss_score=0.0,
                confidence=Confidence.LIKELY,
                finding_type=FindingType.MISCONFIGURATION,
                description=(
                    "Credentials supplied via --wp-auth were rejected by the REST API. "
                    "Check the user has Application Passwords enabled and the password "
                    "is correctly formatted (e.g. 'XXXX XXXX XXXX XXXX XXXX XXXX')."
                ),
                module=self.name, phase="enum",
            ))
            return result

        # Plugins
        n_plug = 0
        if isinstance(plugins, list):
            for p in plugins:
                if not isinstance(p, dict):
                    continue
                slug = (p.get("plugin") or "").split("/")[0]
                if not slug:
                    continue
                wp_plugin = WPPlugin(
                    slug=slug,
                    version=p.get("version") or None,
                    name=p.get("name") or None,
                    author=p.get("author") or None,
                    discovery_method="wp_auth_rest",
                )
                ctx.target.plugins.append(wp_plugin)
                n_plug += 1

        # Themes
        n_theme = 0
        active_theme = None
        if isinstance(themes, list):
            for t in themes:
                if not isinstance(t, dict):
                    continue
                slug = t.get("stylesheet") or t.get("template")
                if not slug:
                    continue
                wp_theme = WPTheme(
                    slug=slug,
                    version=(t.get("version") or {}).get("rendered") if isinstance(t.get("version"), dict) else (t.get("version") or None),
                    name=(t.get("name") or {}).get("rendered") if isinstance(t.get("name"), dict) else (t.get("name") or None),
                    author=(t.get("author") or {}).get("rendered") if isinstance(t.get("author"), dict) else (t.get("author") or None),
                    parent=t.get("template") if t.get("template") != slug else None,
                    discovery_method="wp_auth_rest",
                )
                ctx.target.themes.append(wp_theme)
                n_theme += 1
                if t.get("status") == "active":
                    active_theme = slug

        # Users (full info incl. emails because context=edit)
        n_user = 0
        if isinstance(users, list):
            for u in users:
                if not isinstance(u, dict):
                    continue
                roles = u.get("roles", []) or []
                wp_user = WPUser(
                    slug=u.get("slug", ""),
                    id=u.get("id", 0) or 0,
                    display_name=u.get("name", "") or "",
                    email=u.get("email", "") or "",
                    role=", ".join(roles) if isinstance(roles, list) else str(roles),
                    discovery_method="wp_auth_rest",
                )
                ctx.target.users.append(wp_user)
                n_user += 1

        # Mark inventory complete so downstream modules can short-circuit.
        ctx.set_data("wp_auth_inventory_done", True)
        ctx.set_data("wp_auth_user", username)
        if active_theme:
            ctx.set_data("active_theme", active_theme)

        result.add_finding(Finding(
            id="ENUM-WPAUTH-OK",
            title=f"Authoritative inventory via --wp-auth ({n_plug} plugins / {n_theme} themes / {n_user} users)",
            severity=Severity.INFO,
            cvss_score=0.0,
            confidence=Confidence.CONFIRMED,
            finding_type=FindingType.INFORMATION_DISCLOSURE,
            description=(
                f"Authenticated as {username!r}. Skipping bruteforce enumeration since the "
                f"REST inventory is authoritative."
            ),
            evidence=Evidence(
                request=f"GET {base}/wp-json/wp/v2/{{plugins,themes,users}} (Basic auth)",
                response_status=200,
            ),
            module=self.name, phase="enum",
            tags=["wp-auth", "authoritative-inventory"],
        ))
        return result

    async def _get_json(self, session: BazookaSession, url: str, headers: dict):
        try:
            # use_cache=False — auth-bearing requests must never hit the cache
            resp = await session.get(url, headers=headers, use_cache=False)
            if resp.status_code != 200:
                return None
            return resp.json()
        except (httpx.RequestError, httpx.TimeoutException, ValueError):
            return None
