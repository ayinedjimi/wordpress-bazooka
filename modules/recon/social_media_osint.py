"""Social media OSINT — find profiles of WordPress admins on public platforms."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

# Public profile URL patterns (no login required, no API key)
PROFILE_CHECKS = [
    ("GitHub", "https://github.com/{username}", ["Repositories", "Contributions", "repositories"]),
    ("LinkedIn", "https://www.linkedin.com/in/{username}", ["LinkedIn", "Experience", "connections"]),
    ("Twitter/X", "https://x.com/{username}", ["@{username}", "followers", "following"]),
    ("Gravatar", "https://gravatar.com/{username}", ["Gravatar", "profile"]),
    ("WordPress.org", "https://profiles.wordpress.org/{username}/", ["WordPress.org", "Member Since", "plugins"]),
]


class SocialMediaOSINTModule(BazookaModule):
    name = "recon.social_media_osint"
    phase = "recon"
    description = "Social media profile discovery for WordPress users"
    profiles = ["aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()

        # Collect usernames to check
        usernames: list[str] = []
        for u in ctx.target.users:
            if u.username and len(u.username) >= 3:
                usernames.append(u.username)
            if u.display_name and u.display_name != u.username and len(u.display_name) >= 3:
                # Convert display name to possible username: "John Doe" → "johndoe", "john-doe"
                clean = re.sub(r'[^a-zA-Z0-9]', '', u.display_name.lower())
                if clean and clean not in usernames:
                    usernames.append(clean)

        if not usernames:
            return result

        profiles_found: list[dict] = []

        for username in usernames[:5]:  # Limit to 5 users
            for platform, url_template, signatures in PROFILE_CHECKS:
                url = url_template.format(username=username)
                try:
                    resp = await session.get(url, use_cache=True, cache_ttl=3600)
                    if resp.status_code == 200:
                        body = resp.text[:5000]
                        # Check if it's a real profile (not a 404 page or redirect)
                        has_signature = any(
                            sig.format(username=username).lower() in body.lower()
                            for sig in signatures
                        )
                        if has_signature:
                            profiles_found.append({
                                "username": username,
                                "platform": platform,
                                "url": url,
                            })
                except Exception:
                    continue

        result.add_data("social_profiles", profiles_found)

        if profiles_found:
            profile_lines = "\n".join(
                f"  - {p['username']} sur {p['platform']}: {p['url']}"
                for p in profiles_found
            )
            result.add_finding(Finding(
                id="RECON-SOCIAL-001",
                title=f"{len(profiles_found)} profil(s) public(s) trouve(s) pour les admins WP",
                severity=Severity.LOW,
                cvss_score=2.4,
                confidence=Confidence.LIKELY,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=f"Profils publics trouves:\n{profile_lines}",
                evidence=Evidence(
                    request=f"GET profile URLs for {len(usernames)} usernames",
                    response_body_excerpt=f"{len(profiles_found)} profiles found",
                ),
                impact="Informations personnelles utiles pour du social engineering ou du phishing cible.",
                remediation="Sensibiliser les admins sur la separation des identites pro/perso. Utiliser des usernames differents.",
                compliance=Compliance(owasp_2021="A07:2021", cwe="CWE-200"),
                phase="recon", module=self.name,
            ))

        return result
