"""Gravatar hash reversal for email discovery."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


class GravatarReverseModule(BazookaModule):
    name = "enum.gravatar_reverse"
    phase = "enum"
    description = "Gravatar hash reversal for email discovery"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        emails_discovered: list[dict] = []

        users = ctx.target.users
        if not users:
            result.add_data("emails_discovered", [])
            return result

        for user in users:
            gravatar_hash = user.gravatar_hash
            if not gravatar_hash:
                # Try to extract hash from avatar_url
                # Gravatar URLs: https://secure.gravatar.com/avatar/{hash}
                avatar_url = user.avatar_url
                if avatar_url and "gravatar.com/avatar/" in avatar_url:
                    parts = avatar_url.split("gravatar.com/avatar/")
                    if len(parts) > 1:
                        # Hash is the segment after /avatar/ before ? or /
                        hash_part = parts[1].split("?")[0].split("/")[0]
                        if len(hash_part) == 32:  # MD5 hash length
                            gravatar_hash = hash_part
                            user.gravatar_hash = hash_part

            if not gravatar_hash:
                continue

            # Query Gravatar JSON API
            gravatar_url = f"https://www.gravatar.com/{gravatar_hash}.json"
            resp = await session.get(gravatar_url)

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    entries = data.get("entry", [])
                    if not entries:
                        continue

                    entry = entries[0]

                    # Extract profile information
                    profile_info: dict = {
                        "username": user.username,
                        "gravatar_hash": gravatar_hash,
                    }

                    # Display name from Gravatar
                    display_name = entry.get("displayName", "")
                    if display_name:
                        profile_info["gravatar_display_name"] = display_name

                    # Preferred username
                    preferred_username = entry.get("preferredUsername", "")
                    if preferred_username:
                        profile_info["gravatar_username"] = preferred_username

                    # Profile URL
                    profile_url = entry.get("profileUrl", "")
                    if profile_url:
                        profile_info["profile_url"] = profile_url

                    # Emails (if exposed)
                    email_entries = entry.get("emails", [])
                    for email_entry in email_entries:
                        email_value = email_entry.get("value", "")
                        if email_value:
                            profile_info["email"] = email_value
                            # Update user email if not already set
                            if not user.email:
                                user.email = email_value

                    # Name details
                    name_data = entry.get("name", {})
                    if isinstance(name_data, dict):
                        full_name_parts = []
                        if name_data.get("givenName"):
                            full_name_parts.append(name_data["givenName"])
                        if name_data.get("familyName"):
                            full_name_parts.append(name_data["familyName"])
                        if full_name_parts:
                            profile_info["full_name"] = " ".join(full_name_parts)

                    # Accounts (linked social accounts)
                    accounts = entry.get("accounts", [])
                    if accounts:
                        profile_info["linked_accounts"] = [
                            {
                                "domain": acc.get("domain", ""),
                                "display": acc.get("display", ""),
                                "url": acc.get("url", ""),
                                "shortname": acc.get("shortname", ""),
                            }
                            for acc in accounts[:10]
                        ]

                    # About me / bio
                    about_me = entry.get("aboutMe", "")
                    if about_me:
                        profile_info["bio"] = about_me

                    # Location
                    current_location = entry.get("currentLocation", "")
                    if current_location:
                        profile_info["location"] = current_location

                    emails_discovered.append(profile_info)

                except Exception:
                    continue

            elif resp.status_code == 404:
                # No Gravatar profile for this hash — not uncommon
                continue

        result.add_data("emails_discovered", emails_discovered)
        result.add_data("users_checked", len(users))

        if emails_discovered:
            # Build summary
            email_list = []
            for profile in emails_discovered:
                email = profile.get("email", "")
                username = profile.get("username", "unknown")
                if email:
                    email_list.append(f"{username}: {email}")
                else:
                    email_list.append(f"{username}: (profile found, no email exposed)")

            result.add_finding(Finding(
                id="ENUM-GRAV-001",
                title=f"{len(emails_discovered)} profil(s) Gravatar resolu(s) avec informations personnelles",
                severity=Severity.HIGH,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"Les hash Gravatar des utilisateurs WordPress ont permis de "
                    f"recuperer des profils detailles. "
                    f"Resultats: {'; '.join(email_list[:10])}."
                ),
                evidence=Evidence(
                    request="GET https://www.gravatar.com/{hash}.json",
                    response_status=200,
                    response_body_excerpt=str(emails_discovered[0])[:300],
                ),
                impact=(
                    "Les emails et informations personnelles decouverts peuvent etre utilises "
                    "pour du phishing cible, de la reconnaissance avancee, ou des attaques "
                    "par force brute sur les comptes."
                ),
                remediation=(
                    "Utiliser un plugin pour desactiver les Gravatars ou les remplacer par "
                    "des avatars generes localement. Les utilisateurs peuvent supprimer "
                    "leur profil Gravatar public."
                ),
                compliance=Compliance(owasp_2021="A01:2021", cwe="CWE-200"),
                phase="enum",
                module=self.name,
            ))

        return result
