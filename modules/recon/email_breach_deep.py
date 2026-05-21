"""Deep email breach analysis — HIBP lookup + password mutation generation per email."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from core.models import Evidence, Finding, Severity, Confidence, FindingType, Compliance
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

COMMON_PASSWORD_HASHES_HIBP = [
    "password", "123456", "admin", "letmein", "welcome", "monkey",
    "dragon", "master", "qwerty", "azerty",
]


class EmailBreachDeepModule(BazookaModule):
    name = "recon.email_breach_deep"
    phase = "recon"
    description = "Deep email breach analysis via HIBP + password mutations"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        emails: list[str] = []

        # Collect emails from users
        for u in ctx.target.users:
            if u.email:
                emails.append(u.email)

        # Collect from harvested emails
        harvested = ctx.data.get("harvested_emails", [])
        if isinstance(harvested, list):
            emails.extend(harvested)

        emails = list(set(e for e in emails if e and "@" in e))
        if not emails:
            return result

        result.add_data("emails_to_check", emails)
        breached_emails: list[dict] = []

        for email in emails[:10]:  # Limit to 10 emails
            # HIBP API check (requires API key, free for pwned passwords)
            # We use the Pwned Passwords API (k-anonymity, no API key needed)
            # to check if common passwords for this user are in breaches
            email_local = email.split("@")[0]
            domain_part = email.split("@")[1].split(".")[0] if "@" in email else ""

            # Generate probable passwords from email
            mutations = set()
            for base in [email_local, domain_part, ctx.target.domain]:
                if not base or len(base) < 2:
                    continue
                mutations.add(base)
                mutations.add(base.capitalize())
                mutations.add(f"{base}123")
                mutations.add(f"{base}2024")
                mutations.add(f"{base}2025")
                mutations.add(f"{base}2026")
                mutations.add(f"{base}!")
                mutations.add(f"{base.capitalize()}!")
                mutations.add(f"{base.capitalize()}123")

            # Check each mutation against HIBP Pwned Passwords (k-anonymity)
            pwned_passwords: list[tuple[str, int]] = []
            for password in list(mutations)[:20]:
                sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
                prefix = sha1[:5]
                suffix = sha1[5:]

                try:
                    resp = await session.get(
                        f"https://api.pwnedpasswords.com/range/{prefix}",
                        use_cache=True,
                        cache_ttl=3600,
                    )
                    if resp.status_code == 200:
                        for line in resp.text.strip().split("\n"):
                            parts = line.strip().split(":")
                            if len(parts) == 2 and parts[0] == suffix:
                                count = int(parts[1])
                                pwned_passwords.append((password, count))
                                break
                except Exception:
                    continue

            if pwned_passwords:
                breached_emails.append({
                    "email": email,
                    "pwned_passwords": [(p, c) for p, c in pwned_passwords],
                })

                # Most breached password
                worst = max(pwned_passwords, key=lambda x: x[1])
                result.add_finding(Finding(
                    id=f"RECON-BREACH-{len(breached_emails):02d}",
                    title=f"Mots de passe probables dans des fuites pour {email}",
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    confidence=Confidence.LIKELY,
                    finding_type=FindingType.INFORMATION_DISCLOSURE,
                    description=(
                        f"{len(pwned_passwords)} mutation(s) de mot de passe probable pour {email} "
                        f"trouvee(s) dans des fuites de donnees (HIBP Pwned Passwords). "
                        f"Le plus expose: '{worst[0]}' ({worst[1]:,} occurrences dans des fuites)."
                    ),
                    evidence=Evidence(
                        request=f"HIBP Pwned Passwords API (k-anonymity) for {email}",
                        response_body_excerpt=f"{len(pwned_passwords)} passwords found in breaches",
                    ),
                    impact="Si l'utilisateur reutilise ces mots de passe, le compte WordPress peut etre compromis.",
                    remediation="Forcer le changement de mot de passe. Activer le 2FA. Utiliser un gestionnaire de mots de passe.",
                    compliance=Compliance(owasp_2021="A07:2021", cwe="CWE-521"),
                    phase="recon", module=self.name,
                    tags=["breach", "password", "hibp"],
                ))

        result.add_data("breached_emails", breached_emails)
        return result
