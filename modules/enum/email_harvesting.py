"""Email harvesting module.

Extracts email addresses from site content, REST API responses,
contact pages, and legal/privacy pages.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# False positive domains to filter out
FALSE_POSITIVE_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "test.org",
    "localhost",
    "domain.com",
    "email.com",
    "yourdomain.com",
    "yoursite.com",
    "sentry.io",
    "w3.org",
    "schema.org",
    "wordpress.org",
    "gravatar.com",
    "placeholder.com",
}

# False positive local parts
FALSE_POSITIVE_LOCALS = {
    "noreply",
    "no-reply",
    "donotreply",
    "do-not-reply",
    "wapuu",
    "wordpress",
    "changeme",
    "someone",
    "user",
    "username",
    "your-email",
    "your_email",
    "youremail",
    "email",
    "name",
    "test",
}

# Contact page paths to check
CONTACT_PATHS = [
    "/contact",
    "/contact/",
    "/contact-us",
    "/contact-us/",
    "/nous-contacter",
    "/nous-contacter/",
    "/contactez-nous",
    "/contactez-nous/",
    "/kontakt",
    "/kontakt/",
]

# Legal/privacy page paths
LEGAL_PATHS = [
    "/privacy-policy",
    "/privacy-policy/",
    "/politique-de-confidentialite",
    "/politique-de-confidentialite/",
    "/mentions-legales",
    "/mentions-legales/",
    "/legal",
    "/legal/",
    "/terms",
    "/terms/",
    "/imprint",
    "/imprint/",
    "/impressum",
    "/impressum/",
]


def _extract_emails(text: str) -> set[str]:
    """Extract email addresses from text, filtering false positives."""
    raw_emails = set(EMAIL_REGEX.findall(text))
    valid: set[str] = set()

    for email in raw_emails:
        email_lower = email.lower()
        local_part = email_lower.split("@")[0]
        domain = email_lower.split("@")[1] if "@" in email_lower else ""

        # Filter false positive domains
        if domain in FALSE_POSITIVE_DOMAINS:
            continue

        # Filter false positive local parts
        if local_part in FALSE_POSITIVE_LOCALS:
            continue

        # Filter image/file-like patterns (e.g., "2x@media" from CSS)
        if local_part.endswith(("x", "px")) and local_part[:-1].isdigit():
            continue
        if local_part.endswith(("px", "em", "rem", "vh", "vw")):
            continue

        # Filter extremely short or long emails
        if len(local_part) < 2 or len(email_lower) > 254:
            continue

        valid.add(email_lower)

    return valid


def _classify_email(email: str, target_domain: str, known_usernames: set[str]) -> str:
    """Classify an email as 'admin', 'generic', or 'contact'.

    Returns the classification string.
    """
    local_part = email.split("@")[0].lower()
    domain = email.split("@")[1].lower() if "@" in email else ""

    # Admin indicators
    admin_locals = {"admin", "administrator", "root", "webmaster", "postmaster", "hostmaster"}
    if local_part in admin_locals:
        return "admin"

    # Check if the email belongs to a known WordPress user
    if local_part in known_usernames:
        return "admin"

    # If the email domain matches the target, it's more significant
    if domain == target_domain or domain == f"www.{target_domain}":
        # Common contact addresses
        contact_locals = {"contact", "info", "support", "hello", "bonjour", "service"}
        if local_part in contact_locals:
            return "contact"
        return "admin"  # Staff email on target domain

    return "contact"


class EmailHarvestingModule(BazookaModule):
    name = "enum.email_harvesting"
    phase = "enum"
    description = "Email address harvesting from site content"
    profiles = ["standard", "aggressive"]

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        domain = ctx.target.domain

        # Build set of known usernames for cross-referencing
        known_usernames: set[str] = set()
        for user in ctx.target.users:
            if user.username:
                known_usernames.add(user.username.lower())
            if user.slug:
                known_usernames.add(user.slug.lower())

        all_emails: set[str] = set()
        source_map: dict[str, list[str]] = {}  # email → list of sources

        def _record_emails(emails: set[str], source: str) -> None:
            for email in emails:
                all_emails.add(email)
                source_map.setdefault(email, []).append(source)

        # === SOURCE 1: Homepage HTML ===
        try:
            resp = await session.get(base, use_cache=True)
            if resp.status_code == 200:
                body = resp.text[:50000]
                emails = _extract_emails(body)
                _record_emails(emails, "homepage")
        except Exception:
            pass

        # === SOURCE 2: REST API pages ===
        try:
            resp = await session.get(f"{base}/wp-json/wp/v2/pages?per_page=20", use_cache=True)
            if resp.status_code == 200:
                body = resp.text[:100000]
                emails = _extract_emails(body)
                _record_emails(emails, "wp-json/pages")
        except Exception:
            pass

        # === SOURCE 3: REST API posts ===
        try:
            resp = await session.get(f"{base}/wp-json/wp/v2/posts?per_page=20", use_cache=True)
            if resp.status_code == 200:
                body = resp.text[:100000]
                emails = _extract_emails(body)
                _record_emails(emails, "wp-json/posts")
        except Exception:
            pass

        # === SOURCE 4: REST API comments (author_email if exposed) ===
        try:
            resp = await session.get(f"{base}/wp-json/wp/v2/comments?per_page=50", use_cache=True)
            if resp.status_code == 200:
                body = resp.text[:100000]
                emails = _extract_emails(body)
                _record_emails(emails, "wp-json/comments")
        except Exception:
            pass

        # === SOURCE 5: Contact pages ===
        for path in CONTACT_PATHS:
            try:
                resp = await session.get(f"{base}{path}", use_cache=True)
                if resp.status_code == 200:
                    body = resp.text[:30000]
                    emails = _extract_emails(body)
                    _record_emails(emails, f"contact:{path}")
            except Exception:
                continue

        # === SOURCE 6: Legal/privacy pages ===
        for path in LEGAL_PATHS:
            try:
                resp = await session.get(f"{base}{path}", use_cache=True)
                if resp.status_code == 200:
                    body = resp.text[:30000]
                    emails = _extract_emails(body)
                    _record_emails(emails, f"legal:{path}")
            except Exception:
                continue

        if not all_emails:
            return result

        # Store harvested emails
        result.data["harvested_emails"] = sorted(all_emails)

        # Classify and cross-reference with known users
        admin_emails: list[str] = []
        generic_emails: list[str] = []
        contact_emails: list[str] = []

        for email in sorted(all_emails):
            classification = _classify_email(email, domain, known_usernames)
            if classification == "admin":
                admin_emails.append(email)
            elif classification == "contact":
                contact_emails.append(email)
            else:
                generic_emails.append(email)

        # Cross-reference: enrich ctx.target.users with discovered emails
        for user in ctx.target.users:
            if user.email:
                continue
            # Try to match by username in email local part
            for email in all_emails:
                local_part = email.split("@")[0].lower()
                if local_part == user.username.lower() or local_part == user.slug.lower():
                    user.email = email
                    break

        # Create findings based on classification
        finding_count = 0

        if admin_emails:
            finding_count += 1
            result.add_finding(Finding(
                id=f"ENUM-EMAIL-{finding_count:03d}",
                title=f"{len(admin_emails)} email(s) admin/staff collecte(s)",
                severity=Severity.HIGH,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"Emails d'administration/staff decouverts sur le site: "
                    f"{', '.join(admin_emails[:10])}. "
                    f"Sources: {_summarize_sources(admin_emails, source_map)}."
                ),
                evidence=Evidence(
                    request=f"Multiple GET requests on {base}",
                    response_status=200,
                    response_body_excerpt=", ".join(admin_emails[:5]),
                ),
                impact=(
                    "Les emails admin/staff permettent des attaques ciblees: "
                    "phishing, social engineering, credential stuffing, "
                    "et enumeration de comptes WordPress."
                ),
                remediation=(
                    "Utiliser des adresses email generiques (contact@, info@) sur le site public. "
                    "Masquer les emails personnels. Utiliser des formulaires de contact "
                    "au lieu d'afficher les adresses."
                ),
                compliance=Compliance(
                    owasp_2021="A01:2021 - Broken Access Control",
                    cwe="CWE-200",
                ),
                references=[
                    "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                ],
                phase="enum",
                module=self.name,
                tags=["email", "harvesting", "admin"],
            ))

        if generic_emails:
            finding_count += 1
            result.add_finding(Finding(
                id=f"ENUM-EMAIL-{finding_count:03d}",
                title=f"{len(generic_emails)} email(s) generique(s) collecte(s)",
                severity=Severity.MEDIUM,
                cvss_score=3.7,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"Emails generiques decouverts: "
                    f"{', '.join(generic_emails[:10])}. "
                    f"Sources: {_summarize_sources(generic_emails, source_map)}."
                ),
                evidence=Evidence(
                    request=f"Multiple GET requests on {base}",
                    response_status=200,
                    response_body_excerpt=", ".join(generic_emails[:5]),
                ),
                impact=(
                    "Les emails collectes peuvent etre utilises pour du phishing cible "
                    "ou de l'enumeration de comptes."
                ),
                remediation=(
                    "Utiliser des formulaires de contact au lieu d'afficher les adresses email. "
                    "Obfusquer les emails dans le code source si necessaire."
                ),
                compliance=Compliance(
                    owasp_2021="A01:2021 - Broken Access Control",
                    cwe="CWE-200",
                ),
                phase="enum",
                module=self.name,
                tags=["email", "harvesting"],
            ))

        if contact_emails:
            finding_count += 1
            result.add_finding(Finding(
                id=f"ENUM-EMAIL-{finding_count:03d}",
                title=f"{len(contact_emails)} email(s) de contact public(s) collecte(s)",
                severity=Severity.INFO,
                cvss_score=0.0,
                cvss_vector="",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                description=(
                    f"Emails de contact publics decouverts: "
                    f"{', '.join(contact_emails[:10])}. "
                    f"Sources: {_summarize_sources(contact_emails, source_map)}."
                ),
                evidence=Evidence(
                    request=f"Multiple GET requests on {base}",
                    response_status=200,
                    response_body_excerpt=", ".join(contact_emails[:5]),
                ),
                impact="Impact faible — ces adresses sont intentionnellement publiques.",
                remediation="Aucune action requise si ces emails sont volontairement publics.",
                compliance=Compliance(cwe="CWE-200"),
                phase="enum",
                module=self.name,
                tags=["email", "harvesting", "contact"],
            ))

        return result


def _summarize_sources(emails: list[str], source_map: dict[str, list[str]]) -> str:
    """Produce a short summary of sources where emails were found."""
    all_sources: set[str] = set()
    for email in emails:
        for src in source_map.get(email, []):
            all_sources.add(src)
    return ", ".join(sorted(all_sources)[:5])
