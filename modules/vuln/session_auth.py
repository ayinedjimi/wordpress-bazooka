"""Session and authentication audit — cookie flags and user enumeration via login form."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Compliance, Evidence, Finding, Severity, Confidence, FindingType
from modules.base import BazookaModule, ModuleResult

if TYPE_CHECKING:
    from core.engine import ScanContext
    from core.session import BazookaSession


def _parse_set_cookie_flags(raw_header: str) -> dict[str, bool]:
    """Parse a Set-Cookie header and return presence of security flags."""
    lower = raw_header.lower()
    return {
        "httponly": "httponly" in lower,
        "secure": "secure" in lower,
        "samesite": "samesite" in lower,
    }


class SessionAuthModule(BazookaModule):
    name = "vuln.session_auth"
    phase = "vuln"
    description = "Session cookie flags and login user enumeration audit"
    profiles = ["standard", "aggressive", "bugbounty"]
    intrusive = False

    async def run(self, ctx: ScanContext, session: BazookaSession) -> ModuleResult:
        result = ModuleResult()
        base = ctx.target.url
        login_url = f"{base}/wp-login.php"

        # ------------------------------------------------------------------
        # Part 1: Cookie security flags on wp-login.php response
        # ------------------------------------------------------------------
        try:
            resp_login = await session.get(login_url, use_cache=False, follow_redirects=False)
        except Exception:
            result.status = "partial"
            return result

        # Collect all Set-Cookie headers (httpx multi-value access)
        set_cookies: list[str] = []
        if hasattr(resp_login.headers, "get_list"):
            set_cookies = resp_login.headers.get_list("set-cookie")
        if not set_cookies:
            set_cookies = [v for k, v in resp_login.headers.multi_items() if k.lower() == "set-cookie"]
        if not set_cookies:
            sc = resp_login.headers.get("set-cookie", "")
            if sc:
                set_cookies = [sc]

        missing_flags: dict[str, list[str]] = {}  # cookie_name -> list of missing flags

        for raw_cookie in set_cookies:
            raw_str = raw_cookie if isinstance(raw_cookie, str) else str(raw_cookie)
            # Extract cookie name
            cookie_name = raw_str.split("=", 1)[0].strip()
            flags = _parse_set_cookie_flags(raw_str)

            missing: list[str] = []
            if not flags["httponly"]:
                missing.append("HttpOnly")
            if not flags["secure"]:
                missing.append("Secure")
            if not flags["samesite"]:
                missing.append("SameSite")

            if missing:
                missing_flags[cookie_name] = missing

        if missing_flags:
            details_lines = [f"  {name}: manque {', '.join(flags)}" for name, flags in missing_flags.items()]
            details = "\n".join(details_lines)

            result.add_finding(Finding(
                id="VULN-SESS-001",
                title=f"Cookies sans flags de securite ({len(missing_flags)} cookies)",
                severity=Severity.MEDIUM,
                cvss_score=4.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.MISCONFIGURATION,
                description=(
                    f"La page wp-login.php definit {len(missing_flags)} cookie(s) sans tous les "
                    f"flags de securite recommandes:\n{details}"
                ),
                evidence=Evidence(
                    request=f"GET {login_url}",
                    response_status=resp_login.status_code,
                    response_headers={
                        "set-cookie": "; ".join(str(c) for c in set_cookies[:3])[:500]
                    },
                ),
                impact=(
                    "Sans HttpOnly, les cookies sont accessibles via JavaScript (XSS -> session hijacking). "
                    "Sans Secure, les cookies sont transmis en clair sur HTTP. "
                    "Sans SameSite, les cookies sont envoyes avec les requetes cross-site (CSRF)."
                ),
                remediation=(
                    "Configurer les flags HttpOnly, Secure et SameSite=Lax (ou Strict) sur tous les "
                    "cookies de session. Ajouter dans wp-config.php:\n"
                    "  @ini_set('session.cookie_httponly', 1);\n"
                    "  @ini_set('session.cookie_secure', 1);\n"
                    "  @ini_set('session.cookie_samesite', 'Lax');\n"
                    "Ou utiliser un plugin de securite (SecuPress, Wordfence) pour forcer ces flags."
                ),
                compliance=Compliance(
                    owasp_2021="A05:2021 - Security Misconfiguration",
                    cwe="CWE-614",
                    pci_dss_v4="6.2.4",
                ),
                references=[
                    "https://owasp.org/www-community/controls/SecureCookieAttribute",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
                ],
                phase="vuln",
                module=self.name,
                tags=["cookies", "session", "authentication"],
            ))

        # ------------------------------------------------------------------
        # Part 2: User enumeration via login error messages
        # ------------------------------------------------------------------
        # Test with a username that almost certainly does not exist
        fake_user = "bz_nonexistent_user_test_8291"
        login_data_fake = {
            "log": fake_user,
            "pwd": "wrong_password_test",
            "wp-submit": "Log In",
            "redirect_to": f"{base}/wp-admin/",
            "testcookie": "1",
        }

        try:
            resp_fake_user = await session.post(
                login_url,
                data=login_data_fake,
                use_cache=False,
                follow_redirects=False,
            )
            body_fake = resp_fake_user.text[:5000].lower()
        except Exception:
            body_fake = ""

        # Test with a real username (if we have one) or "admin"
        real_user = "admin"
        if ctx.target.users:
            real_user = ctx.target.users[0].username or "admin"

        login_data_real = {
            "log": real_user,
            "pwd": "wrong_password_test_12345",
            "wp-submit": "Log In",
            "redirect_to": f"{base}/wp-admin/",
            "testcookie": "1",
        }

        try:
            resp_real_user = await session.post(
                login_url,
                data=login_data_real,
                use_cache=False,
                follow_redirects=False,
            )
            body_real = resp_real_user.text[:5000].lower()
        except Exception:
            body_real = ""

        # Detect differential error messages
        user_enum_detected = False
        evidence_detail = ""

        if body_fake and body_real:
            # WordPress default messages:
            # Invalid username: "ERROR: Invalid username"  /  "Le nom d'utilisateur n'est pas enregistre"
            # Wrong password:  "ERROR: The password you entered for the username X is incorrect"
            invalid_user_patterns = [
                "invalid username",
                "nom d'utilisateur",
                "not registered",
                "unknown username",
                "no account found",
            ]
            wrong_pwd_patterns = [
                "incorrect password",
                "the password you entered",
                "mot de passe",
                "wrong password",
            ]

            fake_has_invalid_user = any(p in body_fake for p in invalid_user_patterns)
            real_has_wrong_pwd = any(p in body_real for p in wrong_pwd_patterns)

            if fake_has_invalid_user and real_has_wrong_pwd:
                user_enum_detected = True
                evidence_detail = (
                    f"Utilisateur inexistant ({fake_user}): message 'invalid username'. "
                    f"Utilisateur existant ({real_user}): message 'incorrect password'. "
                    "La difference de message permet d'enumerer les comptes."
                )
            elif fake_has_invalid_user:
                user_enum_detected = True
                evidence_detail = (
                    f"Le message d'erreur pour un utilisateur inexistant ({fake_user}) "
                    "indique explicitement que le nom d'utilisateur est invalide."
                )
            elif body_fake != body_real and len(body_fake) > 100:
                # Different response bodies hint at enumeration
                diff_size = abs(len(body_fake) - len(body_real))
                if diff_size > 50:
                    user_enum_detected = True
                    evidence_detail = (
                        f"Les reponses pour un utilisateur inexistant (taille: {len(body_fake)}) "
                        f"et existant (taille: {len(body_real)}) different significativement "
                        f"(delta: {diff_size} octets), ce qui permet l'enumeration."
                    )

        if user_enum_detected:
            result.add_finding(Finding(
                id="VULN-SESS-002",
                title="Enumeration d'utilisateurs via le formulaire de login",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                confidence=Confidence.CONFIRMED,
                finding_type=FindingType.DESIGN_FLAW,
                description=(
                    "Le formulaire de connexion WordPress revele si un nom d'utilisateur existe ou non "
                    "via des messages d'erreur differents. " + evidence_detail
                ),
                evidence=Evidence(
                    request=f"POST {login_url} (log={fake_user} & log={real_user})",
                    response_status=resp_fake_user.status_code if body_fake else 0,
                    response_body_excerpt=evidence_detail[:500],
                ),
                impact=(
                    "Un attaquant peut determiner les noms d'utilisateur valides sans authentification. "
                    "Cela facilite les attaques par brute-force ciblees et le phishing."
                ),
                remediation=(
                    "Utiliser un message d'erreur generique identique pour les deux cas: "
                    '"Identifiant ou mot de passe incorrect". '
                    "Plugins: WPS Hide Login, SecuPress, iThemes Security."
                ),
                compliance=Compliance(
                    owasp_2021="A07:2021 - Identification and Authentication Failures",
                    cwe="CWE-204",
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account",
                ],
                phase="vuln",
                module=self.name,
                tags=["user-enumeration", "authentication", "login"],
            ))

        return result
